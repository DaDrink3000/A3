from flask import Flask, g, request, redirect, make_response, jsonify
from datetime import datetime, timezone
import os, secrets
from routes.constants import EVENT_REQUEST
from routes.utils import get_client_ip, get_user_id
from services import *
from routes import *
from routes.user_routes import user_bp # Import blueprints
from routes.voting_routes import voting_bp
from collections import defaultdict, deque
import time


ballot_service = BallotEvidentService()
verification_service = BlockchainVerificationService()
eligibility_service = EligibilityService()
audit_service = AuditLoggingService(
    log_dir="audit_logs",
    rotation_when="midnight",
    backup_count=365
)
user_validation_service = UserValidationService(
    strict_mode=False,
    allow_international_mobile=True)

app = Flask(__name__)

# --- R09: DDoS and rate-limit protections ---
RATE_LIMIT_WINDOW = 60          
RATE_LIMIT_MAX = 60             # max requests per window per IP
rate_limit_store = defaultdict(lambda: deque())  # ip -> timestamps deque


# Cookie security (R08) 
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

# Session timeouts and rotation (R12) 
IDLE_TIMEOUT = int(os.getenv("IDLE_TIMEOUT_SECONDS", "900"))        # 15 min
ABS_TIMEOUT  = int(os.getenv("ABSOLUTE_TIMEOUT_SECONDS", "7200"))   # 2 h
ROTATE_EVERY = int(os.getenv("ROTATE_EVERY_SECONDS", "600"))        # 10 min

# --- simple in-memory session store for prototype ---
SESSIONS = {}  # sid -> {"user":"demo","issued":dt,"last":dt}

def now():
    return datetime.now(timezone.utc)

def new_sid():
    return secrets.token_urlsafe(32)

def set_sid_cookie(resp, sid):
    resp.set_cookie(
        "sid", sid,
        secure=True, httponly=True, samesite="Strict",
        path="/",
        max_age=ABS_TIMEOUT
    )

def clear_sid_cookie(resp):
    # match the attributes used when setting the cookie
    resp.delete_cookie(
        "sid",
        path="/",
        secure=True,
        httponly=True,
        samesite="Strict",
    ) 

@app.get("/")
def home():
    return "Voting prototype: R03/R08/R12/R14/R15/R17/R19"

@app.get("/login")
def login():
    """Issue a brand-new session (also counts as rotation on login)."""
    sid = new_sid()
    t = now()
    SESSIONS[sid] = {"user": "demo", "issued": t, "last": t}
    resp = make_response(redirect("/dashboard"))
    set_sid_cookie(resp, sid)
    return resp

@app.get("/logout")
def logout():
    sid = request.cookies.get("sid")
    if sid and sid in SESSIONS:
        del SESSIONS[sid]
    resp = make_response(redirect("/"))
    clear_sid_cookie(resp)
    return resp

@app.get("/dashboard")
def dash():
    return "Dashboard (session required). Try /whoami for details."

@app.get("/whoami")
def whoami():
    ctx = getattr(request, "session_ctx", None)
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "user": ctx["user"],
        "issued": ctx["issued"].isoformat(),
        "last": ctx["last"].isoformat(),
        "sid_suffix": getattr(request, "sid_suffix", "none")
    })

@app.before_request
def before_request():
    """Set up request context - extract user from headers"""
    # Note: 'g' is thread-local and safe for request context
    g.user_id = request.headers.get('X-User-ID', 'anonymous')
# guard, timeouts, rotation (R12)
@app.before_request
def rate_limit_guard():
    """Basic per-IP rate limiting (R09)."""
    client_ip = get_client_ip()
    now_ts = time.time()
    window = rate_limit_store[client_ip]

    # Remove timestamps older than window
    while window and now_ts - window[0] > RATE_LIMIT_WINDOW:
        window.popleft()

    if len(window) >= RATE_LIMIT_MAX:
        retry_after = int(RATE_LIMIT_WINDOW - (now_ts - window[0]))
        audit_service.log_event(
            event_type="RATE_LIMIT",
            message=f"Rate limit exceeded by {client_ip}",
            user_id=get_user_id(),
            ip_address=client_ip,
            method=request.method,
            path=request.path,
            status_code=429
        )
        resp = jsonify({
            "error": "Too Many Requests",
            "success": False,
            "retry_after": retry_after
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    # Otherwise, record the timestamp
    window.append(now_ts)


@app.before_request
def session_guard():
    # public routes
    if request.path in ("/", "/login", "/logout", "/healthz", "/token", "/redeem", "/public-key", "/ballot"):
        return

    sid = request.cookies.get("sid")
    s = SESSIONS.get(sid)
    if not sid or not s:
        return ("Unauthorized", 401)

    issued, last = s["issued"], s["last"]
    age  = (now() - issued).total_seconds()
    idle = (now() - last).total_seconds()

    # absolute timeout
    if age > ABS_TIMEOUT:
        del SESSIONS[sid]
        resp = make_response(("Session expired (absolute)", 401))
        clear_sid_cookie(resp)
        return resp

    # idle timeout
    if idle > IDLE_TIMEOUT:
        del SESSIONS[sid]
        resp = make_response(("Session expired (idle)", 401))
        clear_sid_cookie(resp)
        return resp

    # rotation on activity threshold
    if idle > ROTATE_EVERY:
        new = new_sid()
        SESSIONS[new] = {"user": s["user"], "issued": s["issued"], "last": now()}
        del SESSIONS[sid]
        request._rotated_sid = new
        request.session_ctx = SESSIONS[new]
        request.sid_suffix = new[-6:]
    else:
        s["last"] = now()
        request.session_ctx = s
        request.sid_suffix = sid[-6:]

@app.after_request
def after_request(response):
    """Log all requests after processing"""
    # Skip health and metrics endpoints
    if request.path not in ['/health', '/metrics']:
        audit_service.log_event(
            event_type=EVENT_REQUEST,
            message=f"{request.method} {request.path}",
            user_id=get_user_id(),
            ip_address=get_client_ip(),
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            user_agent=request.headers.get('User-Agent', 'unknown')
        )
    return response
@app.after_request
def apply_headers_and_rotation(resp):
    # --- Security Headers (R14) ---
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
    resp.headers["Expect-CT"] = "max-age=86400, enforce"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"

    rotated = getattr(request, "_rotated_sid", None)
    if rotated:
        set_sid_cookie(resp, rotated)
    return resp

@app.post("/role")
def change_role():
    """
    Demo endpoint to simulate privilege/role change.
    Policy: rotate the session ID immediately.
    """
    ctx = getattr(request, "session_ctx", None)
    if not ctx:
        return ("Unauthorized", 401)
    old_sid = request.cookies.get("sid")
    new = new_sid()
    SESSIONS[new] = {"user": ctx["user"], "issued": ctx["issued"], "last": now()}
    if old_sid in SESSIONS:
        del SESSIONS[old_sid]
    resp = make_response(("role updated; sid rotated", 200))
    set_sid_cookie(resp, new)
    return resp

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.errorhandler(Exception)
def handle_error(error):
    """Log all errors"""
    # You'll need to re-register this in a proper BluePrint/App factory pattern
    # but for a simple conversion, keeping it here works for unhandled exceptions.
    audit_service.log_error(
        error_message=str(error),
        user_id=get_user_id(),
        ip_address=get_client_ip(),
        path=request.path,
        error_type=type(error).__name__
    )
    return jsonify({'error': str(error)}), 500

# User endpoints are now mounted at the root URL
app.register_blueprint(user_bp) 
    # Voting/Core endpoints are also mounted at the root URL
app.register_blueprint(voting_bp) 
# Log application startup
audit_service.log_system_event(
    "Application started",
    version="1.0.0",
    services=['ballot', 'verification', 'eligibility', 'audit', 'user_registration']
)
# --- Register R03 token endpoints ---
try:
    from app.routes.tokens import bp as tokens_bp
    app.register_blueprint(tokens_bp)
except Exception as e:
    print("Warning: tokens blueprint not loaded -", e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
