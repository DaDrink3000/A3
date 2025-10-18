from flask import Flask, request, redirect, make_response, jsonify
from datetime import datetime, timezone
import os, secrets

app = Flask(__name__)

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
    return "Voting prototype: R08/R12/R15/R17"

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

# guard, timeouts, rotation (R12)
@app.before_request
def session_guard():
    # public routes
    if request.path in ("/", "/login", "/logout", "/healthz"):
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
def apply_headers_and_rotation(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
