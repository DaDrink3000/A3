
# app/security/mfa.py
import os, json, base64, secrets, hmac, hashlib, time
from pathlib import Path
from typing import Dict
from flask import Blueprint, request, jsonify, make_response, redirect
try:
    import pyotp
except Exception:
    pyotp = None

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
USERS_FILE = DATA_DIR / "staff_users.jsonl"
USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

bp = Blueprint("mfa", __name__)

def _iter_users():
    if USERS_FILE.exists():
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

def _save_user(u: Dict):
    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(u) + "\n")

def _find_user(username: str):
    for u in _iter_users():
        if u.get("username")==username:
            return u
    return None

def _update_user(username: str, patch: Dict):
    # rewrite file
    users = list(_iter_users())
    for u in users:
        if u.get("username")==username:
            u.update(patch)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        for u in users:
            f.write(json.dumps(u) + "\n")

def _hash_pw(pw: str, salt: str) -> str:
    return hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1, dklen=32).hex()

def _gen_sid():
    return secrets.token_urlsafe(32)

@bp.post("/staff/register")
def register_staff():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "")
    role = (body.get("role") or "clerk").strip()
    if not username or not password:
        return jsonify(ok=False, error="username and password required"), 400
    if _find_user(username):
        return jsonify(ok=False, error="user exists"), 409
    salt = secrets.token_hex(8)
    rec = {
        "username": username,
        "salt": salt,
        "pw": _hash_pw(password, salt),
        "role": role,
        "mfa_enabled": False,
        "mfa_secret": None,
        "recovery": []
    }
    _save_user(rec)
    return jsonify(ok=True, user={"username": username, "role": role})

@bp.post("/staff/mfa/setup")
def mfa_setup():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    if not username:
        return jsonify(ok=False, error="username required"), 400
    u = _find_user(username)
    if not u:
        return jsonify(ok=False, error="not found"), 404
    if pyotp is None:
        return jsonify(ok=False, error="pyotp not installed"), 500
    secret = pyotp.random_base32()
    _update_user(username, {"mfa_secret": secret, "mfa_enabled": True})
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="AEC Prototype")
    return jsonify(ok=True, secret=secret, otpauth_uri=uri)

@bp.post("/staff/login")
def staff_login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "")
    if not username or not password:
        return jsonify(ok=False, error="username and password required"), 400
    u = _find_user(username)
    if not u:
        return jsonify(ok=False, error="invalid credentials"), 401
    if _hash_pw(password, u["salt"]) != u["pw"]:
        return jsonify(ok=False, error="invalid credentials"), 401
    # If MFA enabled, require /staff/mfa/verify
    if u.get("mfa_enabled"):
        # issue a short-lived login token (HMAC'd)
        nonce = secrets.token_urlsafe(16)
        exp = int(time.time()) + 300
        data = f"{username}.{exp}.{nonce}".encode()
        key = hashlib.sha256(b"aec-mfa").digest()
        tag = hmac.new(key, data, hashlib.sha256).hexdigest()
        return jsonify(ok=True, mfa_required=True, login_token=(data+ b"."+ tag.encode()).decode())
    # else, issue session cookie
    from app.main import set_sid_cookie, SESSIONS, now
    sid = _gen_sid()
    t = now()
    SESSIONS[sid] = {"user": username, "issued": t, "last": t}
    resp = make_response(redirect("/dashboard"))
    set_sid_cookie(resp, sid)
    return resp

def _verify_login_token(token: str):
    try:
        data, tag = token.rsplit(".", 1)
        key = hashlib.sha256(b"aec-mfa").digest()
        good = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, tag):
            return None
        username, exp, nonce = data.split(".")
        if int(exp) < int(time.time()):
            return None
        return username
    except Exception:
        return None

@bp.post("/staff/mfa/verify")
def mfa_verify():
    if pyotp is None:
        return jsonify(ok=False, error="pyotp not installed"), 500
    body = request.get_json(silent=True) or {}
    token = (body.get("login_token") or "")
    otp = (body.get("otp") or "").strip()
    username = _verify_login_token(token)
    if not username:
        return jsonify(ok=False, error="invalid token"), 401
    u = _find_user(username)
    if not u or not u.get("mfa_secret"):
        return jsonify(ok=False, error="MFA not setup"), 400
    totp = pyotp.TOTP(u["mfa_secret"])
    if not totp.verify(otp, valid_window=1):
        return jsonify(ok=False, error="invalid OTP"), 401
    # success -> set session
    from app.main import set_sid_cookie, SESSIONS, now
    sid = _gen_sid()
    t = now()
    SESSIONS[sid] = {"user": username, "issued": t, "last": t}
    resp = make_response(redirect("/dashboard"))
    set_sid_cookie(resp, sid)
    return resp
