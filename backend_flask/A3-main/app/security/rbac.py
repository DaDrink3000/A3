
# app/security/rbac.py
from functools import wraps
from flask import request, jsonify
import os

# Very simple role store for prototype:
# In production you'd query a DB/IdP (e.g., AAD, Okta) or JWT 'roles' claim.
USER_ROLES = {
    # username -> set of roles
    "demo": {"clerk"},
    "auditor": {"auditor"},
    "admin": {"admin", "auditor"},
}

def get_current_user():
    # Reuse session established in app.main (sid cookie + SESSIONS)
    ctx = getattr(request, "session_ctx", None)
    if ctx:
        return ctx.get("user")
    # Fallback for local testing via header
    return request.headers.get("X-Debug-User")

def require_roles(*roles):
    """Decorator: require at least one of the roles"""
    want = set(roles)
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify(error="unauthenticated"), 401
            granted = USER_ROLES.get(user, set())
            if not (want & granted):
                return jsonify(error="forbidden: missing role", required=list(want), have=list(granted)), 403
            return fn(*args, **kwargs)
        return wrapped
    return deco
