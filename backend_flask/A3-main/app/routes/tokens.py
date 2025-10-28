from flask import Blueprint, request, jsonify
import os, sqlite3, hashlib, uuid, datetime

bp = Blueprint("tokens", __name__)
DB_PATH = os.getenv("DB_PATH", "/app/dbdata/db.sqlite3")

# Create the tokens table
with sqlite3.connect(DB_PATH) as c:
    c.execute("""CREATE TABLE IF NOT EXISTS tokens(
        hash TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        ts TEXT NOT NULL
    )""")

@bp.post("/token")
def issue_token():
    token = str(uuid.uuid4())
    h = hashlib.sha256(token.encode()).hexdigest()
    with sqlite3.connect(DB_PATH) as c:
        c.execute("INSERT INTO tokens(hash,status,ts) VALUES (?,?,?)",
                  (h, "issued", datetime.datetime.utcnow().isoformat()))
    return jsonify(token=token)

@bp.post("/redeem")
def redeem_token():
    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    h = hashlib.sha256(token.encode()).hexdigest()
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT status FROM tokens WHERE hash=?", (h,)).fetchone()
        if (not row) or row[0] != "issued":
            return jsonify(ok=False, error="used or invalid"), 409
        c.execute("UPDATE tokens SET status='used' WHERE hash=?", (h,))
    return jsonify(ok=True)
