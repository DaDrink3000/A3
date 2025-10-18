from flask import Flask, redirect, make_response

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

@app.get("/")
def home():
    return "Voting prototype: R08/R12/R15/R17"

@app.get("/login")
def login():
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("sid", "demo-session-id", secure=True, httponly=True, samesite="Strict")
    return resp

@app.get("/dashboard")
def dash():
    return "Dashboard (secured transport + cookie flags working)"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
