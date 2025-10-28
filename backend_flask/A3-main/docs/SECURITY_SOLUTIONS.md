# Security Solutions: R01, R07, R16, R20

This document describes the concrete implementation added to this repo to satisfy:

- **R01: MFA for AEC staff + Role‑Based Access (RBAC)**
- **R07: Verifiable tallying**
- **R16: Geographic access controls**
- **R20: User‑experience safeguards**

## R01 — MFA + RBAC

### What we added
- `app/security/mfa.py` — Flask blueprint with endpoints:
  - `POST /staff/register` → create staff user (username/password/role)
  - `POST /staff/mfa/setup` → generate TOTP secret + provisioning URI (scan in Google Authenticator, etc.)
  - `POST /staff/login` → step 1 (password check). If MFA enabled, returns a short‑lived `login_token`.
  - `POST /staff/mfa/verify` → step 2 (OTP check). On success, issues secure session cookie (same site Strict, HTTPOnly).
- `app/security/rbac.py` — lightweight RBAC decorator `@require_roles("auditor","admin", ...)` using the username from the session.
- `app/main.py` is already doing secure cookies + rotation + timeouts (R12). We reuse that session to attach staff identity.

### Configure / Use
1. Install requirements (new deps: `PyNaCl`, `pyotp`).
2. Register a staff user:
   ```bash
   curl -X POST http://localhost:8001/staff/register -H 'Content-Type: application/json'      -d '{"username":"auditor","password":"Passw0rd!","role":"auditor"}'
   ```
3. Enable TOTP (MFA) and scan the QR (the URI is returned):
   ```bash
   curl -X POST http://localhost:8001/staff/mfa/setup -H 'Content-Type: application/json'      -d '{"username":"auditor"}'
   ```
4. Login step 1:
   ```bash
   curl -sX POST http://localhost:8001/staff/login -H 'Content-Type: application/json'      -d '{"username":"auditor","password":"Passw0rd!"}'
   # => returns {"ok":true,"mfa_required":true,"login_token":"..."}
   ```
5. Login step 2 (OTP from authenticator app):
   ```bash
   curl -i -X POST http://localhost:8001/staff/mfa/verify -H 'Content-Type: application/json'      -d '{"login_token":"<from step 4>","otp":"123456"}'
   # => sets a secure cookie 'sid' and redirects to /dashboard
   ```

### Protect endpoints with roles
Use the decorator:
```python
from app.security.rbac import require_roles

@bp.get("/tally")
@require_roles("auditor","admin")
def get_tally(): ...
```

---

## R07 — Verifiable tallying

### What we added
- `app/services/tally_service.py` which:
  - Reads `ballots.jsonl` (sealed‑box ciphertext per ballot)
  - Decrypts using the server’s X25519 private key from `key_mgmt.ensure_encryption_keys()`
  - Produces counts per candidate **and** a *verifiable commitment list* of `(ballot_id, sha256(ciphertext_b64))`
- `app/routes/tally_routes.py`: `GET /tally` (RBAC‑protected for `auditor` or `admin`).

### Verifying the tally externally
1. Anyone can recompute the commitments from a public `ballots.jsonl` dump by hashing each `choice` field (base64 string) with SHA‑256.
2. The published counts are reproducible by an authorized auditor who can decrypt using the private key (managed by `key_mgmt.py`).

> Future extension: publish a Merkle root of the per‑ballot commitments and per‑ballot decryption proofs to enable selective audit without revealing unrelated ballots.

---

## R16 — Geographic access controls

### What we added
- `app/middleware.py` with two controls:
  - **CIDR allow‑list** via env var `ALLOWED_CIDRS` (comma‑separated)
  - **Country code** allow policy via `ALLOWED_COUNTRY` (default `AU`)
- `app/main.py` registers `@app.before_request` hook `geo_guard()` that applies geofencing to public endpoints:
  - `/ballot*`, `/voter*`, `/public-key`

### Configure
- Allow only AEC network ranges (example):
  ```bash
  export ALLOWED_CIDRS="203.0.113.0/24,2001:db8::/32"
  export ALLOWED_COUNTRY="AU"
  ```
- In non‑prod, pass a header `X-Test-Country: AU` to simulate geo resolution.
  In prod, replace `country_allowed()` with a MaxMind/Cloud provider lookup.

---

## R20 — User‑experience safeguards

The app already had:
- Strict security headers (HSTS, CSP, X‑Frame‑Options, etc.)
- Session rotation and inactivity/absolute timeouts
- Rate limiting (per‑IP sliding window)

We additionally ensured that:
- Staff logins return clear, structured JSON errors and use two‑step flows.
- Sensitive endpoints (`/tally`) are role‑gated; attempts are met with precise 401/403 responses.
- Geo‑blocked requests get an explicit 451 with guidance.

> Suggested UI polish (if you add a web frontend):
> - Inline OTP entry with time‑based progress, clipboard‑safe input.
> - Clear “ballot receipt” showing `(ballot_id, sha256(ciphertext))` so voters can later verify inclusion.
> - Nonce replay messages that explain how to refresh and retry.

---

## Wiring recap (code)
- New modules added:
  - `app/security/mfa.py`, `app/security/rbac.py`, `app/middleware.py`, `app/services/tally_service.py`, `app/routes/tally_routes.py`
- `app/main.py` updated to register MFA + Tally blueprints and apply geofencing to public endpoints.
- `app/requirements.txt` updated (adds `PyNaCl`, `pyotp`).

## Run
```bash
docker compose up --build
# or locally
pip install -r app/requirements.txt
export FLASK_APP=app/main.py
python -m flask run --host=0.0.0.0 --port=8001
```

