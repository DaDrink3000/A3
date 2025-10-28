# A3 — Side-by-Side Deployment (Option A)

This repository bundles **both** backends side-by-side:

- `backend_flask/A3-main/` — Flask prototype (secure APIs, MFA/RBAC, geo controls, tally API).
- `frontend_node/evp-full/` — Node/Express full app (voting UI, admin panel, MFA, tally+export).

They run independently; use the one you need for demos. You can run both together via Docker Compose.

## Quick Start (Docker)

```bash
docker compose up --build
```

- Flask service → http://localhost:8001
  - Example endpoints: `/public-key`, `/ballot`, `/tally`, `/staff/*`
- Node service → http://localhost:3000
  - UI pages: voting and admin flows, TOTP setup/verify, etc.

### Environment

- Flask: see `backend_flask/A3-main/app/requirements.txt` and `main.py` for env variables like `ALLOWED_CIDRS`, `ALLOWED_COUNTRY`.
- Node: configure `frontend_node/evp-full/.env` (copied from `.env.example`). Make sure `SESSION_SECRET`, `RECEIPT_PEPPER` are strong, random values.

## Local (without Docker)

**Flask**

```bash
cd backend_flask/A3-main/app
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
export FLASK_APP=main.py
python main.py  # or: python -m flask run --host=0.0.0.0 --port=8001
```

**Node**

```bash
cd frontend_node/evp-full
cp .env.example .env  # then edit the secrets
npm ci
npm start
```

## Notes
- For HTTPS demos: put both behind a reverse proxy (nginx/Traefik) or enable HTTPS in your environment.
- Production: set `COOKIE_SECURE=true` in Node `.env`, and serve Flask behind TLS (HSTS is set by Flask already).
- You can evolve the Node app to call the Flask APIs if you want a split UI/API architecture, but this bundle intentionally keeps them independent.
