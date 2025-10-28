**Stack:** Docker Compose, Node.js, Python/Flask, Nginx

## Overview

This project is a containerised secure-voting prototype that shows defence-in-depth from the edge (TLS, headers) to the app (session hardening, key rotation) to the SDLC (automated security analysis and dependency hygiene), with operational controls (backup/restore) — all in a reproducible, Dockerised setup.

## Features
- Express-based HTTP server
- Server-side templating
- TOTP-based MFA support
- Health endpoint(s): /api/health, /api/healthz

## Directory Structure (top-level)

.
├─ backend_flask/A3-main/

│  ├─ app/

│  │  ├─ routes/                 # Flask blueprints/endpoints

│  │  ├─ services/               # domain/services

│  │  ├─ data/                   # users.jsonl / voters.csv (optional seeds)

│  │  ├─ audit_logs/             # integrity/audit logs (if enabled)

│  │  ├─ middleware.py           # SID rotation & timeouts 

│  │  ├─ key_mgmt.py             # signing key load/rotate 

│  │  ├─ main.py                 # binds to :8001 (ensure Nginx upstream matches)

│  │  └─ requirements.txt

│  ├─ infra/nginx/

│  │  ├─ default.conf            # TLS, headers, /api -> backend, / -> frontend

│  │  └─ cert/                   # self-signed TLS for localhost

│  │     ├─ fullchain.pem

│  │     └─ privkey.pem

│  ├─ .github/workflows/

│  │  ├─ security-ci.yml         # CodeQL + secret scans 

│  │  └─ dependabot.yml          # dep updates 

│  └─ SECURITY.md

│

├─ frontend_node/evp-full/

│  ├─ data/                      # UI data (if any)

│  ├─ locales/                   # i18n strings

│  ├─ logs/                      # UI logs (opt)

│  ├─ middleware/

│  │  ├─ authz.js

│  │  ├─ geoAccess.js

│  │  ├─ i18n.js

│  │  └─ validate.js

│  ├─ public/

│  │  └─ confirm.js

│  ├─ routes/                    # express/next-like routes (UI)

│  ├─ scripts/                   # helper scripts

│  ├─ utils/                     # shared helpers

│  ├─ views/                     # templates/components

│  ├─ .env.example               # sample env

│  ├─ .env                       # runtime env (not committed)

│  ├─ app.js                     # Node entry (dev server :3000)

│  ├─ Dockerfile                 # frontend container

│  ├─ CHECKLIST.md

│  ├─ package.json

│  └─ package-lock.json

│

├─ scripts/

│  ├─ backup.py                  # gzip snapshot to /app/backups

│  └─ restore.py                 # latest snapshot -> /app/dbdata

│

├─ docker-compose.yml            # all services (nginx, app1, app2, frontend, backup, restore)

└─ README.md

## Architecture

Client  <--HTTPS-->  Nginx :443

                        ├─ "/"         -> Frontend (Node :3000)
                        
                        └─ "/api/*"    -> Flask pool (app1, app2 :8001)

                                           └─ SQLite @ /app/dbdata/db.sqlite3
                                           
Nightly backup  -> /app/backups  (gz snapshots)
On-demand restore -> restores latest snapshot to dbdata

## Getting Started
### Prerequisites
Docker Desktop / Docker Engine + Compose v2

### Setup

#### TLS for localhost
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout backend_flask/A3-main/infra/nginx/cert/privkey.pem \
  -out    backend_flask/A3-main/infra/nginx/cert/fullchain.pem \
  -days 365 -subj "/CN=localhost"
  
#### Signing key (Docker secret)
openssl rand -base64 48 > backend_flask/A3-main/infra/signing_key.pem

#### Run
docker compose up -d
docker compose ps

### Backups & restore
docker compose exec backup bash -lc "python /scripts/backup.py"
docker compose run --rm restore

### CI / Security pipeline
.github/workflows/security-ci.yml:
CodeQL (Python + JavaScript)
Gitleaks secret scanning (results.sarif uploaded to code scanning)
Workflow fails on high/critical findings (merge-blocking)
dependabot.yml:
Updates npm / pip dependencies on a schedule; opens PRs with suggested bumps
Viewing results:
Push to GitHub with Actions enabled.
Check Security → Code scanning alerts for CodeQL / SARIF uploads.
Check Actions tab for deps-and-secrets run output.



## Services

**A3-main-code/docker-compose.yaml**
- `app1` → ports: none | image/build: ./backend_flask/A3-main/app
- `app2` → ports: none | image/build: ./backend_flask/A3-main/app
- `frontend` → ports: 3000:3000 | image/build: build context
- `nginx` → ports: 80:80, 443:443 | image/build: nginx:stable
- `backup` → ports: none | image/build: python:3.12-slim
- `restore` → ports: none | image/build: python:3.12-slim

## Local URLs

- Reverse proxy: http://localhost
- App service: http://localhost:3000
- Health: http://localhost/api/health
- Health: http://localhost/api/healthz


## Troubleshooting

- If a container shows as **unhealthy**, check its logs:
 
docker compose logs <service>
  
- On Windows/PowerShell, set env vars with `setx` or use a `.env` file instead of `export`.
- If port 80 is in use, change the host port in the compose file (e.g., `8080:80`) and visit `http://localhost:8080`.
- 502 Bad Gateway: Flask/Nginx port mismatch:
  
docker compose logs app1 | findstr /i "Running on http://"
docker compose restart nginx

- PowerShell’s fake curl: Use real curl or un-alias:
C:\Windows\System32\curl.exe -k https://localhost/api/healthz
## License

Academic assignment project; internal dependencies under their respective licenses.
