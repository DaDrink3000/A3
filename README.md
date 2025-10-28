**Stack:** Docker Compose, Node.js, Python/Flask, Nginx

## Overview

This repository contains a multi-service web application packaged for local development and demo via Docker Compose. The primary frontend/server is a Node.js app (see `package.json`). A Python/Flask component is present for auxiliary services or APIs. Nginx is included as a reverse proxy in front of the app layer.

## Features
- Express-based HTTP server
- Server-side templating
- TOTP-based MFA support
- Health endpoint(s): /health, /healthz

## Directory Structure (top-level)

```
A3-main-code
```

## Getting Started

Copy the example environment:
```bash
cp .env.example .env
# then edit values as needed
```
Install Node.js dependencies (optional if using Docker):
```bash
npm install
npm run dev   # or: npm start
```
Run with Docker Compose:
```bash
docker compose -f docker-compose.yaml up --build
```

## Configuration

Environment variables expected (from `.env.example`):
```
ADMIN_PASSWORD
ALLOWLIST_CIDRS
AUDIT_HMAC_KEY
AUDIT_LOG
COOKIE_SECURE
DEFAULT_LANG
DEFAULT_STAFF_PASSWORD
ENABLE_HTTPS_REDIRECT
GEO_COUNTRY
GEO_DEFAULT_COUNTRY
GEO_ENABLE
NODE_ENV
PORT
RECEIPT_PEPPER
SESSION_SECRET
```

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
- Health: http://localhost/health
- Health: http://localhost/healthz

## NPM Scripts

- **start**: `node app.js`
- **dev**: `NODE_ENV=development HOST=0.0.0.0 PORT=3000 node app.js`
- **test**: `jest --runInBand`
- **lint**: `eslint . || true`
- **audit**: `npm audit --audit-level=high || true`
- **check**: `npm run lint && npm run audit`

## Troubleshooting

- If a container shows as **unhealthy**, check its logs:
  ```bash
docker compose logs <service>
  ```
- On Windows/PowerShell, set env vars with `setx` or use a `.env` file instead of `export`.
- If port 80 is in use, change the host port in the compose file (e.g., `8080:80`) and visit `http://localhost:8080`.

## License

MIT (or as specified by your course/repo policy). Update as needed.
