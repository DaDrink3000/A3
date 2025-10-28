# EVP Demo — R01 (MFA + RBAC) + R16 (Geo) + R20 (Confirm + i18n) + R07 (Verifiable tallying)

## Run
1) `npm install`
2) `cp .env.example .env`
3) `npm start`
4) Open http://localhost:3000/

## Demo staff accounts
- admin@aec.local (role: admin)
- manager@aec.local (role: manager)
- auditor@aec.local (role: auditor)
- Default password: `Password123!` (from `.env`)

## R07: Verifiable tallying
- Every submitted ballot is assigned an `acceptedId` and stored in `data/accepted.json` (demo box).
- Admin can download **tally_bundle.zip** from `/admin/export-tally` containing:
  - `accepted_ids.txt`  (one ID per line)
  - `counts.json`       (first-preference totals by candidate)
  - `metadata.json`     (generation info)
  - `checksum.txt`      (SHA-256 over canonical JSON of `{counts, ids}`)
  - `README.txt`
- Verify integrity (and optionally recount if you have `data/accepted.json`):
  ```bash
  node scripts/verify_tally.js <bundle.zip or extracted folder>
  ```

## R01
- Routes: `/auth/login`, `/auth/setup-mfa`, `/auth/verify-mfa`, `/admin`
- Middleware: requireAuth → requireMFA → requireRole('admin') (admin area & export)
- TOTP via `speakeasy`, QR via `qrcode`

## R16
- AU-only by default, allow-list CIDRs, audit log at `logs/access-decisions.log`

## R20
- Confirm screen with receipt hash explanation; i18n EN/中文


## Requirements implemented
- R01: MFA + RBAC (admin/manager/auditor)
- R07: Verifiable tally with admin-only export `/admin/export-tally`
- R16: Geographic access controls (env-driven; audit log at `data/audit.log`)
- R20: Confirm screen with receipt-hash explanation + i18n (EN + ES)

### Quickstart
```bash
npm install
cp .env.example .env
npm start
# open http://localhost:8000/vote
# login: POST /auth/login { username: 'admin', password: process.env.ADMIN_PASSWORD }
```


### Additional implemented requirements (batch 2)
* **R02** Voter eligibility & secure verification (`data/eligibility.json`, `utils/eligibility.js`, `/token/issue`)
* **R03** Unlinkable one-time token (`utils/token.js`, `/token/redeem`, required before vote submit)
* **R06** Append-only tamper-evident ballot ledger (`utils/ledger.js` → `data/ballots.ndjson`)
* **R08** Security headers + HTTPS redirect (`helmet`, HSTS)
* **R11** HMAC-chained audit log (`utils/audit.js`, env `AUDIT_HMAC_KEY`)
* **R12** Session hardening (secure/httpOnly/sameSite cookie)
* **R13** Input validation (`middleware/validate.js` + Joi)
* **R14** Security headers baseline (`helmet`)
* **R15** Key mgmt & rotation (`utils/keys.js`, `scripts/rotate-keys.js`)
* **R17/R18** CI security gates (`.github/workflows/ci.yml`, lint + audit)
* **R19** Backup & restore (`scripts/backup.js`, `scripts/restore-latest.js`)

#### Useful commands
```bash
npm run check         # lint + audit
node scripts/backup.js
node scripts/restore-latest.js
node scripts/rotate-keys.js
```


## Docker
```bash
docker compose build
cp .env.example .env
# (optional) edit .env e.g. ADMIN_PASSWORD, SESSION_SECRET
# For local dev keep ENABLE_HTTPS_REDIRECT=false to avoid loops
# Bring up stack
docker compose up -d
# Check health
curl -s http://localhost/healthz
# Logs
docker compose logs -f app
```
