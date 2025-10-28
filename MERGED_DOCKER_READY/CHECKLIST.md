# A3 Security Requirements Checklist

- [x] R01 — MFA + RBAC (admin/manager/auditor)
  - Files: middleware/authz.js, routes/auth.js, utils/mfa.js
- [x] R07 — Verifiable tally & export (admin-only GET /admin/export-tally)
  - Files: utils/tally.js, routes/admin.js, data/accepted.json
- [x] R16 — Geographic access controls + audit
  - Files: middleware/geoAccess.js, utils/audit.js, .env.example (GEO_* vars)
- [x] R20 — Confirm screen + receipt-hash explanation + i18n
  - Files: routes/vote.js, utils/receipt.js, views/{vote,confirm,receipt}.ejs, locales/{en,es}.json

> Note: Geo restrictions are demo-level without a GeoIP DB. Enforce at edge/WAF for production.
