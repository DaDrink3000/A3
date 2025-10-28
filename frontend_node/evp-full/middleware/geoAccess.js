// middleware/geoAccess.js
// R16: Geographic access controls with safe fallback audit logging

const fs = require('fs');
const path = require('path');
const geoip = require('geoip-lite');
const CIDRMatcher = require('cidr-matcher');

// Try to import an existing audit helper if your project has one;
// otherwise define a simple local logger.
let auditDecision = null;
try {
  // Adjust this import if you *do* have a real audit util.
  // Example expected export: module.exports = { auditDecision: (entry)=>{} }
  ({ auditDecision } = require('../utils/audit'));
} catch (_) {
  // ignore; we'll use fallback
}

// Fallback audit logger (append line-delimited JSON)
if (typeof auditDecision !== 'function') {
  const AUDIT_LOG = process.env.AUDIT_LOG || 'logs/access-decisions.log';
  fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
  auditDecision = (entry) => {
    try {
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
      fs.appendFileSync(AUDIT_LOG, line, { encoding: 'utf8' });
    } catch (e) {
      // last resort: console
      console.error('auditDecision fallback error:', e);
      console.error(entry);
    }
  };
}

const ENABLED = (process.env.GEO_ENABLE || 'true').toLowerCase() !== 'false';
const DEFAULT_COUNTRY = (process.env.GEO_DEFAULT_COUNTRY || 'AU').toUpperCase();
const ALLOWLIST = String(process.env.ALLOWLIST_CIDRS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const matcher = new CIDRMatcher(ALLOWLIST);

// Helper: get client IP (considering reverse proxy)
function clientIp(req) {
  // Express’ req.ip already respects trust proxy; also check XFF first IP
  const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xff || req.ip || req.connection?.remoteAddress || '';
}

// Optional header to override country in testing (don’t enable in prod)
function countryForIp(ip, req) {
  const forced = req.headers['x-test-country'];
  if (forced && /^[A-Za-z]{2}$/.test(forced)) return forced.toUpperCase();
  const hit = geoip.lookup(ip);
  return hit?.country || 'ZZ';
}

function geoAccess(req, res, next) {
  if (!ENABLED) return next();

  // Let health checks bypass
  if (req.path === '/healthz') return next();

  const ip = clientIp(req);

  // Allow CIDR allowlist first (corp/VPN/devnets)
  if (ip && ALLOWLIST.length && matcher.contains(ip)) {
    auditDecision({ ip, path: req.path, decision: 'ALLOW', reason: 'CIDR_ALLOW' });
    return next();
  }

  const ctry = countryForIp(ip, req);
  if (ctry !== DEFAULT_COUNTRY) {
    auditDecision({ ip, path: req.path, decision: 'DENY', reason: `GEO_BLOCK country=${ctry}` });
    return res.status(403).send('Geo access denied');
  }

  auditDecision({ ip, path: req.path, decision: 'ALLOW', reason: 'COUNTRY_OK' });
  return next();
}

module.exports = geoAccess;
