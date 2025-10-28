const CidrMatcher = require('cidr-matcher');
const geoip = require('geoip-lite');
const { auditDecision } = require('../utils/audit');

function parseCidrs(str) {
  if (!str) return [];
  return str.split(',').map(s => s.trim()).filter(Boolean);
}

const defaultCountry = (process.env.GEO_DEFAULT_COUNTRY || 'AU').toUpperCase();
const allowCidrs = new CidrMatcher(parseCidrs(process.env.ALLOWLIST_CIDRS || '127.0.0.1/32,::1/128,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12'));
const enabled = String(process.env.GEO_ENABLE || 'true').toLowerCase() !== 'false';

function clientIp(req) {
  return (req.ip || '').replace('::ffff:', '') || (req.connection && req.connection.remoteAddress) || '';
}

module.exports = function geoAccess(req, res, next) {
  if (!enabled) return next();
  const ip = clientIp(req);
  const path = req.originalUrl || req.url;

  if (ip && allowCidrs.contains(ip)) {
    auditDecision({ ip, decision: 'allow', reason: 'allowlist', path });
    return next();
  }

  const lookup = ip ? geoip.lookup(ip) : null;
  const country = lookup && lookup.country ? String(lookup.country).toUpperCase() : 'UNKNOWN';

  if (country === defaultCountry) {
    auditDecision({ ip, country, decision: 'allow', reason: 'geo-match', path });
    return next();
  }

  auditDecision({ ip, country, decision: 'deny', reason: 'geo-mismatch', path });
  res.status(403).send('Access denied by geographic policy.');
};
