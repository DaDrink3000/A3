const crypto = require('crypto');
function canonicalStringify(obj) { return JSON.stringify(obj, Object.keys(obj).sort()); }
function computeReceipt(ballotObj, pepper) {
  const canonical = canonicalStringify(ballotObj);
  const h = crypto.createHash('sha256').update(canonical, 'utf8').update(pepper || '').digest('hex');
  return { hashHex: h, shortCode: h.slice(0, 10) };
}
module.exports = { computeReceipt, canonicalStringify };
