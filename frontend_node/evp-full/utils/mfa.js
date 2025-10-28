const crypto = require('crypto');

// Simple TOTP (RFC6238-ish) minimal implementation; replace with 'speakeasy' in production.
function hotp(key, counter){
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) | ((hmac[offset+2] & 0xff) << 8) | (hmac[offset+3] & 0xff);
  return (code % 1000000).toString().padStart(6, '0');
}

function totp(secret, step = 30, t = Math.floor(Date.now()/1000)){
  const counter = Math.floor(t / step);
  return hotp(Buffer.from(secret, 'hex'), counter);
}

function verifyTotp(secret, token, window=1){
  token = String(token || '');
  const now = Math.floor(Date.now()/1000);
  for(let w=-window; w<=window; w++){
    if(totp(secret, 30, now + (w*30)) === token) return true;
  }
  return false;
}

function genSecret(bytes=20){
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { totp, verifyTotp, genSecret };
