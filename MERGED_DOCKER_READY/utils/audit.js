const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const LOG = path.join(process.cwd(), 'data', 'audit.log');

function audit(event, details){
  const key = (process.env.AUDIT_HMAC_KEY || 'dev_audit_key');
  const ts = new Date().toISOString();
  // Read last line for chaining
  let prev = '';
  try{
    const last = fs.readFileSync(LOG, 'utf-8').trim().split('\n').pop();
    if(last){ prev = JSON.parse(last).sig || ''; }
  }catch{}
  const payload = { ts, event, details, prev };
  const sig = crypto.createHmac('sha256', key).update(JSON.stringify(payload)).digest('hex');
  const line = JSON.stringify({ ...payload, sig });
  fs.mkdirSync(path.dirname(LOG), { recursive: true });
  fs.appendFileSync(LOG, line + '\n');
}

module.exports = { audit };
