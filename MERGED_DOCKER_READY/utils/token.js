const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const FILE = path.join(process.cwd(), 'data', 'tokens.json');

function load(){
  try{ return JSON.parse(fs.readFileSync(FILE,'utf-8')); }catch{ return { tokens:[] }; }
}
function save(db){
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(db, null, 2));
}

function issueToken(voterId){
  const db = load();
  const token = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  db.tokens.push({ hash, redeemed:false, ts: Date.now() });
  save(db);
  // Return raw token ONLY to voter (caller)
  return token;
}

function redeem(token){
  const db = load();
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const rec = db.tokens.find(t => t.hash===hash);
  if(!rec || rec.redeemed) return false;
  rec.redeemed = true;
  save(db);
  return true;
}

module.exports = { issueToken, redeem };
