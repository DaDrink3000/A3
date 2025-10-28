const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const FILE = path.join(process.cwd(), 'data', 'keys.json');

function load(){
  try{ return JSON.parse(fs.readFileSync(FILE,'utf-8')); }catch{ return { active:null, keys:{} }; }
}
function save(db){ fs.mkdirSync(path.dirname(FILE), { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(db, null, 2)); }

function rotate(){
  const db = load();
  const kid = 'k'+Date.now();
  const material = crypto.randomBytes(32).toString('hex');
  db.keys[kid] = { material, created: new Date().toISOString() };
  db.active = kid;
  save(db);
  return { kid, material };
}

function getActive(){
  const db = load();
  if(!db.active) rotate();
  const d = load();
  return { kid: d.active, material: d.keys[d.active].material };
}

module.exports = { rotate, getActive };
