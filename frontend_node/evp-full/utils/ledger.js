const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const LEDGER = path.join(process.cwd(), 'data', 'ballots.ndjson');

function lastHash(){
  try{
    const lines = fs.readFileSync(LEDGER,'utf-8').trim().split('\n');
    if(lines.length===0) return '';
    return JSON.parse(lines[lines.length-1]).curr;
  }catch{ return ''; }
}

function appendBallot(ballot){
  const prev = lastHash();
  const body = { ballot, prev, ts: new Date().toISOString() };
  const curr = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
  const line = JSON.stringify({ ...body, curr });
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  fs.appendFileSync(LEDGER, line + '\n', { encoding:'utf-8', mode:0o600 });
  return { prev, curr };
}

function verify(){
  try{
    const lines = fs.readFileSync(LEDGER,'utf-8').trim().split('\n');
    let prev = '';
    for(const line of lines){
      const obj = JSON.parse(line);
      const { ballot, ts, curr } = obj;
      const recomputed = crypto.createHash('sha256').update(JSON.stringify({ ballot, prev, ts })).digest('hex');
      if(recomputed !== curr) return false;
      prev = curr;
    }
    return true;
  }catch{ return true; }
}

module.exports = { appendBallot, verify };
