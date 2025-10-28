const fs = require('fs');
const path = require('path');
const FILE = path.join(process.cwd(), 'data', 'eligibility.json');

function isEligible(id){
  try{
    const { eligible } = JSON.parse(fs.readFileSync(FILE, 'utf-8'));
    return Array.isArray(eligible) && eligible.includes(id);
  }catch{ return false; }
}
module.exports = { isEligible };
