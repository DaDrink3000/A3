#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const srcRoot = path.join(process.cwd(), 'backups');
const dest = path.join(process.cwd(), 'data');
if(!fs.existsSync(srcRoot)) { console.error('No backups found'); process.exit(1); }

const entries = fs.readdirSync(srcRoot).filter(n=>n.startsWith('backup-')).sort();
if(entries.length===0){ console.error('No backups found'); process.exit(1); }
const latest = path.join(srcRoot, entries[entries.length-1]);

function copyDir(srcDir, dstDir){
  for(const entry of fs.readdirSync(srcDir, { withFileTypes:true })){
    const s = path.join(srcDir, entry.name);
    const d = path.join(dstDir, entry.name);
    if(entry.isDirectory()){
      fs.mkdirSync(d, { recursive:true });
      copyDir(s,d);
    }else{
      fs.copyFileSync(s,d);
    }
  }
}

fs.mkdirSync(dest, { recursive:true });
copyDir(latest, dest);
console.log('Restored from', latest);
