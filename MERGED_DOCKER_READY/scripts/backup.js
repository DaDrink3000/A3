#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const src = path.join(process.cwd(), 'data');
const destRoot = path.join(process.cwd(), 'backups');
const stamp = new Date().toISOString().replace(/[:.]/g,'-');
const dest = path.join(destRoot, 'backup-' + stamp);
fs.mkdirSync(dest, { recursive:true });

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

if(fs.existsSync(src)){
  copyDir(src, dest);
  console.log('Backup completed:', dest);
}else{
  console.log('No data directory to backup.');
}
