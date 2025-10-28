// Usage:
//   node scripts/verify_tally.js <bundle-path>
// <bundle-path> can be a directory containing the files, or a .zip path.
//
// If running on the server with access to data/accepted.json, this script also
// recomputes counts from ballots corresponding to accepted_ids.txt and compares
// to counts.json.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function readBundle(bundlePath) {
  if (!fs.existsSync(bundlePath)) {
    throw new Error('Bundle path not found: ' + bundlePath);
  }
  const stat = fs.statSync(bundlePath);
  if (stat.isDirectory()) {
    return {
      'accepted_ids.txt': fs.readFileSync(path.join(bundlePath, 'accepted_ids.txt'), 'utf8'),
      'counts.json': fs.readFileSync(path.join(bundlePath, 'counts.json'), 'utf8'),
      'metadata.json': fs.readFileSync(path.join(bundlePath, 'metadata.json'), 'utf8'),
      'checksum.txt': fs.readFileSync(path.join(bundlePath, 'checksum.txt'), 'utf8').trim(),
    };
  } else if (bundlePath.endsWith('.zip')) {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(bundlePath);
    const out = {};
    for (const name of ['accepted_ids.txt','counts.json','metadata.json','checksum.txt']) {
      const entry = zip.getEntry(name);
      if (!entry) throw new Error('Missing file in zip: ' + name);
      out[name] = zip.readAsText(entry).toString();
      if (name === 'checksum.txt') out[name] = out[name].trim();
    }
    return out;
  } else {
    throw new Error('Provide a folder or .zip path');
  }
}

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function canonicalStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function verifyIntegrity(files) {
  const ids = files['accepted_ids.txt'].trim().split('\n').filter(Boolean);
  const counts = JSON.parse(files['counts.json']);
  const expected = files['checksum.txt'];
  const canonical = canonicalStringify({ counts, ids });
  const actual = sha256(canonical);
  const ok = (expected === actual);
  return { ok, expected, actual, total_ids: ids.length };
}

function tryRecount(files) {
  // Optional recount using local server's accepted.json, if present
  const BOX_FILE = path.join(__dirname, '..', 'data', 'accepted.json');
  if (!fs.existsSync(BOX_FILE)) {
    return { didRecount: false, message: 'No local data/accepted.json found; skipped recount.' };
  }
  const ids = files['accepted_ids.txt'].trim().split('\n').filter(Boolean);
  const box = JSON.parse(fs.readFileSync(BOX_FILE, 'utf8'));
  const idset = new Set(ids);
  const counts = {};
  let included = 0;
  for (const entry of box) {
    if (idset.has(entry.id)) {
      const pref = (entry.ballot.preferences || [])[0];
      if (pref) {
        counts[pref] = (counts[pref] || 0) + 1;
      }
      included++;
    }
  }
  const bundleCounts = JSON.parse(files['counts.json']);
  const match = JSON.stringify(counts) === JSON.stringify(bundleCounts);
  return { didRecount: true, included, counts, bundleCounts, match };
}

function main() {
  const p = process.argv[2];
  if (!p) {
    console.error('Usage: node scripts/verify_tally.js <bundle-folder-or-zip>');
    process.exit(2);
  }
  try {
    const files = readBundle(p);
    const integrity = verifyIntegrity(files);
    console.log('Integrity check:', integrity.ok ? 'OK' : 'FAIL');
    console.log('  expected checksum:', integrity.expected);
    console.log('  actual   checksum:', integrity.actual);
    console.log('  total accepted IDs in bundle:', integrity.total_ids);

    const recount = tryRecount(files);
    if (recount.didRecount) {
      console.log('Recount using local accepted.json →', recount.match ? 'MATCH' : 'MISMATCH');
      console.log('  included ballots:', recount.included);
      if (!recount.match) {
        console.log('  local counts:', recount.counts);
        console.log('  bundle counts:', recount.bundleCounts);
      }
    } else {
      console.log(recount.message);
    }
  } catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
  }
}

if (require.main === module) main();
