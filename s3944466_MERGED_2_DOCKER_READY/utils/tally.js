    const fs = require('fs');
    const path = require('path');
    const crypto = require('crypto');

    const BOX_FILE = path.join(__dirname, '..', 'data', 'accepted.json');

    function loadBox() {
      try { return JSON.parse(fs.readFileSync(BOX_FILE, 'utf8')); } catch { return []; }
    }
    function saveBox(arr) {
      fs.writeFileSync(BOX_FILE, JSON.stringify(arr, null, 2));
    }

    function acceptBallot(ballot) {
      const entry = {
        id: crypto.randomUUID(),
        ballot,
        ts: new Date().toISOString(),
      };
      const box = loadBox();
      box.push(entry);
      saveBox(box);
      return entry.id;
    }

    function computeCounts() {
      const box = loadBox();
      const counts = {};
      for (const entry of box) {
        for (const pref of (entry.ballot.preferences || [])) {
          counts[pref] = (counts[pref] || 0) + 1;
          break; // simple plurality for demo: count only first preference
        }
      }
      return { counts, total_ballots: box.length };
    }

    function buildBundleFiles() {
      const box = loadBox();
      const ids = box.map(e => e.id);
      const { counts, total_ballots } = computeCounts();
      const metadata = {
        generated_at: new Date().toISOString(),
        election: 'house',
        total_ballots,
        algorithm: 'sha256',
        notes: 'Demo bundle: counts are first-preference plurality only.'
      };
      const canonical = JSON.stringify({ counts, ids }, Object.keys({ counts, ids }).sort());
      const checksum = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');

      return {
        'accepted_ids.txt': ids.join('\n') + '\n',
        'counts.json': JSON.stringify(counts, null, 2),
        'metadata.json': JSON.stringify(metadata, null, 2),
        'checksum.txt': checksum,
        'README.txt':
`This bundle contains:
- accepted_ids.txt   (one ID per line)
- counts.json        (totals by candidate)
- metadata.json      (generation details)
- checksum.txt       (SHA-256 over canonical JSON of {counts, ids})

To verify:
1) Extract the ZIP somewhere.
2) Run: node scripts/verify_tally.js <path-to-extracted-folder>

If verifying on the server with access to data/accepted.json, the script will also recompute counts
from ballots matching accepted_ids.txt and compare to counts.json.`
      };
    }

    module.exports = { acceptBallot, computeCounts, buildBundleFiles };
