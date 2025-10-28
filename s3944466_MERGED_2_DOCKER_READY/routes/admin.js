const express = require('express');
const archiver = require('archiver');
const path = require('path');
const { buildBundleFiles } = require('../utils/tally');

const router = express.Router();

router.get('/', (req, res) => {
  res.render('admin', { title: 'Admin Panel' });
});

router.get('/export-tally', async (req, res) => {
  const files = buildBundleFiles();

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="tally_bundle.zip"');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', err => { throw err; });
  archive.pipe(res);

  for (const [name, content] of Object.entries(files)) {
    archive.append(content, { name });
  }

  archive.finalize();
});

module.exports = router;
