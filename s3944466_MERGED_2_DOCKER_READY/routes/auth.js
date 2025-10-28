const { validate, loginSchema, mfaVerifySchema } = require('../middleware/validate');
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const router = express.Router();
const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
function findUser(username) {
  return loadUsers().find(u => u.username.toLowerCase() === String(username).toLowerCase());
}

// Seed default passwords if missing
function ensurePasswordHashes() {
  const users = loadUsers();
  let changed = false;
  users.forEach(u => {
    if (!u.passwordHash) {
      const plain = process.env.DEFAULT_STAFF_PASSWORD || 'Password123!';
      u.passwordHash = bcrypt.hashSync(plain, 10);
      changed = true;
    }
  });
  if (changed) saveUsers(users);
}
ensurePasswordHashes();

router.get('/login', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken(), title: 'Staff Login', err: null });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (!user) return res.status(401).render('login', { csrfToken: req.csrfToken(), title: 'Staff Login', err: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).render('login', { csrfToken: req.csrfToken(), title: 'Staff Login', err: 'Invalid credentials' });

  req.session.user = { username: user.username, role: user.role, mfaEnabled: !!user.mfaEnabled };
  req.session.mfaPassed = !user.mfaEnabled;
  if (user.mfaEnabled) return res.redirect('/auth/verify-mfa');
  res.redirect('/');
});

router.get('/setup-mfa', (req, res) => {
  if (!req.session.user) return res.redirect('/auth/login');
  const user = findUser(req.session.user.username);
  if (user.mfaEnabled) return res.redirect('/auth/verify-mfa');
  const secret = speakeasy.generateSecret({ name: `EVP(${user.username})`, length: 20 });
  req.session.pendingMfa = { base32: secret.base32, otpauth: secret.otpauth_url };
  qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
    if (err) return res.status(500).send('QR error');
    res.render('mfa-setup', { csrfToken: req.csrfToken(), title: 'Set up MFA', qr: dataUrl, secret: secret.base32, err: null });
  });
});

router.post('/setup-mfa', (req, res) => {
  if (!req.session.user || !req.session.pendingMfa) return res.redirect('/auth/login');
  const token = req.body.token;
  const { base32 } = req.session.pendingMfa;
  const ok = speakeasy.totp.verify({ secret: base32, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(400).render('mfa-setup', { csrfToken: req.csrfToken(), title: 'Set up MFA', qr: null, secret: base32, err: 'Invalid code, try again.' });
  const users = loadUsers();
  const idx = users.findIndex(u => u.username.toLowerCase() === req.session.user.username.toLowerCase());
  if (idx >= 0) {
    users[idx].mfaEnabled = true;
    users[idx].mfaSecret = base32;
    saveUsers(users);
  }
  req.session.user.mfaEnabled = true;
  req.session.mfaPassed = true;
  req.session.pendingMfa = null;
  res.redirect('/');
});

router.get('/verify-mfa', (req, res) => {
  if (!req.session.user) return res.redirect('/auth/login');
  res.render('mfa-verify', { csrfToken: req.csrfToken(), title: 'Verify MFA', err: null });
});

router.post('/verify-mfa', (req, res) => {
  if (!req.session.user) return res.redirect('/auth/login');
  const users = loadUsers();
  const user = users.find(u => u.username.toLowerCase() === req.session.user.username.toLowerCase());
  if (!user || !user.mfaEnabled) return res.redirect('/');
  const token = req.body.token;
  const ok = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(400).render('mfa-verify', { csrfToken: req.csrfToken(), title: 'Verify MFA', err: 'Invalid code' });
  req.session.mfaPassed = true;
  res.redirect('/');
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/auth/login'));
});

module.exports = router;
