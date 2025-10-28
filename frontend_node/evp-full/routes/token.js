const express = require('express');
const router = express.Router();
const { requireRole } = require('../middleware/authz');
const { isEligible } = require('../utils/eligibility');
const { issueToken, redeem } = require('../utils/token');

// Admin issues token to eligible voterId; returns raw token (simulates out-of-band delivery)
router.post('/issue', requireRole(['admin','manager']), (req,res)=>{
  const { voterId } = req.body || {};
  if(!voterId || !isEligible(voterId)) return res.status(400).json({ ok:false, error:'Not eligible' });
  const token = issueToken(voterId);
  res.json({ ok:true, token });
});

// Voter redeems token before voting
router.post('/redeem', (req,res)=>{
  const { token } = req.body || {};
  if(!token) return res.status(400).json({ ok:false, error:'Missing token' });
  if(!redeem(token)) return res.status(400).json({ ok:false, error:'Invalid or already used token' });
  req.session = req.session || {};
  req.session.hasVoteToken = true;
  res.json({ ok:true });
});

module.exports = router;
