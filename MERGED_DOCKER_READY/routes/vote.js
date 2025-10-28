const { validate, voteConfirmSchema } = require('../middleware/validate');
const express = require('express');
const { computeReceipt } = require('../utils/receipt');
const { acceptBallot } = require('../utils/tally');

const router = express.Router();

router.get('/', (req, res) => res.redirect('/vote'));

router.get('/vote', (req, res) => {
  res.render('vote', { csrfToken: req.csrfToken(), title: req.t('title_vote') });
});

router.post('/vote/confirm', (req, res) => {
  const { pref1, pref2, pref3 } = req.body;
  const ballot = { election: 'house', preferences: [pref1, pref2, pref3].filter(Boolean) };
  req.session.ballot = ballot;
  const pepper = process.env.RECEIPT_PEPPER || '';
  const receipt = computeReceipt(ballot, pepper);
  res.render('confirm', { csrfToken: req.csrfToken(), title: req.t('title_confirm'), receipt });
});

router.post('/vote/submit', (req, res) => {
  const ballot = req.session.ballot;
  if (!ballot) return res.status(400).send('Missing ballot in session.');
  const pepper = process.env.RECEIPT_PEPPER || '';
  const receipt = computeReceipt(ballot, pepper);

  // R07: accept ballot and assign an ID in the "box"
  const acceptedId = acceptBallot(ballot);

  req.session.ballot = null;
  res.render('receipt', { csrfToken: req.csrfToken(), title: req.t('title_receipt'), receipt, acceptedId });
});

module.exports = router;
