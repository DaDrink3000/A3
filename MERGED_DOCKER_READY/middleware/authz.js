function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/auth/login');
  next();
}

function requireMFA(req, res, next) {
  if (req.session.user && req.session.user.mfaEnabled) {
    if (!req.session.mfaPassed) return res.redirect('/auth/verify-mfa');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    const user = req.session.user;
    if (!user || user.role !== role) return res.status(403).send('Forbidden: insufficient role');
    next();
  };
}

module.exports = { requireAuth, requireMFA, requireRole };
