require('dotenv').config();
const express = require('express');
const i18n = require('./middleware/i18n');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const csrf = require('csurf');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const geoAccess = require('./middleware/geoAccess');
const { requireAuth, requireMFA, requireRole } = require('./middleware/authz');

const voteRouter = require('./routes/vote');
const authRouter = require('./routes/auth');
const adminRouter = require('./routes/admin');

const app = express();
app.get('/healthz', (req, res) => res.send('ok'));
app.set('trust proxy', 1);
if ((process.env.ENABLE_HTTPS_REDIRECT||'true').toLowerCase()==='true'){
  app.use((req,res,next)=>{
    if(req.secure || req.headers['x-forwarded-proto']==='https') return next();
    if(req.method==='GET'||req.method==='HEAD') return res.redirect('https://' + req.headers.host + req.url);
    return res.status(400).send('HTTPS required');
  });
}

// Trust reverse proxies (X-Forwarded-For)
app.set('trust proxy', true);

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { sameSite: 'lax', httpOnly: true, secure: false }
}));

// Static
app.use('/public', express.static(path.join(__dirname, 'public')));

// EJS + layouts
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// i18n (R20)
const locales = { en: require('./locales/en.json'), zh: require('./locales/zh.json') };
app.use((req, res, next) => {
  const queryLang = (req.query.lang || '').toLowerCase();
  const cookieLang = (req.cookies.lang || '').toLowerCase();
  const lang = (queryLang === 'zh' || queryLang === 'en') ? queryLang :
               (cookieLang === 'zh' ? 'zh' : 'en');
  if (lang !== cookieLang) res.cookie('lang', lang, { httpOnly: false, sameSite: 'lax' });
  req.t = (key) => locales[lang][key] || key;
  res.locals.t = req.t;
  res.locals.lang = lang;
  res.locals.user = req.session.user || null;
  res.locals.mfaPassed = !!req.session.mfaPassed;
  next();
});

// R16: Geo (mount only if enabled)
if ((process.env.GEO_ENABLE || 'true').toLowerCase() !== 'false') {
  app.use(geoAccess);
}

// CSRF
app.use(csrf());

// Routes
app.use('/', voteRouter);
app.use('/evp', voteRouter);
app.use('/auth', authRouter);
app.use('/admin', requireAuth, requireMFA, requireRole('admin'), adminRouter);

// Errors
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Unexpected error');
});

const port = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(port, () => console.log(`Listening on http://localhost:${port}`));
}

module.exports = app;

app.get('/healthz', (_req,res)=>res.json({ ok:true }));
app.use('/token', require('./routes/token'));