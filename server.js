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
const PORT = process.env.PORT || 3002;
const COOKIE_MAX_AGE = 60 * 60 * 1000;
const USER_COOKIE_NAME = 'user';
const ADMIN_COOKIE_NAME = 'admin_user';
const LOCAL_DATABASE_FILE = path.join(__dirname, 'data', 'portal-db.json');
const SECURE_USER_COLLECTION = process.env.SECURE_USER_COLLECTION || 'secureUsers';
const LEGACY_USER_COLLECTION = 'users';
const APPLICATION_COLLECTION = process.env.APPLICATION_COLLECTION || 'applications';
const VERIFICATION_COLLECTION = process.env.VERIFICATION_COLLECTION || 'verificationCodes';

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

function getCookieUser(req, cookieName = USER_COOKIE_NAME) {
  if (!req.cookies[cookieName]) {
    return null;
  }

  try {
    return JSON.parse(req.cookies[cookieName]);
  } catch (error) {
    return null;
  }
}

function setUserCookie(res, user, cookieName = USER_COOKIE_NAME) {
  res.cookie(
    cookieName,
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

function clearUserCookie(res, cookieName = USER_COOKIE_NAME) {
  res.clearCookie(cookieName);
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

// Persistent local JSON fallback store when Firebase is not configured.
// This keeps local users, applications, and verification records between
// restarts. Firestore is still used automatically once Firebase credentials
// are configured in .env.
const demoUsersByUid = new Map();
const demoUsersByUsername = new Map();
const demoUsersByEmail = new Map();
const demoApplications = new Map();
const verificationRecords = new Map();
const resetCodes = new Map();

function getDefaultLocalDatabase() {
  return {
    users: [],
    applications: [],
    verifications: [],
  };
}

function ensureLocalDatabaseFile() {
  const directory = path.dirname(LOCAL_DATABASE_FILE);
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true });
  }

  if (!fs.existsSync(LOCAL_DATABASE_FILE)) {
    fs.writeFileSync(
      LOCAL_DATABASE_FILE,
      JSON.stringify(getDefaultLocalDatabase(), null, 2),
      'utf8'
    );
  }
}

function readLocalDatabase() {
  ensureLocalDatabaseFile();

  try {
    const raw = fs.readFileSync(LOCAL_DATABASE_FILE, 'utf8');
    const parsed = raw ? JSON.parse(raw) : getDefaultLocalDatabase();

    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      applications: Array.isArray(parsed.applications) ? parsed.applications : [],
      verifications: Array.isArray(parsed.verifications) ? parsed.verifications : [],
    };
  } catch (error) {
    return getDefaultLocalDatabase();
  }
}

function persistLocalState() {
  if (isFirebaseConfigured()) {
    return;
  }

  ensureLocalDatabaseFile();
  fs.writeFileSync(
    LOCAL_DATABASE_FILE,
    JSON.stringify(
      {
        users: [...demoUsersByUid.values()],
        applications: [...demoApplications.values()],
        verifications: [...verificationRecords.values()],
      },
      null,
      2
    ),
    'utf8'
  );
}

function loadLocalState() {
  if (isFirebaseConfigured()) {
    return;
  }

  const stored = readLocalDatabase();

  demoUsersByUid.clear();
  demoUsersByUsername.clear();
  demoUsersByEmail.clear();
  demoApplications.clear();
  verificationRecords.clear();

  stored.users.forEach(user => {
    if (!user || !user.uid) {
      return;
    }

    const normalizedUser = {
      ...user,
      usernameLower: user.usernameLower || normalizeValue(user.username).toLowerCase(),
      emailLower: user.emailLower || normalizeValue(user.email).toLowerCase(),
    };
    demoUsersByUid.set(normalizedUser.uid, normalizedUser);
    if (normalizedUser.usernameLower) {
      demoUsersByUsername.set(normalizedUser.usernameLower, normalizedUser);
    }
    if (normalizedUser.emailLower) {
      demoUsersByEmail.set(normalizedUser.emailLower, normalizedUser);
    }
  });

  stored.applications.forEach(application => {
    if (application && application.id) {
      demoApplications.set(application.id, application);
    }
  });

  stored.verifications.forEach(record => {
    if (record && record.emailLower) {
      verificationRecords.set(record.emailLower, record);
    }
  });
}

loadLocalState();

function getUserCollectionNames() {
  return [...new Set([SECURE_USER_COLLECTION, LEGACY_USER_COLLECTION])];
}

async function findUserByField(field, value) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    for (const collectionName of getUserCollectionNames()) {
      const snapshot = await firestore
        .collection(collectionName)
        .where(field, '==', value)
        .limit(1)
        .get();

      if (!snapshot.empty) {
        const doc = snapshot.docs[0];
        return { uid: doc.id, ...doc.data() };
      }
    }
    return null;
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

async function findUserForAuthentication(identifier) {
  const cleanIdentifier = normalizeValue(identifier).toLowerCase();
  if (!cleanIdentifier) {
    return null;
  }

  let user = await findUserByField('usernameLower', cleanIdentifier);
  if (!user) {
    user = await findUserByField('emailLower', cleanIdentifier);
  }

  return user;
}

async function createUser(userData) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const userRef = firestore.collection(SECURE_USER_COLLECTION).doc();
    const record = {
      ...userData,
      uid: userRef.id,
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await userRef.set(record);
    return { ...record, uid: userRef.id };
  }

  const now = Date.now();
  const uid = crypto.randomBytes(12).toString('hex');
  const record = { ...userData, uid, createdAt: now, createdAtMs: now, updatedAtMs: now };
  demoUsersByUid.set(uid, record);
  if (record.usernameLower) demoUsersByUsername.set(record.usernameLower, record);
  if (record.emailLower) demoUsersByEmail.set(record.emailLower, record);
  persistLocalState();
  return record;
}

async function updateUserPassword(uid, passwordHash, passwordSalt) {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    for (const collectionName of getUserCollectionNames()) {
      const docRef = firestore.collection(collectionName).doc(uid);
      const snapshot = await docRef.get();

      if (!snapshot.exists) {
        continue;
      }

      await docRef.update({
        passwordHash,
        passwordSalt,
        updatedAtMs: Date.now(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return;
    }

    await firestore
      .collection(SECURE_USER_COLLECTION)
      .doc(uid)
      .set(
        {
          uid,
          passwordHash,
          passwordSalt,
          updatedAtMs: Date.now(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    return;
  }

  const record = demoUsersByUid.get(uid);
  if (!record) return;
  record.passwordHash = passwordHash;
  record.passwordSalt = passwordSalt;
  record.updatedAt = Date.now();
  record.updatedAtMs = record.updatedAt;
  persistLocalState();
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

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderTemplateFile(relativePath, replacements = {}) {
  const filePath = path.join(__dirname, relativePath);
  let template = fs.readFileSync(filePath, 'utf8');

  Object.entries(replacements).forEach(([key, value]) => {
    template = template.split(`{{${key}}}`).join(String(value ?? ''));
  });

  return template;
}

function sanitizeReturnTo(value, fallback = '/dashboard') {
  const candidate = normalizeValue(value);
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) {
    return fallback;
  }

  return candidate;
}

function humanizeSlug(value) {
  return normalizeValue(value)
    .replace(/[-_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, letter => letter.toUpperCase());
}

function inferSourcePath(req, explicitValue = '') {
  let candidate = sanitizeReturnTo(explicitValue, '');

  if (!candidate) {
    const referer = req.get('referer');
    if (referer) {
      try {
        candidate = sanitizeReturnTo(new URL(referer).pathname, '');
      } catch (error) {
        candidate = '';
      }
    }
  }

  return candidate || '/';
}

function inferSourceLabel(sourcePath, explicitTitle = '') {
  const cleanTitle = normalizeValue(explicitTitle);
  if (cleanTitle) {
    return cleanTitle;
  }

  const cleanPath = sanitizeReturnTo(sourcePath, '/');
  const segments = cleanPath.split('/').filter(Boolean);
  if (!segments.length) {
    return 'Immigration New Zealand';
  }

  let lastSegment = segments[segments.length - 1];
  if (/^index\.html?$/i.test(lastSegment) && segments.length > 1) {
    lastSegment = segments[segments.length - 2];
  }

  return humanizeSlug(lastSegment) || 'Immigration New Zealand';
}

function getTimestampMs(value) {
  if (!value) return 0;
  if (typeof value === 'number') return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value.toMillis === 'function') return value.toMillis();
  if (typeof value.seconds === 'number') return value.seconds * 1000;
  return 0;
}

function formatDateTime(ms) {
  if (!ms) return 'Just now';
  return new Intl.DateTimeFormat('en-NZ', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(ms));
}

const ADMIN_EMAILS = new Set([
  'ffclimmigration@gmail.com',
  normalizeValue(process.env.ADMIN_EMAIL || '').toLowerCase(),
].filter(Boolean));

function isAdminUser(user) {
  if (!user) return false;
  const email = normalizeValue(user.email).toLowerCase();
  const username = normalizeValue(user.username).toLowerCase();
  return ADMIN_EMAILS.has(email) || username === 'admin' || username === 'officialimmigration';
}

function requireAdmin(req, res, next) {
  if (!isAdminUser(req.user)) {
    res.status(403).send(`
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Admin Access Required</title>
        <style>
          body{margin:0;font-family:Inter,Arial,sans-serif;background:#0d1117;color:#f4f7fb;display:grid;place-items:center;min-height:100vh;padding:24px}
          .card{max-width:560px;background:#111826;border:1px solid #273244;border-radius:20px;padding:32px;box-shadow:0 18px 60px rgba(0,0,0,.35)}
          h1{margin:0 0 12px;font-size:28px;color:#ff8a4c}
          p{margin:0 0 18px;line-height:1.6;color:#b7c0cd}
          a{display:inline-block;padding:12px 18px;border-radius:12px;background:#e35205;color:#fff;text-decoration:none;font-weight:600}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Admin Access Required</h1>
          <p>This area is reserved for the official Immigration control team. Sign in with an approved administrator account to manage approvals and website operations.</p>
          <a href="/dashboard">Return to dashboard</a>
        </div>
      </body>
      </html>
    `);
    return;
  }

  next();
}

function seedDemoApplications() {
  if (demoApplications.size > 0) return;

  const now = Date.now();
  [
    {
      id: 'demo-aewv-review',
      title: 'Accredited Employer Work Visa Review',
      type: 'Visa Approval',
      applicantName: 'Mia Thompson',
      applicantEmail: 'mia.thompson@example.com',
      sourcePath: '/www.immigration.govt.nz/visas/accredited-employer-work-visa/index.htm',
      summary: 'Awaiting final review for employer accreditation evidence and wage validation.',
      status: 'pending',
      priority: 'high',
      submittedAtMs: now - 1000 * 60 * 50,
      updatedAtMs: now - 1000 * 60 * 50,
      history: [],
    },
    {
      id: 'demo-family-visa',
      title: 'Family Residence Supporting Documents',
      type: 'Document Review',
      applicantName: 'Daniel Okafor',
      applicantEmail: 'daniel.okafor@example.com',
      sourcePath: '/live/resident-visas-to-live-in-new-zealand',
      summary: 'Medical and police certificate set submitted for review by compliance team.',
      status: 'in_review',
      priority: 'medium',
      submittedAtMs: now - 1000 * 60 * 180,
      updatedAtMs: now - 1000 * 60 * 70,
      history: [
        {
          atMs: now - 1000 * 60 * 70,
          action: 'Moved to in review',
          actor: 'System',
          note: 'Assigned to case management queue.',
        },
      ],
    },
    {
      id: 'demo-portal-access',
      title: 'Portal Account Approval',
      type: 'Account Approval',
      applicantName: 'Aisha Bello',
      applicantEmail: 'aisha.bello@example.com',
      sourcePath: '/login/signup',
      summary: 'New portal account registration waiting for administrator approval.',
      status: 'needs_info',
      priority: 'low',
      submittedAtMs: now - 1000 * 60 * 420,
      updatedAtMs: now - 1000 * 60 * 100,
      history: [
        {
          atMs: now - 1000 * 60 * 100,
          action: 'Requested more information',
          actor: 'System',
          note: 'Awaiting passport image upload.',
        },
      ],
    },
  ].forEach(application => {
    demoApplications.set(application.id, application);
  });

  persistLocalState();
}

async function listPortalUsers() {
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const snapshots = await Promise.all(
      getUserCollectionNames().map(collectionName => firestore.collection(collectionName).get())
    );
    const users = new Map();

    snapshots.forEach(snapshot => {
      snapshot.docs.forEach(doc => {
        users.set(doc.id, { uid: doc.id, ...doc.data() });
      });
    });

    return [...users.values()]
      .sort((a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0));
  }

  return [...demoUsersByUid.values()].sort(
    (a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0)
  );
}

async function listApplications() {
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(APPLICATION_COLLECTION).get();
    return snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .sort((a, b) => (b.updatedAtMs || b.submittedAtMs || 0) - (a.updatedAtMs || a.submittedAtMs || 0));
  }

  seedDemoApplications();
  return [...demoApplications.values()].sort(
    (a, b) => (b.updatedAtMs || b.submittedAtMs || 0) - (a.updatedAtMs || a.submittedAtMs || 0)
  );
}

async function listApplicationsForUser(user) {
  const allApplications = await listApplications();
  const email = normalizeValue(user && user.email).toLowerCase();
  const uid = normalizeValue(user && user.uid);

  return allApplications.filter(application => {
    const applicantEmail = normalizeValue(application.applicantEmail).toLowerCase();
    const submittedByUid = normalizeValue(application.submittedByUid);
    return (email && applicantEmail === email) || (uid && submittedByUid === uid);
  });
}

async function createApplicationRecord(applicationData) {
  const now = Date.now();
  const baseRecord = {
    title: applicationData.title,
    type: applicationData.type || 'General Review',
    applicantName: applicationData.applicantName,
    applicantEmail: applicationData.applicantEmail,
    applicantUsername: applicationData.applicantUsername || '',
    submittedByUid: applicationData.submittedByUid || '',
    sourcePath: applicationData.sourcePath || '/',
    sourceLabel: applicationData.sourceLabel || inferSourceLabel(applicationData.sourcePath || '/'),
    summary: applicationData.summary || '',
    documentChecklist: applicationData.documentChecklist || '',
    requestedStartDate: applicationData.requestedStartDate || '',
    status: applicationData.status || 'pending',
    priority: applicationData.priority || 'medium',
    submittedAtMs: now,
    updatedAtMs: now,
    history: [
      {
        atMs: now,
        action: 'Created',
        actor: 'System',
        note: 'Application added to approval queue.',
      },
    ],
  };

  if (isFirebaseConfigured()) {
    const docRef = ensureFirebaseReady().collection(APPLICATION_COLLECTION).doc();
    const record = {
      ...baseRecord,
      id: docRef.id,
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await docRef.set(record);
    return record;
  }

  const record = {
    ...baseRecord,
    id: applicationData.id || crypto.randomBytes(8).toString('hex'),
  };
  demoApplications.set(record.id, record);
  persistLocalState();
  return record;
}

async function updateApplicationStatus(id, status, reviewer, note) {
  const cleanStatus = normalizeValue(status) || 'pending';
  const cleanNote = normalizeValue(note);
  const event = {
    atMs: Date.now(),
    action:
      cleanStatus === 'approved'
        ? 'Approved'
        : cleanStatus === 'rejected'
          ? 'Rejected'
          : cleanStatus === 'needs_info'
            ? 'Requested more information'
            : 'Moved to in review',
    actor: reviewer.name || reviewer.username || reviewer.email || 'Administrator',
    note: cleanNote || 'No reviewer note supplied.',
  };

  if (isFirebaseConfigured()) {
    const docRef = ensureFirebaseReady().collection(APPLICATION_COLLECTION).doc(id);
    const snapshot = await docRef.get();
    if (!snapshot.exists) {
      throw new Error('Approval item not found.');
    }
    const application = snapshot.data();
    const history = Array.isArray(application.history) ? application.history : [];
    await docRef.set(
      {
        status: cleanStatus,
        reviewerName: reviewer.name || reviewer.username || reviewer.email,
        reviewerEmail: reviewer.email || '',
        reviewerNote: cleanNote,
        updatedAtMs: event.atMs,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        history: [...history, event],
      },
      { merge: true }
    );
    return;
  }

  seedDemoApplications();
  const application = demoApplications.get(id);
  if (!application) {
    throw new Error('Approval item not found.');
  }
  application.status = cleanStatus;
  application.reviewerName = reviewer.name || reviewer.username || reviewer.email;
  application.reviewerEmail = reviewer.email || '';
  application.reviewerNote = cleanNote;
  application.updatedAtMs = event.atMs;
  application.history = [...(application.history || []), event];
  demoApplications.set(id, application);
  persistLocalState();
}

async function getVerificationRecord(email) {
  const emailLower = normalizeValue(email).toLowerCase();
  if (!emailLower) {
    return null;
  }

  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(VERIFICATION_COLLECTION).doc(emailLower).get();
    if (!snapshot.exists) {
      return null;
    }

    return {
      emailLower,
      ...snapshot.data(),
    };
  }

  return verificationRecords.get(emailLower) || null;
}

async function saveVerificationRecord(email, updates = {}) {
  const emailLower = normalizeValue(email).toLowerCase();
  if (!emailLower) {
    throw new Error('Verification email is required.');
  }

  const existingRecord = await getVerificationRecord(emailLower);
  const now = Date.now();
  const record = {
    email: updates.email || existingRecord?.email || emailLower,
    emailLower,
    code: updates.code ?? existingRecord?.code ?? '',
    expires: updates.expires ?? existingRecord?.expires ?? 0,
    verified: updates.verified ?? existingRecord?.verified ?? false,
    createdAtMs: existingRecord?.createdAtMs || updates.createdAtMs || now,
    updatedAtMs: updates.updatedAtMs || now,
    verifiedAtMs: updates.verifiedAtMs ?? existingRecord?.verifiedAtMs ?? null,
    registeredAtMs: updates.registeredAtMs ?? existingRecord?.registeredAtMs ?? null,
    registeredUserUid: updates.registeredUserUid ?? existingRecord?.registeredUserUid ?? '',
    registeredUsername: updates.registeredUsername ?? existingRecord?.registeredUsername ?? '',
    status: updates.status || existingRecord?.status || 'sent',
  };

  if (isFirebaseConfigured()) {
    await ensureFirebaseReady()
      .collection(VERIFICATION_COLLECTION)
      .doc(emailLower)
      .set(
        {
          ...record,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    return record;
  }

  verificationRecords.set(emailLower, record);
  persistLocalState();
  return record;
}

async function listVerificationRecords(limitCount = 10) {
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady()
      .collection(VERIFICATION_COLLECTION)
      .orderBy('updatedAtMs', 'desc')
      .limit(limitCount)
      .get();

    return snapshot.docs.map(doc => ({ emailLower: doc.id, ...doc.data() }));
  }

  return [...verificationRecords.values()]
    .sort((a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0))
    .slice(0, limitCount);
}

function getVerificationStatus(record) {
  if (!record) {
    return 'unknown';
  }

  if (record.registeredAtMs) {
    return 'registered';
  }

  if (record.verified) {
    return 'verified';
  }

  if (record.expires && Date.now() > record.expires) {
    return 'expired';
  }

  return 'sent';
}

function isAuthenticated(req, res, next) {
  const user = getCookieUser(req) || getCookieUser(req, ADMIN_COOKIE_NAME);

  if (!user) {
    res.redirect(buildRedirect('/login', { returnTo: req.originalUrl || req.url || '/dashboard' }));
    return;
  }

  req.user = user;
  next();
}

function requireAdminSession(req, res, next) {
  const adminUser = getCookieUser(req, ADMIN_COOKIE_NAME);

  if (!adminUser || !isAdminUser(adminUser)) {
    clearUserCookie(res, ADMIN_COOKIE_NAME);
    res.redirect(
      buildRedirect('/admin/login', {
        returnTo: sanitizeReturnTo(req.originalUrl || req.url || '/admin', '/admin'),
      })
    );
    return;
  }

  req.user = adminUser;
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

app.get('/admin/login', (req, res) => {
  const returnTo = sanitizeReturnTo(req.query.returnTo, '/admin');
  const currentAdmin = getCookieUser(req, ADMIN_COOKIE_NAME);

  if (currentAdmin && isAdminUser(currentAdmin)) {
    res.redirect(returnTo);
    return;
  }

  const success = normalizeValue(req.query.success);
  const error = normalizeValue(req.query.error);
  const flash = success
    ? `<div class="flash flash-success">${escapeHtml(success)}</div>`
    : error
      ? `<div class="flash flash-error">${escapeHtml(error)}</div>`
      : '';

  res.send(
    renderTemplateFile('templates/admin-login.html', {
      FLASH: flash,
      RETURN_TO: escapeHtml(returnTo),
      PRIMARY_ADMIN: escapeHtml([...ADMIN_EMAILS][0] || 'Not configured'),
    })
  );
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
    const existing = await findUserByField('emailLower', email.toLowerCase());
    if (existing) {
      return res.status(400).json({ error: 'That email address is already registered.' });
    }

    const existingVerification = await getVerificationRecord(email);
    if (existingVerification && getVerificationStatus(existingVerification) === 'registered') {
      return res.status(400).json({ error: 'That email address is already registered.' });
    }

    const code = generateVerificationCode();
    await saveVerificationRecord(email, {
      email,
      code,
      expires: Date.now() + 10 * 60 * 1000,
      verified: false,
      verifiedAtMs: null,
      registeredAtMs: null,
      registeredUserUid: '',
      registeredUsername: '',
      status: 'sent',
    });

    console.log(`[Verification] Code for ${email}: ${code}`);

    return res.json({
      success: true,
      message: `A verification code has been sent to the admin dashboard for ${email}.`,
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || 'Unable to send verification code right now.',
    });
  }
});

app.post('/confirm-verification-code', async (req, res) => {
  const email = normalizeValue(req.body.email);
  const code = normalizeValue(req.body.code);

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and confirmation code are required.' });
  }

  try {
    const entry = await getVerificationRecord(email);
    if (!entry || entry.code !== code || Date.now() > entry.expires) {
      return res.status(400).json({ error: 'Invalid or expired confirmation code.' });
    }

    await saveVerificationRecord(email, {
      ...entry,
      verified: true,
      verifiedAtMs: Date.now(),
      expires: Date.now() + 30 * 60 * 1000,
      status: 'verified',
    });

    return res.json({
      success: true,
      message: 'Email address confirmed successfully.',
    });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Unable to confirm the code right now.' });
  }
});

// ---------- Register (now requires verified email) ----------
app.post('/register', async (req, res) => {
  const email = normalizeValue(req.body.email);
  const username = normalizeValue(req.body.username);
  const password = normalizeValue(req.body.password);
  const confirmPassword = normalizeValue(req.body.confirmPassword);
  const returnTo = sanitizeReturnTo(req.body.returnTo, '/dashboard');

  if (!email || !username || !password || !confirmPassword) {
    res.redirect(buildRedirect('/login/signup', { error: 'All fields are required.', returnTo }));
    return;
  }

  try {
    const verification = await getVerificationRecord(email);
    if (!verification || !verification.verified || Date.now() > verification.expires) {
      res.redirect(
        buildRedirect('/login/signup', {
          error: 'Please verify your email address before creating an account.',
          returnTo,
        })
      );
      return;
    }

    if (username.length < 4) {
      res.redirect(buildRedirect('/login/signup', { error: 'Username must be at least 4 characters.', returnTo }));
      return;
    }

    if (password.length < 8) {
      res.redirect(buildRedirect('/login/signup', { error: 'Password must be at least 8 characters.', returnTo }));
      return;
    }

    if (password !== confirmPassword) {
      res.redirect(buildRedirect('/login/signup', { error: 'Passwords do not match.', returnTo }));
      return;
    }

    const existingUsername = await findUserByField('usernameLower', username.toLowerCase());
    if (existingUsername) {
      res.redirect(buildRedirect('/login/signup', { error: 'That username is already registered.', returnTo }));
      return;
    }

    const existingEmail = await findUserByField('emailLower', email.toLowerCase());
    if (existingEmail) {
      res.redirect(buildRedirect('/login/signup', { error: 'That email address is already registered.', returnTo }));
      return;
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

    try {
      await createApplicationRecord({
        title: `Portal access request for ${username}`,
        type: 'Account Approval',
        applicantName: username,
        applicantEmail: email,
        applicantUsername: username,
        submittedByUid: user.uid,
        sourcePath: '/login/signup',
        sourceLabel: 'Portal account registration',
        summary: 'New user registration created through the portal and ready for admin review.',
        priority: 'medium',
      });
    } catch (applicationError) {
      console.error('Unable to create admin approval record:', applicationError.message);
    }

    await saveVerificationRecord(email, {
      ...verification,
      expires: Date.now(),
      registeredAtMs: Date.now(),
      registeredUserUid: user.uid,
      registeredUsername: user.username,
      status: 'registered',
    });

    setUserCookie(res, user);
    res.redirect(returnTo);
  } catch (error) {
    res.redirect(
      buildRedirect('/login/signup', {
        error: error.message || 'Unable to create your account right now.',
        returnTo,
      })
    );
  }
});

app.post('/login', async (req, res) => {
  const username = normalizeValue(req.body.username);
  const password = normalizeValue(req.body.password);
  const returnTo = sanitizeReturnTo(req.body.returnTo || req.query.returnTo, '/dashboard');

  if (!username || !password) {
    res.redirect(buildRedirect('/login', { error: 'Enter your username and password.', returnTo }));
    return;
  }

  try {
    const user = await findUserForAuthentication(username);
    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.redirect(buildRedirect('/login', { error: 'Invalid username or password.', returnTo }));
      return;
    }

    setUserCookie(res, user);
    res.redirect(returnTo);
  } catch (error) {
    res.redirect(
      buildRedirect('/login', {
        error: error.message || 'Unable to sign you in right now.',
        returnTo,
      })
    );
  }
});

app.post('/admin/login', async (req, res) => {
  const identifier = normalizeValue(req.body.identifier);
  const password = normalizeValue(req.body.password);
  const returnTo = sanitizeReturnTo(req.body.returnTo, '/admin');

  if (!identifier || !password) {
    res.redirect(buildRedirect('/admin/login', { error: 'Enter your admin username or email and password.', returnTo }));
    return;
  }

  try {
    const user = await findUserForAuthentication(identifier);
    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.redirect(buildRedirect('/admin/login', { error: 'Invalid admin credentials.', returnTo }));
      return;
    }

    if (!isAdminUser(user)) {
      res.redirect(buildRedirect('/admin/login', { error: 'This account is not approved for admin access.', returnTo }));
      return;
    }

    setUserCookie(res, user);
    setUserCookie(res, user, ADMIN_COOKIE_NAME);
    res.redirect(returnTo);
  } catch (error) {
    res.redirect(
      buildRedirect('/admin/login', {
        error: error.message || 'Unable to sign in to the admin workspace right now.',
        returnTo,
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
  const canAccessAdmin = isAdminUser(req.user);
  const adminNav = canAccessAdmin ? '<a href="/admin">Admin</a>' : '';
  const adminCard = canAccessAdmin
    ? `
          <a href="/admin" class="action-card">
            <div class="icon">🛡️</div>
            <h3>Admin Control</h3>
            <p>Review website approvals, monitor portal users, and manage operational decisions in one place.</p>
            <div class="arrow">→</div>
          </a>
      `
    : '';

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
            ${adminNav}
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
          ${adminCard}
        </section>
      </main>
    </body>
    </html>
  `);
});

app.get('/apply', isAuthenticated, async (req, res) => {
  try {
    const sourcePath = inferSourcePath(req, req.query.source || req.query.sourcePath);
    const sourceLabel = inferSourceLabel(sourcePath, req.query.title);
    const recentApplications = (await listApplicationsForUser(req.user)).slice(0, 6);
    const success = normalizeValue(req.query.success);
    const error = normalizeValue(req.query.error);
    const flash = success
      ? `<div class="flash flash-success">${escapeHtml(success)}</div>`
      : error
        ? `<div class="flash flash-error">${escapeHtml(error)}</div>`
        : '';
    const selectedType = normalizeValue(req.query.type) || 'Work Visa';
    const selectedPriority = normalizeValue(req.query.priority) || 'medium';
    const visaTypes = ['Work Visa', 'Visitor Visa', 'Student Visa', 'Residence Visa', 'Citizenship', 'Portal Access', 'Document Review'];
    const priorityOptions = ['low', 'medium', 'high'];
    const recentMarkup = recentApplications.length
      ? recentApplications.map(application => `
          <li>
            <strong>${escapeHtml(application.title)}</strong>
            <span>${escapeHtml((application.status || 'pending').replace('_', ' '))} · ${escapeHtml(formatDateTime(application.updatedAtMs || application.submittedAtMs || getTimestampMs(application.updatedAt)))}</span>
            <p>${escapeHtml(application.summary || 'No summary recorded.')}</p>
          </li>
        `).join('')
      : '<li><strong>No submissions yet</strong><span>New applications will appear here once you send them to the queue.</span><p>Your next submission will be visible to the admin team immediately.</p></li>';

    res.send(
      renderTemplateFile('templates/application-form.html', {
        FLASH: flash,
        APPLICANT_NAME: escapeHtml(req.user.name || req.user.username),
        APPLICANT_EMAIL: escapeHtml(req.user.email || ''),
        APPLICANT_USERNAME: escapeHtml(req.user.username || ''),
        SOURCE_PATH: escapeHtml(sourcePath),
        SOURCE_LABEL: escapeHtml(sourceLabel),
        DEFAULT_APPLICATION_TITLE: escapeHtml(req.query.title || `${sourceLabel} application`),
        DEFAULT_SUMMARY: escapeHtml(req.query.summary || `Application started from ${sourceLabel}. Please review the submitted eligibility details and supporting information.`),
        DEFAULT_DOCUMENTS: '',
        REQUESTED_START_DATE: '',
        VISA_TYPE_OPTIONS: visaTypes
          .map(type => `<option value="${escapeHtml(type)}"${type === selectedType ? ' selected' : ''}>${escapeHtml(type)}</option>`)
          .join(''),
        PRIORITY_OPTIONS: priorityOptions
          .map(priority => `<option value="${priority}"${priority === selectedPriority ? ' selected' : ''}>${escapeHtml(humanizeSlug(priority))}</option>`)
          .join(''),
        RECENT_APPLICATIONS: recentMarkup,
      })
    );
  } catch (error) {
    res.status(500).send(`Unable to load the application form: ${escapeHtml(error.message)}`);
  }
});

app.post('/apply', isAuthenticated, async (req, res) => {
  const sourcePath = inferSourcePath(req, req.body.sourcePath);
  const applicationTitle = normalizeValue(req.body.applicationTitle);
  const visaType = normalizeValue(req.body.visaType) || 'General Review';
  const priority = ['low', 'medium', 'high'].includes(normalizeValue(req.body.priority).toLowerCase())
    ? normalizeValue(req.body.priority).toLowerCase()
    : 'medium';
  const requestedStartDate = normalizeValue(req.body.requestedStartDate);
  const summary = normalizeValue(req.body.summary);
  const documentChecklist = normalizeValue(req.body.documentChecklist);

  if (!applicationTitle || !summary) {
    res.redirect(
      buildRedirect('/apply', {
        error: 'Application title and summary are required.',
        source: sourcePath,
        title: applicationTitle || inferSourceLabel(sourcePath),
        type: visaType,
        priority,
      })
    );
    return;
  }

  try {
    await createApplicationRecord({
      title: applicationTitle,
      type: visaType,
      applicantName: req.user.name || req.user.username,
      applicantEmail: req.user.email,
      applicantUsername: req.user.username,
      submittedByUid: req.user.uid,
      sourcePath,
      sourceLabel: inferSourceLabel(sourcePath, applicationTitle),
      summary,
      documentChecklist,
      requestedStartDate,
      priority,
      status: 'pending',
    });

    res.redirect(
      buildRedirect('/apply', {
        success: 'Application submitted to the approval queue successfully.',
        source: sourcePath,
        title: applicationTitle,
        type: visaType,
      })
    );
  } catch (error) {
    res.redirect(
      buildRedirect('/apply', {
        error: error.message || 'Unable to submit the application right now.',
        source: sourcePath,
        title: applicationTitle || inferSourceLabel(sourcePath),
        type: visaType,
        priority,
      })
    );
  }
});

app.get('/admin', requireAdminSession, async (req, res) => {
  try {
    const applications = await listApplications();
    const users = await listPortalUsers();
    const verificationItems = await listVerificationRecords(10);
    const pendingCount = applications.filter(item => item.status === 'pending').length;
    const inReviewCount = applications.filter(item => item.status === 'in_review').length;
    const approvedCount = applications.filter(item => item.status === 'approved').length;
    const urgentCount = applications.filter(item => item.priority === 'high').length;
    const latestUsers = users.slice(0, 8);
    const latestActivity = applications
      .flatMap(app =>
        (app.history || []).map(event => ({
          ...event,
          applicationTitle: app.title,
        }))
      )
      .sort((a, b) => (b.atMs || 0) - (a.atMs || 0))
      .slice(0, 8);
    const success = normalizeValue(req.query.success);
    const error = normalizeValue(req.query.error);
    const flash = success
      ? `<div class="flash flash-success">${escapeHtml(success)}</div>`
      : error
        ? `<div class="flash flash-error">${escapeHtml(error)}</div>`
        : '';

    const applicationMarkup = applications.length
      ? applications.map(app => {
          const statusClass = `status-${escapeHtml(app.status)}`;
          const priorityClass = `priority-${escapeHtml(app.priority)}`;
          const historyHtml = (app.history || [])
            .slice()
            .sort((a, b) => (b.atMs || 0) - (a.atMs || 0))
            .slice(0, 3)
            .map(event => `
                <li>
                  <strong>${escapeHtml(event.action)}</strong>
                  <span>${escapeHtml(event.actor)} · ${escapeHtml(formatDateTime(event.atMs))}</span>
                  <p>${escapeHtml(event.note || '')}</p>
                </li>
              `)
            .join('');

          return `
            <article class="queue-card">
              <div class="queue-top">
                <div>
                  <div class="queue-eyebrow">${escapeHtml(app.type || 'Review')}</div>
                  <h3>${escapeHtml(app.title)}</h3>
                  <p class="queue-summary">${escapeHtml(app.summary || 'No summary provided.')}</p>
                </div>
                <div class="queue-badges">
                  <span class="status-pill ${statusClass}">${escapeHtml((app.status || 'pending').replace('_', ' '))}</span>
                  <span class="priority-pill ${priorityClass}">${escapeHtml(app.priority || 'medium')} priority</span>
                </div>
              </div>
              <div class="queue-meta">
                <span><strong>Applicant</strong> ${escapeHtml(app.applicantName || 'Unknown')}</span>
                <span><strong>Email</strong> ${escapeHtml(app.applicantEmail || 'Not supplied')}</span>
                <span><strong>Submitted</strong> ${escapeHtml(formatDateTime(app.submittedAtMs || getTimestampMs(app.submittedAt)))}</span>
                <span><strong>Source</strong> <a href="${escapeHtml(app.sourcePath || '/')}">${escapeHtml(app.sourceLabel || app.sourcePath || '/')}</a></span>
              </div>
              <div class="queue-body">
                <div class="queue-history">
                  <h4>Recent Activity</h4>
                  <ul>${historyHtml || '<li><strong>Created</strong><span>System</span><p>No review activity yet.</p></li>'}</ul>
                </div>
                <form method="POST" action="/admin/applications/${encodeURIComponent(app.id)}/status" class="queue-form">
                  <label>
                    Reviewer note
                    <textarea name="note" placeholder="Add context for the next team member, applicant, or audit trail.">${escapeHtml(app.reviewerNote || '')}</textarea>
                  </label>
                  <div class="queue-actions">
                    <button type="submit" name="status" value="approved" class="btn btn-approve">Approve</button>
                    <button type="submit" name="status" value="in_review" class="btn btn-review">Mark In Review</button>
                    <button type="submit" name="status" value="needs_info" class="btn btn-request">Request Info</button>
                    <button type="submit" name="status" value="rejected" class="btn btn-reject">Reject</button>
                  </div>
                </form>
              </div>
            </article>
          `;
        }).join('')
      : '<div class="empty-state"><h3>No approval items yet</h3><p>New portal registrations and submissions will appear here automatically.</p></div>';

    const userMarkup = latestUsers.length
      ? latestUsers.map(user => `
          <tr>
            <td>${escapeHtml(user.name || user.username || 'Unknown')}</td>
            <td>${escapeHtml(user.email || 'No email')}</td>
            <td>${escapeHtml(user.username || 'No username')}</td>
            <td>${escapeHtml(formatDateTime(user.createdAtMs || getTimestampMs(user.createdAt)))}</td>
          </tr>
        `).join('')
      : '<tr><td colspan="4">No registered users found.</td></tr>';

    const verificationMarkup = verificationItems.length
      ? verificationItems.map(item => `
          <tr>
            <td>${escapeHtml(item.email || item.emailLower || 'Unknown')}</td>
            <td><span class="code-chip">${escapeHtml(item.code || 'N/A')}</span></td>
            <td>${escapeHtml(getVerificationStatus(item))}</td>
            <td>${escapeHtml(formatDateTime(item.updatedAtMs || item.createdAtMs))}</td>
          </tr>
        `).join('')
      : '<tr><td colspan="4">No verification codes have been issued yet.</td></tr>';

    const activityMarkup = latestActivity.length
      ? latestActivity.map(item => `
          <li>
            <div>
              <strong>${escapeHtml(item.action)}</strong>
              <span>${escapeHtml(item.applicationTitle)}</span>
            </div>
            <time>${escapeHtml(formatDateTime(item.atMs))}</time>
          </li>
        `).join('')
      : '<li><div><strong>System ready</strong><span>No approval actions have been taken yet.</span></div><time>Now</time></li>';

    res.send(
      renderTemplateFile('templates/admin-control-centre.html', {
        FLASH: flash,
        CURRENT_USER: escapeHtml(req.user.email || req.user.username),
        STORAGE_MODE: escapeHtml(isFirebaseConfigured() ? 'Firebase / Firestore' : 'Local JSON database'),
        PENDING_COUNT: pendingCount,
        IN_REVIEW_COUNT: inReviewCount,
        APPROVED_COUNT: approvedCount,
        URGENT_COUNT: urgentCount,
        APPLICATION_MARKUP: applicationMarkup,
        USER_MARKUP: userMarkup,
        VERIFICATION_MARKUP: verificationMarkup,
        ACTIVITY_MARKUP: activityMarkup,
        APPROVAL_STORAGE_TEXT: escapeHtml(isFirebaseConfigured() ? 'Firestore-backed production storage.' : `Local JSON database at ${LOCAL_DATABASE_FILE}`),
        USER_STORAGE_TEXT: escapeHtml(
          isFirebaseConfigured()
            ? `Hashed credentials stored in Firestore collection "${SECURE_USER_COLLECTION}".`
            : 'Hashed credentials stored in the local JSON fallback database.'
        ),
        PRIMARY_ADMIN: escapeHtml([...ADMIN_EMAILS][0] || 'Not configured'),
      })
    );
  } catch (error) {
    res.status(500).send(`Unable to load admin workspace: ${escapeHtml(error.message)}`);
  }
});

app.post('/admin/applications/:id/status', requireAdminSession, async (req, res) => {
  const id = normalizeValue(req.params.id);
  const status = normalizeValue(req.body.status);
  const note = normalizeValue(req.body.note);

  try {
    await updateApplicationStatus(id, status, req.user, note);
    res.redirect(buildRedirect('/admin', { success: 'Approval queue updated successfully.' }));
  } catch (error) {
    res.redirect(buildRedirect('/admin', { error: error.message || 'Unable to update approval.' }));
  }
});

app.get('/logout', (req, res) => {
  clearUserCookie(res, USER_COOKIE_NAME);
  clearUserCookie(res, ADMIN_COOKIE_NAME);
  res.redirect('/');
});

app.get('/admin/logout', (req, res) => {
  clearUserCookie(res, ADMIN_COOKIE_NAME);
  res.redirect(buildRedirect('/admin/login', { success: 'Admin session ended successfully.' }));
});

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
