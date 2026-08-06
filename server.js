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
const RENDER_DISK_ROOT = process.env.RENDER_DISK_ROOT || '';
const COOKIE_MAX_AGE = 60 * 60 * 1000;
const USER_COOKIE_NAME = 'user';
const ADMIN_COOKIE_NAME = 'admin_user';
const LOCAL_DATABASE_FILE = process.env.LOCAL_DATABASE_FILE
  ? path.resolve(process.env.LOCAL_DATABASE_FILE)
  : (RENDER_DISK_ROOT ? path.join(RENDER_DISK_ROOT, 'data', 'portal-db.json') : path.join(__dirname, 'data', 'portal-db.json'));
const SECURE_USER_COLLECTION = process.env.SECURE_USER_COLLECTION || 'secureUsers';
const LEGACY_USER_COLLECTION = 'users';
const APPLICATION_COLLECTION = process.env.APPLICATION_COLLECTION || 'applications';
const VERIFICATION_COLLECTION = process.env.VERIFICATION_COLLECTION || 'verificationCodes';
const DOCUMENT_COLLECTION = process.env.DOCUMENT_COLLECTION || 'documents';
const PAYMENT_COLLECTION = process.env.PAYMENT_COLLECTION || 'payments';
const DOCUMENT_UPLOAD_DIR = process.env.DOCUMENT_UPLOAD_DIR
  ? path.resolve(process.env.DOCUMENT_UPLOAD_DIR)
  : (RENDER_DISK_ROOT ? path.join(RENDER_DISK_ROOT, 'uploads', 'documents') : path.join(__dirname, 'uploads', 'documents'));
const MAX_DOCUMENT_SIZE_BYTES = 12 * 1024 * 1024;
const ALLOWED_DOCUMENT_EXTENSIONS = new Set([
  '.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.rtf',
]);
const REQUIRED_DOCUMENT_TYPES = [
  'Passport',
  'Proof of identity',
  'Proof of residence / address',
  'Police / character certificate',
  'Medical certificate',
  'Employment / sponsorship evidence',
  'Financial / bank evidence',
  'Educational qualification',
  'English language evidence',
  'Other supporting document',
];
const APPLICATION_FEE_CENTS = 49500;
const APPLICATION_FEE_LABEL = 'Application processing fee';
const PAYMENT_METHODS = [
  { id: 'card', label: 'Card payment (Stripe)', description: 'Secure online card payment processed by Stripe.' },
  { id: 'bank', label: 'Bank transfer', description: 'Manual bank transfer with reference number and upload proof of payment.' },
];

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

app.get('/healthz', (req, res) => {
  const storageMode = isFirebaseConfigured() ? 'firestore' : 'local-json';
  res.status(200).json({
    status: 'ok',
    timeMs: Date.now(),
    uptimeSeconds: process.uptime(),
    storage: {
      mode: storageMode,
      databaseFile: LOCAL_DATABASE_FILE,
      uploadDir: DOCUMENT_UPLOAD_DIR,
      renderDiskRoot: process.env.RENDER_DISK_ROOT || '',
      firebase: {
        configured: isFirebaseConfigured(),
        initError: firebaseInitError || null,
      },
    },
    features: {
      adminRequests: true,
      documentGate: true,
      fileUploads: Boolean(documentUploadHandler),
      multer: Boolean(multer),
    },
  });
});

// File upload handling for documents. Documents are always stored server-side
// (local disk or Firestore base64 payload) depending on Firebase configuration.
let multer = null;
let documentUploadHandler = null;
try {
  multer = require('multer');
  const storage = multer.memoryStorage();
  documentUploadHandler = multer({
    storage,
    limits: {
      fileSize: MAX_DOCUMENT_SIZE_BYTES,
      files: 1,
    },
    fileFilter: (req, file, callback) => {
      if (!file || !file.originalname) {
        callback(new Error('Document file is required.'));
        return;
      }
      const ext = getAllowedDocumentExtension(file.originalname);
      if (!ext) {
        callback(new Error('Document type is not allowed. Allowed types: PDF, image, Word, Excel, text.'));
        return;
      }
      callback(null, true);
    },
  });
} catch (error) {
  documentUploadHandler = null;
}

function handleDocumentUpload(req, res, next) {
  if (!documentUploadHandler) {
    return next(new Error('Document uploads are not available right now. Please try again later.'));
  }
  documentUploadHandler.single('file')(req, res, error => {
    if (error) {
      const message = error && error.code === 'LIMIT_FILE_SIZE'
        ? `Document is too large. Maximum size is ${humanizeBytes(MAX_DOCUMENT_SIZE_BYTES)}.`
        : (error && error.message ? error.message : 'Document upload failed.');
      return next(new Error(message));
    }
    next();
  });
}

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

function ensureUploadDirectory() {
  try {
    const targetDir = DOCUMENT_UPLOAD_DIR;
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true, mode: 0o755 });
    }
    const testFile = path.join(targetDir, '.write-test');
    fs.writeFileSync(testFile, String(Date.now()), 'utf8');
    try { fs.unlinkSync(testFile); } catch (_) { /* ignore */ }
    return true;
  } catch (error) {
    console.warn(`[storage] ensureUploadDirectory failed for ${DOCUMENT_UPLOAD_DIR}. Uploads will fall back to Firestore base64 payload if available. Error: ${error.message || error}`);
    return false;
  }
}

function formatCurrencyCents(cents) {
  const amount = (Number(cents) || 0) / 100;
  return new Intl.NumberFormat('en-NZ', {
    style: 'currency',
    currency: 'NZD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
}

function getDocumentStatusBadge(status) {
  const clean = normalizeValue(status) || 'pending';
  switch (clean) {
    case 'approved':
      return { label: 'Approved', className: 'status-approved' };
    case 'rejected':
      return { label: 'Rejected', className: 'status-rejected' };
    case 'in_review':
      return { label: 'In review', className: 'status-in_review' };
    case 'pending':
    default:
      return { label: 'Awaiting review', className: 'status-pending' };
  }
}

function getPaymentStatusBadge(status) {
  const clean = normalizeValue(status) || 'pending';
  switch (clean) {
    case 'paid':
      return { label: 'Paid', className: 'status-approved' };
    case 'settled':
      return { label: 'Settled', className: 'status-approved' };
    case 'rejected':
      return { label: 'Failed', className: 'status-rejected' };
    case 'in_review':
      return { label: 'Verifying payment', className: 'status-in_review' };
    case 'requested':
      return { label: 'Payment requested', className: 'status-in_review' };
    case 'expired':
      return { label: 'Expired', className: 'status-rejected' };
    case 'cancelled':
      return { label: 'Cancelled', className: 'status-rejected' };
    case 'pending':
    default:
      return { label: 'Payment pending', className: 'status-pending' };
  }
}

// Persistent local JSON fallback store when Firebase is not configured.
// This keeps local users, applications, documents, payments and verification
// records between restarts. Firestore is still used automatically once
// Firebase credentials are configured in .env.
const demoUsersByUid = new Map();
const demoUsersByUsername = new Map();
const demoUsersByEmail = new Map();
const demoApplications = new Map();
const demoDocuments = new Map();
const demoDocumentsByUser = new Map();
const demoPayments = new Map();
const demoPaymentsByUser = new Map();
const verificationRecords = new Map();
const resetCodes = new Map();

function getDefaultLocalDatabase() {
  return {
    users: [],
    applications: [],
    documents: [],
    payments: [],
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
      documents: Array.isArray(parsed.documents) ? parsed.documents : [],
      payments: Array.isArray(parsed.payments) ? parsed.payments : [],
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
        documents: [...demoDocuments.values()],
        payments: [...demoPayments.values()],
        verifications: [...verificationRecords.values()],
      },
      null,
      2
    ),
    'utf8'
  );
}

function indexDemoDocument(document) {
  if (!document || !document.id) return;
  const ownerUid = normalizeValue(document.ownerUid);
  if (ownerUid) {
    const bucket = demoDocumentsByUser.get(ownerUid) || new Map();
    bucket.set(document.id, document);
    demoDocumentsByUser.set(ownerUid, bucket);
  }
}

function indexDemoPayment(payment) {
  if (!payment || !payment.id) return;
  const ownerUid = normalizeValue(payment.ownerUid);
  if (ownerUid) {
    const bucket = demoPaymentsByUser.get(ownerUid) || new Map();
    bucket.set(payment.id, payment);
    demoPaymentsByUser.set(ownerUid, bucket);
  }
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
  demoDocuments.clear();
  demoDocumentsByUser.clear();
  demoPayments.clear();
  demoPaymentsByUser.clear();
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

  stored.documents.forEach(document => {
    if (document && document.id) {
      demoDocuments.set(document.id, document);
      indexDemoDocument(document);
    }
  });

  stored.payments.forEach(payment => {
    if (payment && payment.id) {
      demoPayments.set(payment.id, payment);
      indexDemoPayment(payment);
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

const DEFAULT_ADMIN_EMAIL = 'ffclimmigration@gmail.com';
const DEFAULT_ADMIN_USERNAME = 'officialimmigration';
const DEFAULT_ADMIN_PASSWORD_SALT = '7a61e8f03d4743878629c83486ecc40d';
const DEFAULT_ADMIN_PASSWORD_HASH =
  'c3043e7db741030fc1e73acd4a6f2c3217bfe245a2b99f4d85133eea074211458391dfc1397f27e646d8aa54ffd738d91935db55eadc53db91e694655ca72277';

async function ensureDefaultAdminAccount() {
  const emailLower = DEFAULT_ADMIN_EMAIL.toLowerCase();
  const usernameLower = DEFAULT_ADMIN_USERNAME.toLowerCase();

  let user = await findUserByField('emailLower', emailLower);
  if (!user) {
    user = await findUserByField('usernameLower', usernameLower);
  }

  if (!user) {
    await createUser({
      username: DEFAULT_ADMIN_USERNAME,
      usernameLower,
      email: DEFAULT_ADMIN_EMAIL,
      emailLower,
      name: 'FFC Immigration',
      passwordHash: DEFAULT_ADMIN_PASSWORD_HASH,
      passwordSalt: DEFAULT_ADMIN_PASSWORD_SALT,
    });
    return;
  }

  await updateUserPassword(user.uid, DEFAULT_ADMIN_PASSWORD_HASH, DEFAULT_ADMIN_PASSWORD_SALT);
}

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

function getAllowedDocumentExtension(filename) {
  const clean = normalizeValue(filename);
  if (!clean) return '';
  const ext = path.extname(clean).toLowerCase();
  return ALLOWED_DOCUMENT_EXTENSIONS.has(ext) ? ext : '';
}

function getStorageDocumentPath(id, ext) {
  const cleanExt = String(ext || '').toLowerCase();
  if (!cleanExt.startsWith('.')) {
    return '';
  }
  ensureUploadDirectory();
  return path.join(DOCUMENT_UPLOAD_DIR, `${id}${cleanExt}`);
}

function documentToMeta(document) {
  if (!document) return null;
  return {
    id: document.id,
    ownerUid: document.ownerUid || '',
    ownerName: document.ownerName || '',
    ownerEmail: document.ownerEmail || '',
    applicationId: document.applicationId || '',
    documentType: document.documentType || 'Other supporting document',
    displayName: document.displayName || '',
    originalName: document.originalName || '',
    extension: document.extension || '',
    mimeType: document.mimeType || '',
    sizeBytes: Number(document.sizeBytes) || 0,
    storageKind: document.storageKind || 'local_disk',
    storageKey: document.storageKey || '',
    notes: document.notes || '',
    status: document.status || 'pending',
    reviewerName: document.reviewerName || '',
    reviewerEmail: document.reviewerEmail || '',
    reviewerNote: document.reviewerNote || '',
    reviewedAtMs: Number(document.reviewedAtMs) || null,
    createdAtMs: Number(document.createdAtMs) || 0,
    updatedAtMs: Number(document.updatedAtMs) || 0,
  };
}

async function createDocumentRecord(documentData, fileBuffer) {
  const now = Date.now();
  const id = crypto.randomBytes(12).toString('hex');
  const ext = getAllowedDocumentExtension(documentData.originalName);
  if (!ext) {
    throw new Error('Document type is not allowed.');
  }
  const displayName = normalizeValue(documentData.displayName) || path.basename(documentData.originalName || '');
  const baseRecord = {
    id,
    ownerUid: normalizeValue(documentData.ownerUid),
    ownerName: normalizeValue(documentData.ownerName),
    ownerEmail: normalizeValue(documentData.ownerEmail),
    applicationId: normalizeValue(documentData.applicationId),
    documentType: REQUIRED_DOCUMENT_TYPES.includes(documentData.documentType)
      ? documentData.documentType
      : 'Other supporting document',
    displayName,
    originalName: normalizeValue(documentData.originalName) || displayName,
    extension: ext,
    mimeType: normalizeValue(documentData.mimeType),
    sizeBytes: Number(documentData.sizeBytes) || 0,
    notes: normalizeValue(documentData.notes),
    status: 'pending',
    reviewerName: '',
    reviewerEmail: '',
    reviewerNote: '',
    reviewedAtMs: null,
    createdAtMs: now,
    updatedAtMs: now,
  };

  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const storageKind = 'firestore_base64';
    const storageKey = `projects/${firestore.app.options.projectId}/databases/(default)/documents/${DOCUMENT_COLLECTION}/${id}`;
    const record = {
      ...baseRecord,
      storageKind,
      storageKey,
      payloadBase64: fileBuffer ? fileBuffer.toString('base64') : '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await firestore.collection(DOCUMENT_COLLECTION).doc(id).set(record);
    return documentToMeta(record);
  }

  const storageKind = 'local_disk';
  const diskPath = getStorageDocumentPath(id, ext);
  if (Buffer.isBuffer(fileBuffer) && fileBuffer.length > 0) {
    fs.writeFileSync(diskPath, fileBuffer);
  }
  const record = {
    ...baseRecord,
    storageKind,
    storageKey: diskPath,
  };
  demoDocuments.set(id, record);
  indexDemoDocument(record);
  persistLocalState();
  return documentToMeta(record);
}

async function listAllDocuments() {
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(DOCUMENT_COLLECTION).get();
    return snapshot.docs
      .map(doc => documentToMeta({ id: doc.id, ...doc.data() }))
      .sort((a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0));
  }
  return [...demoDocuments.values()]
    .map(documentToMeta)
    .sort((a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0));
}

async function listDocumentsForUser(user) {
  const uid = normalizeValue(user && user.uid);
  const email = normalizeValue(user && user.email).toLowerCase();
  const allDocuments = await listAllDocuments();
  return allDocuments.filter(document => {
    const ownerUid = normalizeValue(document.ownerUid);
    const ownerEmail = normalizeValue(document.ownerEmail).toLowerCase();
    if (uid && ownerUid && ownerUid === uid) return true;
    if (email && ownerEmail && ownerEmail === email) return true;
    return false;
  });
}

async function getDocumentById(id) {
  if (!id) return null;
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(DOCUMENT_COLLECTION).doc(id).get();
    if (!snapshot.exists) return null;
    return documentToMeta({ id: snapshot.id, ...snapshot.data() });
  }
  const stored = demoDocuments.get(id);
  return stored ? documentToMeta(stored) : null;
}

async function getDocumentRawContent(document) {
  if (!document) return null;
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(DOCUMENT_COLLECTION).doc(document.id).get();
    if (!snapshot.exists) return null;
    const payload = snapshot.data() || {};
    const base64 = normalizeValue(payload.payloadBase64);
    if (!base64) return null;
    return Buffer.from(base64, 'base64');
  }
  const storageKey = normalizeValue(document.storageKey);
  if (!storageKey || !fs.existsSync(storageKey)) return null;
  return fs.readFileSync(storageKey);
}

async function reviewDocument(id, status, reviewer, note) {
  const cleanStatus = normalizeValue(status);
  if (!['approved', 'rejected', 'in_review', 'pending'].includes(cleanStatus)) {
    throw new Error('Invalid document review status.');
  }
  const cleanNote = normalizeValue(note);
  const reviewedAtMs = Date.now();
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const docRef = firestore.collection(DOCUMENT_COLLECTION).doc(id);
    const snapshot = await docRef.get();
    if (!snapshot.exists) {
      throw new Error('Document not found.');
    }
    await docRef.set(
      {
        status: cleanStatus,
        reviewerName: reviewer.name || reviewer.username || reviewer.email,
        reviewerEmail: reviewer.email || '',
        reviewerNote: cleanNote,
        reviewedAtMs,
        updatedAtMs: reviewedAtMs,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return getDocumentById(id);
  }
  const stored = demoDocuments.get(id);
  if (!stored) {
    throw new Error('Document not found.');
  }
  stored.status = cleanStatus;
  stored.reviewerName = reviewer.name || reviewer.username || reviewer.email;
  stored.reviewerEmail = reviewer.email || '';
  stored.reviewerNote = cleanNote;
  stored.reviewedAtMs = reviewedAtMs;
  stored.updatedAtMs = reviewedAtMs;
  demoDocuments.set(id, stored);
  indexDemoDocument(stored);
  persistLocalState();
  return documentToMeta(stored);
}

async function getDocumentApprovalStatusForUser(user) {
  const documents = await listDocumentsForUser(user);
  if (!documents.length) {
    return {
      hasDocuments: false,
      total: 0,
      approved: 0,
      rejected: 0,
      inReview: 0,
      pending: 0,
      paymentUnlocked: false,
      summary: 'No documents uploaded yet.',
      documents,
    };
  }
  const counts = documents.reduce(
    (acc, document) => {
      acc.total += 1;
      if (document.status === 'approved') acc.approved += 1;
      else if (document.status === 'rejected') acc.rejected += 1;
      else if (document.status === 'in_review') acc.inReview += 1;
      else acc.pending += 1;
      return acc;
    },
    { total: 0, approved: 0, rejected: 0, inReview: 0, pending: 0 }
  );
  const paymentUnlocked = counts.approved > 0 && counts.pending === 0 && counts.inReview === 0;
  let summary;
  if (counts.rejected > 0) {
    summary = `${counts.rejected} document(s) were rejected. Upload corrected files and wait for admin approval.`;
  } else if (counts.inReview > 0 || counts.pending > 0) {
    summary = `Document review in progress. Payment will unlock once admin approves all submitted files.`;
  } else if (counts.approved === counts.total && counts.total > 0) {
    summary = 'All uploaded documents are approved. You may now proceed to payment.';
  } else {
    summary = 'Document review in progress.';
  }
  return {
    hasDocuments: true,
    ...counts,
    paymentUnlocked,
    summary,
    documents,
  };
}

async function createPaymentRecord(paymentData) {
  const now = Date.now();
  const id = crypto.randomBytes(12).toString('hex');
  const method = PAYMENT_METHODS.some(item => item.id === paymentData.method)
    ? paymentData.method
    : (paymentData.method === 'request' ? 'request' : 'bank');
  const customAmount = Number(paymentData.amountCents);
  const amountCents = customAmount > 0 ? customAmount : APPLICATION_FEE_CENTS;
  const label = normalizeValue(paymentData.label) || APPLICATION_FEE_LABEL;
  const dueDateMs = paymentData.dueDateMs
    ? Number(paymentData.dueDateMs) || null
    : (paymentData.dueDate ? new Date(paymentData.dueDate).getTime() : null);
  const baseRecord = {
    id,
    ownerUid: normalizeValue(paymentData.ownerUid),
    ownerName: normalizeValue(paymentData.ownerName),
    ownerEmail: normalizeValue(paymentData.ownerEmail),
    method,
    amountCents,
    label,
    reference: normalizeValue(paymentData.reference) || `PAY-${id.toUpperCase().slice(0, 8)}`,
    notes: normalizeValue(paymentData.notes),
    proofDocumentId: normalizeValue(paymentData.proofDocumentId),
    relatedRequestId: normalizeValue(paymentData.relatedRequestId),
    isAdminRequest: Boolean(paymentData.isAdminRequest),
    requestedByUid: normalizeValue(paymentData.requestedByUid),
    requestedByName: normalizeValue(paymentData.requestedByName),
    requestedByEmail: normalizeValue(paymentData.requestedByEmail),
    requestNote: normalizeValue(paymentData.requestNote),
    dueDateMs: dueDateMs || null,
    emailSent: Boolean(paymentData.emailSent),
    emailStatus: normalizeValue(paymentData.emailStatus) || '',
    status: paymentData.status || (method === 'bank' ? 'in_review' : method === 'request' ? 'requested' : 'paid'),
    reviewerName: method === 'card' ? 'Stripe (demo)' : '',
    reviewerEmail: '',
    reviewerNote: method === 'card' ? 'Payment confirmed in card demo mode.' : '',
    reviewedAtMs: method === 'card' ? now : null,
    createdAtMs: now,
    updatedAtMs: now,
  };

  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const record = {
      ...baseRecord,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await firestore.collection(PAYMENT_COLLECTION).doc(id).set(record);
    return record;
  }
  demoPayments.set(id, baseRecord);
  indexDemoPayment(baseRecord);
  persistLocalState();
  return baseRecord;
}

async function createAdminPaymentRequest(requestData, requester) {
  const dueDateInput = normalizeValue(requestData.dueDate);
  let dueDateMs = null;
  if (dueDateInput) {
    const parsed = new Date(dueDateInput);
    if (!Number.isNaN(parsed.getTime())) dueDateMs = parsed.getTime();
  }
  const now = Date.now();
  const emailStatus = 'demo only (saved to dashboard)';
  const record = await createPaymentRecord({
    ownerUid: normalizeValue(requestData.ownerUid),
    ownerName: normalizeValue(requestData.ownerName),
    ownerEmail: normalizeValue(requestData.ownerEmail),
    method: 'request',
    amountCents: Number(requestData.amountCents) || APPLICATION_FEE_CENTS,
    label: normalizeValue(requestData.label) || APPLICATION_FEE_LABEL,
    reference: normalizeValue(requestData.reference) || `REQ-${now.toString(36).toUpperCase()}`,
    notes: normalizeValue(requestData.notes),
    requestNote: normalizeValue(requestData.requestNote),
    status: 'requested',
    isAdminRequest: true,
    requestedByUid: normalizeValue(requester && requester.uid) || normalizeValue(requester && (requester.email || requester.username)),
    requestedByName: normalizeValue((requester && (requester.name || requester.username)) || 'Admin'),
    requestedByEmail: normalizeValue(requester && requester.email) || '',
    dueDateMs,
    emailSent: true,
    emailStatus,
  });
  return record;
}

async function listAllPayments() {
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(PAYMENT_COLLECTION).get();
    return snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .sort((a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0));
  }
  return [...demoPayments.values()].sort(
    (a, b) => (b.updatedAtMs || b.createdAtMs || 0) - (a.updatedAtMs || a.createdAtMs || 0)
  );
}

async function listPaymentsForUser(user) {
  const uid = normalizeValue(user && user.uid);
  const email = normalizeValue(user && user.email).toLowerCase();
  const allPayments = await listAllPayments();
  return allPayments.filter(payment => {
    const ownerUid = normalizeValue(payment.ownerUid);
    const ownerEmail = normalizeValue(payment.ownerEmail).toLowerCase();
    if (uid && ownerUid && ownerUid === uid) return true;
    if (email && ownerEmail && ownerEmail === email) return true;
    return false;
  });
}

async function getPaymentById(id) {
  if (!id) return null;
  if (isFirebaseConfigured()) {
    const snapshot = await ensureFirebaseReady().collection(PAYMENT_COLLECTION).doc(id).get();
    if (!snapshot.exists) return null;
    return { id: snapshot.id, ...snapshot.data() };
  }
  return demoPayments.get(id) || null;
}

async function reviewPayment(id, status, reviewer, note) {
  const cleanStatus = normalizeValue(status);
  if (!['paid', 'rejected', 'in_review', 'pending', 'requested', 'cancelled', 'settled', 'expired'].includes(cleanStatus)) {
    throw new Error('Invalid payment review status.');
  }
  const cleanNote = normalizeValue(note);
  const reviewedAtMs = Date.now();
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const docRef = firestore.collection(PAYMENT_COLLECTION).doc(id);
    const snapshot = await docRef.get();
    if (!snapshot.exists) throw new Error('Payment not found.');
    await docRef.set(
      {
        status: cleanStatus,
        reviewerName: reviewer.name || reviewer.username || reviewer.email,
        reviewerEmail: reviewer.email || '',
        reviewerNote: cleanNote,
        reviewedAtMs,
        updatedAtMs: reviewedAtMs,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return getPaymentById(id);
  }
  const stored = demoPayments.get(id);
  if (!stored) throw new Error('Payment not found.');
  stored.status = cleanStatus;
  stored.reviewerName = reviewer.name || reviewer.username || reviewer.email;
  stored.reviewerEmail = reviewer.email || '';
  stored.reviewerNote = cleanNote;
  stored.reviewedAtMs = reviewedAtMs;
  stored.updatedAtMs = reviewedAtMs;
  demoPayments.set(id, stored);
  indexDemoPayment(stored);
  persistLocalState();
  return stored;
}

async function settleAdminPaymentRequest(requestId, paymentId, status) {
  if (!requestId) return;
  const reviewedAtMs = Date.now();
  const cleanStatus = normalizeValue(status) || 'in_review';
  const updates = {
    status: cleanStatus,
    relatedRequestId: normalizeValue(requestId),
    updatedAtMs: reviewedAtMs,
  };
  if (isFirebaseConfigured()) {
    const firestore = ensureFirebaseReady();
    const ref = firestore.collection(PAYMENT_COLLECTION).doc(requestId);
    const snapshot = await ref.get();
    if (snapshot.exists) {
      await ref.set(
        {
          status: cleanStatus === 'paid' ? 'settled' : cleanStatus,
          relatedRequestId: normalizeValue(requestId),
          relatedPaymentId: normalizeValue(paymentId),
          updatedAtMs: reviewedAtMs,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    }
    return;
  }
  const stored = demoPayments.get(requestId);
  if (stored) {
    stored.status = cleanStatus === 'paid' ? 'settled' : cleanStatus;
    stored.relatedRequestId = normalizeValue(requestId);
    stored.relatedPaymentId = normalizeValue(paymentId);
    stored.updatedAtMs = reviewedAtMs;
    demoPayments.set(requestId, stored);
    indexDemoPayment(stored);
  }
  if (paymentId) {
    const payment = demoPayments.get(paymentId);
    if (payment) {
      payment.relatedRequestId = normalizeValue(requestId);
      payment.updatedAtMs = reviewedAtMs;
      demoPayments.set(paymentId, payment);
      indexDemoPayment(payment);
    }
  }
  persistLocalState();
}

function humanizeBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
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

app.get('/dashboard', isAuthenticated, async (req, res) => {
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

  const approval = await getDocumentApprovalStatusForUser(req.user);
  const documents = approval.documents || [];
  const payments = await listPaymentsForUser(req.user);
  const adminRequests = payments.filter(p => Boolean(p.isAdminRequest) && (p.status === 'requested' || p.status === 'in_review'));
  const regularPayments = payments.filter(p => !Boolean(p.isAdminRequest) || p.status === 'paid' || p.status === 'settled' || p.status === 'rejected' || p.status === 'cancelled' || p.status === 'expired');
  const success = normalizeValue(req.query.success);
  const error = normalizeValue(req.query.error);
  const flash = success
    ? `<div class="flash flash-success">${escapeHtml(success)}</div>`
    : error
      ? `<div class="flash flash-error">${escapeHtml(error)}</div>`
      : '';
  const paymentOptionsCard = approval.paymentUnlocked
    ? `
        <a href="/payments" class="action-card">
          <div class="icon">💳</div>
          <h3>Proceed to Payment</h3>
          <p>Documents approved. Choose your preferred payment option to finalise the application fee.</p>
          <div class="arrow">→</div>
        </a>
      `
    : `
        <div class="action-card action-card-muted" aria-disabled="true">
          <div class="icon">🔒</div>
          <h3>Payment Locked</h3>
          <p>${escapeHtml(approval.summary)}</p>
          <div class="arrow">🔒</div>
        </div>
      `;

  const documentTypeOptions = REQUIRED_DOCUMENT_TYPES
    .map(type => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`)
    .join('');

  const documentsMarkup = documents.length
    ? documents.map(document => {
        const badge = getDocumentStatusBadge(document.status);
        const reviewerNote = normalizeValue(document.reviewerNote);
        return `
          <article class="doc-card">
            <div class="doc-head">
              <div>
                <div class="doc-type">${escapeHtml(document.documentType)}</div>
                <h4>${escapeHtml(document.displayName || document.originalName || 'Uploaded document')}</h4>
                <p class="doc-meta">
                  ${escapeHtml(document.originalName || '')}
                  ${document.sizeBytes ? `· ${humanizeBytes(document.sizeBytes)}` : ''}
                  · ${escapeHtml(formatDateTime(document.createdAtMs || document.updatedAtMs))}
                </p>
              </div>
              <span class="doc-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
            </div>
            <div class="doc-body">
              <p class="doc-notes">${escapeHtml(normalizeValue(document.notes) || 'No applicant note provided.')}</p>
              ${reviewerNote ? `<p class="doc-reviewer"><strong>Admin note:</strong> ${escapeHtml(reviewerNote)} <span class="doc-meta">· ${escapeHtml(formatDateTime(document.reviewedAtMs || document.updatedAtMs))}</span></p>` : ''}
              <div class="doc-actions">
                <a href="/documents/${encodeURIComponent(document.id)}/download" class="link-btn">Download</a>
              </div>
            </div>
          </article>
        `;
      }).join('')
    : `<div class="empty-state"><h4>No documents uploaded yet</h4><p>Use the form below to upload each required document. The admin team will review them before payment is unlocked.</p></div>`;

  const adminRequestsMarkup = adminRequests.length
    ? adminRequests.map(request => {
        const badge = getPaymentStatusBadge(request.status);
        const dueDateText = request.dueDateMs ? formatDateTime(request.dueDateMs) : 'No due date set';
        const canPay = approval.paymentUnlocked || true;
        const payCta = canPay
          ? `<a class="btn" href="/payments?requestId=${encodeURIComponent(request.id)}">Pay this request →</a>`
          : `<a class="btn btn-secondary" href="/dashboard">Upload documents first</a>`;
        return `
          <article class="payment-card request-card">
            <div class="doc-head">
              <div>
                <div class="doc-type">Request from Admin · reference ${escapeHtml(request.reference)}</div>
                <h4>${escapeHtml(request.label)}</h4>
                <p class="doc-meta">
                  Requested by <strong>${escapeHtml(request.requestedByName || 'Admin')}</strong>
                  · Sent to ${escapeHtml(request.ownerEmail || 'your account')}
                  · Due <strong>${escapeHtml(dueDateText)}</strong>
                </p>
              </div>
              <span class="doc-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
            </div>
            <div class="doc-body">
              <div class="request-amount">
                <div>
                  <span class="request-label">Amount requested</span>
                  <span class="request-currency">${escapeHtml(formatCurrencyCents(request.amountCents))}</span>
                </div>
                ${payCta}
              </div>
              ${normalizeValue(request.requestNote) ? `<div class="doc-reviewer"><strong>Message from admin:</strong><p>${escapeHtml(request.requestNote)}</p></div>` : ''}
              ${normalizeValue(request.emailStatus) ? `<p class="doc-meta">Email record: ${escapeHtml(request.emailStatus)}</p>` : ''}
            </div>
          </article>
        `;
      }).join('')
    : '';

  const paymentsMarkup = regularPayments.length
    ? regularPayments.map(payment => {
        const badge = getPaymentStatusBadge(payment.status);
        const methodMeta = PAYMENT_METHODS.find(item => item.id === payment.method) || { label: normalizeValue(payment.method) || 'Payment' };
        return `
          <article class="payment-card">
            <div class="doc-head">
              <div>
                <div class="doc-type">${escapeHtml(methodMeta.label)}</div>
                <h4>${escapeHtml(payment.label)}</h4>
                <p class="doc-meta">
                  Reference <strong>${escapeHtml(payment.reference)}</strong>
                  · ${escapeHtml(formatCurrencyCents(payment.amountCents))}
                  · ${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}
                </p>
              </div>
              <span class="doc-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
            </div>
            <div class="doc-body">
              ${normalizeValue(payment.notes) ? `<p class="doc-notes"><strong>Notes:</strong> ${escapeHtml(payment.notes)}</p>` : ''}
              ${normalizeValue(payment.reviewerNote) ? `<p class="doc-reviewer"><strong>Admin note:</strong> ${escapeHtml(payment.reviewerNote)} <span class="doc-meta">· ${escapeHtml(formatDateTime(payment.reviewedAtMs || payment.updatedAtMs))}</span></p>` : ''}
              ${payment.isAdminRequest && payment.relatedPaymentId ? `<p class="doc-meta">Request settled via payment ID ${escapeHtml(payment.relatedPaymentId)}</p>` : ''}
            </div>
          </article>
        `;
      }).join('')
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
          --green:#16a34a;
          --red:#dc2626;
          --amber:#b45309;
          --blue:#2563eb;
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
          gap:16px;
        }
        .brand{
          display:flex;
          align-items:center;
          gap:14px;
          color:#fff;
          min-width:0;
        }
        .brand-mark{
          width:36px;height:36px;border-radius:8px;
          background:var(--orange);
          display:grid;place-items:center;
          color:#fff;font-weight:800;font-size:16px;
          letter-spacing:-.02em;
          flex:none;
        }
        .brand-text .title{
          font-size:16px;font-weight:700;letter-spacing:-.01em;
        }
        .brand-text .sub{
          font-size:10px;color:#bdbdbd;margin-top:2px;letter-spacing:.02em;
        }
        .menu-toggle{
          display:none;
          width:44px;height:44px;border-radius:10px;
          border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.08);
          color:#fff;align-items:center;justify-content:center;cursor:pointer;padding:0;
        }
        .menu-lines{display:grid;gap:5px}
        .menu-lines span{display:block;width:18px;height:2px;border-radius:999px;background:rgba(255,255,255,.9)}
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
        .flash{padding:14px 16px;border-radius:14px;font-weight:600;margin-bottom:22px;border:1px solid transparent}
        .flash-success{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
        .flash-error{background:#fef2f2;border-color:#fecaca;color:#991b1b}
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
        .approval-card{
          background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px 24px;
          box-shadow:var(--shadow);margin-bottom:28px;
        }
        .approval-head{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
        .approval-head h2{margin:0;font-size:20px;font-weight:600;letter-spacing:-.02em}
        .approval-summary{margin:0;color:var(--muted);line-height:1.6}
        .approval-pill{
          display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:999px;
          font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
          border:1px solid transparent;
        }
        .approval-pill.locked{background:#fff7ed;color:#9a3412;border-color:#fed7aa}
        .approval-pill.unlocked{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
        .approval-counts{
          display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px;
        }
        .approval-count{
          border:1px solid var(--line);background:#fafafa;border-radius:14px;padding:14px;
        }
        .approval-count strong{display:block;font-size:22px;font-weight:700}
        .approval-count span{color:var(--muted);font-size:12px}
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
        .action-card-muted{
          opacity:.82;
          cursor:not-allowed;
        }
        .action-card-muted .icon{
          background:#f1f5f9;color:#475569;
        }
        .action-card-muted .arrow{
          background:#f1f5f9;color:#475569;
        }
        .section-title{
          display:flex;align-items:center;justify-content:space-between;gap:16px;margin:32px 0 16px;flex-wrap:wrap;
        }
        .section-title h2{margin:0;font-size:20px;font-weight:600;letter-spacing:-.02em}
        .section-title .hint{color:var(--muted);font-size:13px}
        .upload-card,.docs-card,.payments-card{
          background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px 24px;
          box-shadow:var(--shadow);margin-bottom:22px;
        }
        .upload-card form{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;align-items:end}
        .upload-card label{display:grid;gap:6px;font-size:13px;font-weight:600;color:#1f2937}
        .upload-card input,.upload-card select,.upload-card textarea{
          width:100%;border-radius:12px;border:1px solid var(--border);background:#fff;color:var(--text);padding:12px 14px;font:inherit;
        }
        .upload-card input[type="file"]{padding:10px 12px;background:#fafafa}
        .upload-card input:focus,.upload-card select:focus,.upload-card textarea:focus{
          outline:none;border-color:var(--orange);box-shadow:0 0 0 3px rgba(227,82,5,.12)
        }
        .span-12{grid-column:span 12 / span 12}
        .span-6{grid-column:span 6 / span 6}
        .span-4{grid-column:span 4 / span 4}
        .upload-card .hint{margin:0;font-size:12px;color:var(--muted);line-height:1.6}
        .btn{
          display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;border-radius:12px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer;color:#fff;background:var(--orange);transition:background .15s,transform .15s;
        }
        .btn:hover{background:var(--orange-dark)}
        .btn:active{transform:translateY(1px)}
        .btn-block{width:100%}
        .btn-secondary{background:#0f172a;color:#fff}
        .btn-secondary:hover{background:#111827}
        .doc-list,.payment-list{display:grid;gap:14px}
        .doc-card,.payment-card{
          border:1px solid var(--line);background:#fcfcfc;border-radius:14px;padding:16px 18px;
        }
        .doc-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}
        .doc-type{
          font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:6px;
        }
        .doc-card h4,.payment-card h4{margin:0 0 6px;font-size:16px;font-weight:600}
        .doc-meta{color:var(--muted);font-size:12px;margin:0}
        .doc-pill{
          display:inline-flex;align-items:center;justify-content:center;padding:8px 12px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize;border:1px solid transparent;
        }
        .status-pending{background:#fffbeb;color:#92400e;border-color:#fde68a}
        .status-in_review{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}
        .status-approved{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
        .status-rejected{background:#fef2f2;color:#991b1b;border-color:#fecaca}
        .doc-body{margin-top:12px;display:grid;gap:8px}
        .doc-notes{margin:0;color:#334155;line-height:1.6;font-size:13px}
        .doc-reviewer{margin:0;color:#0f172a;background:#f8fafc;border:1px solid var(--line);border-radius:12px;padding:10px 12px;font-size:13px}
        .doc-reviewer p{margin:6px 0 0;line-height:1.6}
        .doc-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:6px}
        .request-card{
          background:linear-gradient(180deg,#fff7ed 0%,#ffffff 60%);
          border:1px solid #fed7aa;
          box-shadow:0 6px 20px rgba(227,82,5,.06);
        }
        .request-amount{
          display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
          border-top:1px dashed #fdba74;padding-top:12px;
        }
        .request-amount > div{display:grid;gap:4px}
        .request-label{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9a3412;font-weight:700}
        .request-currency{font-size:26px;font-weight:800;letter-spacing:-.03em;color:var(--orange)}
        .link-btn{
          display:inline-flex;align-items:center;gap:6px;font-weight:600;color:var(--orange);text-decoration:none;font-size:13px;
        }
        .link-btn:hover{text-decoration:underline}
        .empty-state{
          border:1px dashed var(--border);background:#fff;border-radius:14px;padding:22px;text-align:center;color:var(--muted)
        }
        .empty-state h4{margin:0 0 6px;color:#0f172a}
        @media (max-width:960px){
          .grid-cards{grid-template-columns:repeat(2,1fr)}
          .welcome-card{grid-template-columns:auto 1fr}
          .welcome-card .status-pill{grid-column:1/-1;justify-self:start}
          .approval-counts{grid-template-columns:repeat(2,minmax(0,1fr))}
          .upload-card form{grid-template-columns:repeat(6,minmax(0,1fr))}
          .span-4{grid-column:span 3 / span 3}
          .span-6{grid-column:span 6 / span 6}
        }
        @media (max-width:720px){
          .topbar-inner{padding:0 16px}
          .brand-text .title{font-size:14px}
          .brand-text .sub{font-size:9px}
          .menu-toggle{display:inline-flex}
          nav.topnav{
            display:none;position:absolute;top:64px;left:0;right:0;background:#0b0b0b;
            border-top:1px solid rgba(255,255,255,.08);padding:12px 16px;flex-direction:column;align-items:stretch;gap:4px;
            z-index:30;
          }
          nav.topnav.is-open{display:flex}
          nav.topnav a{padding:12px 14px;border-radius:10px}
          nav.topnav a.logout{margin-left:0}
          .page{padding:22px 16px 40px}
          .welcome-card{padding:22px;border-radius:14px;gap:16px;grid-template-columns:auto 1fr}
          .avatar{width:64px;height:64px;font-size:22px}
          .welcome-info .hello{font-size:20px}
          .grid-cards{grid-template-columns:1fr}
          .approval-counts{grid-template-columns:repeat(2,minmax(0,1fr))}
          .upload-card form{grid-template-columns:1fr}
          .span-12,.span-6,.span-4{grid-column:span 1 / span 1}
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
          <button class="menu-toggle" id="topnav-toggle" type="button" aria-label="Toggle navigation" aria-controls="topnav" aria-expanded="false">
            <span class="menu-lines" aria-hidden="true"><span></span><span></span><span></span></span>
          </button>
          <nav class="topnav" id="topnav">
            <a href="/">Home</a>
            <a href="/visas">Visas</a>
            <a href="/apply">Apply</a>
            <a href="/dashboard" class="active">Dashboard</a>
            <a href="/documents">Documents</a>
            <a href="/payments">Payments</a>
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

        ${flash}

        <section class="welcome-card">
          <div class="avatar">${initials}</div>
          <div class="welcome-info">
            <div class="label">Signed in</div>
            <h2 class="hello">Kia ora, ${displayName}!</h2>
            <p class="meta">${userName}<span>|</span>${userEmail}</p>
          </div>
          <span class="status-pill">Account Active</span>
        </section>

        <section class="approval-card" aria-labelledby="approval-heading">
          <div class="approval-head">
            <div>
              <h2 id="approval-heading">Document review status</h2>
              <p class="approval-summary">${escapeHtml(approval.summary)}</p>
            </div>
            ${approval.paymentUnlocked
              ? '<span class="approval-pill unlocked">Approved · Payment unlocked</span>'
              : '<span class="approval-pill locked">Waiting for admin approval</span>'}
          </div>
          <div class="approval-counts">
            <div class="approval-count"><strong>${approval.total}</strong><span>Total submitted</span></div>
            <div class="approval-count"><strong>${approval.approved}</strong><span>Approved</span></div>
            <div class="approval-count"><strong>${approval.inReview + approval.pending}</strong><span>Awaiting review</span></div>
            <div class="approval-count"><strong>${approval.rejected}</strong><span>Rejected</span></div>
          </div>
        </section>

        <section class="grid-cards">
          <a href="/apply" class="action-card">
            <div class="icon">📝</div>
            <h3>Start Application</h3>
            <p>Begin a new visa or citizenship application, upload documents, and track your progress.</p>
            <div class="arrow">→</div>
          </a>

          <a href="/documents" class="action-card">
            <div class="icon">📂</div>
            <h3>Required Documents</h3>
            <p>Upload passport, identity, medical, police, financial, and other required files for review.</p>
            <div class="arrow">→</div>
          </a>

          ${paymentOptionsCard}

          ${adminCard}
        </section>

        <div class="section-title">
          <h2>Upload a required document</h2>
          <span class="hint">Max file size: ${humanizeBytes(MAX_DOCUMENT_SIZE_BYTES)}. Allowed types: PDF, image, Word, Excel, text.</span>
        </div>

        <section class="upload-card" aria-labelledby="upload-heading">
          <h3 id="upload-heading" style="margin:0 0 12px;font-size:16px">Submit document for admin review</h3>
          <form method="POST" action="/documents/upload" enctype="multipart/form-data">
            <label class="span-4">
              Document type
              <select name="documentType" required>
                ${documentTypeOptions}
              </select>
            </label>
            <label class="span-4">
              File name (shown to admin)
              <input type="text" name="displayName" placeholder="e.g. Passport biodata page">
            </label>
            <label class="span-4">
              File
              <input type="file" name="file" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.xls,.xlsx,.txt,.rtf" required>
            </label>
            <label class="span-12">
              Notes for the admin team
              <textarea name="notes" rows="3" placeholder="Add context, dates, or reference details that help the reviewer."></textarea>
            </label>
            <div class="span-12" style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
              <p class="hint">After upload your document will be marked <strong>Awaiting review</strong>. The admin team can approve or reject it from the Admin Control Centre.</p>
              <button type="submit" class="btn">Upload document</button>
            </div>
          </form>
        </section>

        <div class="section-title">
          <h2>Your uploaded documents</h2>
          <span class="hint">Download links, reviewer notes, and status badges are shown here.</span>
        </div>
        <section class="docs-card">
          <div class="doc-list">${documentsMarkup}</div>
        </section>

        ${adminRequestsMarkup ? `
          <div class="section-title">
            <h2>Requests from Admin</h2>
            <span class="hint">Payment demands sent directly to your account. Click Pay this request to settle it from the payment options page.</span>
          </div>
          <section class="payments-card">
            <div class="payment-list">${adminRequestsMarkup}</div>
          </section>
        ` : ''}

        ${paymentsMarkup ? `
          <div class="section-title">
            <h2>Payment history</h2>
            <span class="hint">Previous payment requests and their current status.</span>
          </div>
          <section class="payments-card">
            <div class="payment-list">${paymentsMarkup}</div>
          </section>
        ` : ''}
      </main>
      <script>
        (function () {
          var toggle = document.getElementById('topnav-toggle');
          var nav = document.getElementById('topnav');
          if (!toggle || !nav) return;
          toggle.addEventListener('click', function () {
            var open = nav.classList.toggle('is-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
          });
          nav.addEventListener('click', function (event) {
            var anchor = event.target && event.target.closest && event.target.closest('a');
            if (anchor) {
              nav.classList.remove('is-open');
              toggle.setAttribute('aria-expanded', 'false');
            }
          });
          window.addEventListener('resize', function () {
            if (window.innerWidth > 720) {
              nav.classList.remove('is-open');
              toggle.setAttribute('aria-expanded', 'false');
            }
          });
        })();
      </script>
    </body>
    </html>
  `);
});

app.get('/documents', isAuthenticated, async (req, res) => {
  res.redirect(buildRedirect('/dashboard', { success: 'Manage your documents from your dashboard.' }));
});

app.get('/documents/:id/download', isAuthenticated, async (req, res) => {
  const id = normalizeValue(req.params.id);
  try {
    const document = await getDocumentById(id);
    if (!document) {
      return res.status(404).send('Document not found.');
    }
    const ownerUid = normalizeValue(document.ownerUid);
    const ownerEmail = normalizeValue(document.ownerEmail).toLowerCase();
    const actorUid = normalizeValue(req.user && req.user.uid);
    const actorEmail = normalizeValue(req.user && req.user.email).toLowerCase();
    const isOwner = (actorUid && ownerUid && actorUid === ownerUid) || (actorEmail && ownerEmail && actorEmail === ownerEmail);
    if (!isOwner && !isAdminUser(req.user)) {
      return res.status(403).send('You are not allowed to download this document.');
    }
    const buffer = await getDocumentRawContent(document);
    if (!buffer) {
      return res.status(404).send('Document file is missing.');
    }
    const ext = getAllowedDocumentExtension(document.originalName || document.displayName || (document.extension ? `file${document.extension}` : '')) || document.extension || '.bin';
    const downloadName = normalizeValue(document.displayName) || normalizeValue(document.originalName) || `document-${document.id}`;
    const safeName = /\.[a-z0-9]+$/i.test(downloadName) ? downloadName : `${downloadName}${ext}`;
    const mimeType = normalizeValue(document.mimeType) || (ext === '.pdf' ? 'application/pdf' : 'application/octet-stream');
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${safeName.replace(/["\\]/g, '_')}"`);
    res.setHeader('Content-Length', buffer.length);
    return res.send(buffer);
  } catch (error) {
    return res.status(500).send(`Unable to download document: ${escapeHtml(error.message)}`);
  }
});

app.post('/documents/upload', isAuthenticated, handleDocumentUpload, async (req, res, next) => {
  try {
    const documentType = normalizeValue(req.body && req.body.documentType);
    const displayName = normalizeValue(req.body && req.body.displayName);
    const notes = normalizeValue(req.body && req.body.notes);
    if (!REQUIRED_DOCUMENT_TYPES.includes(documentType)) {
      return res.redirect(buildRedirect('/dashboard', { error: 'Please select a valid document type.' }));
    }
    const file = req.file;
    if (!file || !file.buffer) {
      return res.redirect(buildRedirect('/dashboard', { error: 'A document file is required.' }));
    }
    const ext = getAllowedDocumentExtension(file.originalname || (file.filename || ''));
    if (!ext) {
      return res.redirect(buildRedirect('/dashboard', { error: 'Document type is not allowed.' }));
    }
    if (file.size > MAX_DOCUMENT_SIZE_BYTES) {
      return res.redirect(buildRedirect('/dashboard', { error: `Document is too large. Maximum size is ${humanizeBytes(MAX_DOCUMENT_SIZE_BYTES)}.` }));
    }
    await createDocumentRecord(
      {
        ownerUid: req.user.uid,
        ownerName: req.user.name || req.user.username,
        ownerEmail: req.user.email,
        documentType,
        displayName,
        originalName: file.originalname || (file.filename || ''),
        mimeType: file.mimetype || '',
        sizeBytes: Number(file.size) || file.buffer.length,
        notes,
      },
      file.buffer
    );
    return res.redirect(buildRedirect('/dashboard', { success: 'Document uploaded and sent to the admin team for review.' }));
  } catch (error) {
    return res.redirect(buildRedirect('/dashboard', { error: error.message || 'Document upload failed.' }));
  }
});

app.use('/documents/upload', (error, req, res, next) => {
  if (res.headersSent) return next(error);
  const message = error && error.message ? error.message : 'Document upload failed.';
  return res.redirect(buildRedirect('/dashboard', { error: message }));
});

app.get('/payments', isAuthenticated, async (req, res) => {
  const approval = await getDocumentApprovalStatusForUser(req.user);
  const payments = await listPaymentsForUser(req.user);
  const requestId = normalizeValue(req.query.requestId);
  const activeRequest = requestId ? await getPaymentById(requestId) : null;
  const isValidRequest = activeRequest
    && ((activeRequest.ownerUid && req.user.uid && activeRequest.ownerUid === req.user.uid)
      || (activeRequest.ownerEmail && req.user.email && activeRequest.ownerEmail.toLowerCase() === normalizeValue(req.user.email).toLowerCase()))
    && (activeRequest.status === 'requested' || activeRequest.status === 'in_review');
  const success = normalizeValue(req.query.success);
  const error = normalizeValue(req.query.error);
  const flash = success
    ? `<div class="flash flash-success">${escapeHtml(success)}</div>`
    : error
      ? `<div class="flash flash-error">${escapeHtml(error)}</div>`
      : '';

  if (!approval.paymentUnlocked && !isValidRequest) {
    res.send(`
      <!doctype html>
      <html lang="en-NZ">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Payment Options - Immigration New Zealand</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
          :root{--orange:#e35205;--orange-dark:#cf4900;--bg:#f3f3f3;--text:#1f1f1f;--muted:#6f6f6f;--line:#d5d5d5;--card:#fff;--shadow:0 2px 8px rgba(0,0,0,.06)}
          *{box-sizing:border-box}
          body{margin:0;font-family:"Inter",Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
          .topbar{background:#000;height:64px;display:flex;align-items:center;border-bottom:3px solid var(--orange);position:relative}
          .topbar-inner{width:100%;max-width:1280px;margin:0 auto;padding:0 28px;display:flex;justify-content:space-between;align-items:center;gap:16px}
          .brand{display:flex;align-items:center;gap:14px;color:#fff;min-width:0}
          .brand-mark{width:36px;height:36px;border-radius:8px;background:var(--orange);display:grid;place-items:center;color:#fff;font-weight:800}
          .brand-text .title{font-size:16px;font-weight:700}
          .brand-text .sub{font-size:10px;color:#bdbdbd;margin-top:2px}
          .menu-toggle{display:none;width:44px;height:44px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.08);color:#fff;align-items:center;justify-content:center;cursor:pointer;padding:0}
          .menu-lines{display:grid;gap:5px}
          .menu-lines span{display:block;width:18px;height:2px;border-radius:999px;background:rgba(255,255,255,.9)}
          nav.topnav{display:flex;align-items:center;gap:4px}
          nav.topnav a{color:#e8e8e8;text-decoration:none;font-size:13px;font-weight:500;padding:8px 14px;border-radius:6px}
          nav.topnav a:hover{background:rgba(255,255,255,.08);color:#fff}
          nav.topnav a.active{background:var(--orange);color:#fff}
          .page{max-width:1080px;margin:0 auto;padding:40px 28px 60px}
          .flash{padding:14px 16px;border-radius:14px;font-weight:600;margin-bottom:22px;border:1px solid transparent}
          .flash-success{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
          .flash-error{background:#fef2f2;border-color:#fecaca;color:#991b1b}
          .lock-card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:30px;box-shadow:var(--shadow)}
          .lock-card h1{margin:0 0 10px;font-size:26px;font-weight:600;letter-spacing:-.02em}
          .lock-card p{margin:0 0 22px;color:var(--muted);line-height:1.7}
          .btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:12px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer;color:#fff;background:var(--orange);text-decoration:none}
          .btn:hover{background:var(--orange-dark)}
          .history-title{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin:10px 0 14px}
          .history-title h2{margin:0;font-size:18px;font-weight:600}
          .doc-list{display:grid;gap:14px}
          .doc-card{border:1px solid var(--line);background:#fcfcfc;border-radius:14px;padding:16px 18px}
          .doc-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}
          .doc-type{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:6px}
          .doc-card h4{margin:0 0 6px;font-size:16px;font-weight:600}
          .doc-meta{color:var(--muted);font-size:12px;margin:0}
          .doc-pill{display:inline-flex;align-items:center;justify-content:center;padding:8px 12px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize;border:1px solid transparent}
          .status-pending{background:#fffbeb;color:#92400e;border-color:#fde68a}
          .status-in_review{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}
          .status-approved{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
          .status-rejected{background:#fef2f2;color:#991b1b;border-color:#fecaca}
          .status-settled{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
          .status-requested{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}
          .doc-body{margin-top:12px;display:grid;gap:8px}
          .doc-notes{margin:0;color:#334155;line-height:1.6;font-size:13px}
          .doc-reviewer{margin:0;color:#0f172a;background:#f8fafc;border:1px solid var(--line);border-radius:12px;padding:10px 12px;font-size:13px}
          @media (max-width:720px){
            .topbar-inner{padding:0 16px}
            .menu-toggle{display:inline-flex}
            nav.topnav{display:none;position:absolute;top:64px;left:0;right:0;background:#0b0b0b;border-top:1px solid rgba(255,255,255,.08);padding:12px 16px;flex-direction:column;align-items:stretch;gap:4px;z-index:30}
            nav.topnav.is-open{display:flex}
            nav.topnav a{padding:12px 14px;border-radius:10px}
            .page{padding:24px 16px 40px}
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
            <button class="menu-toggle" id="pay-toggle" type="button" aria-label="Toggle navigation" aria-controls="pay-nav" aria-expanded="false">
              <span class="menu-lines" aria-hidden="true"><span></span><span></span><span></span></span>
            </button>
            <nav class="topnav" id="pay-nav">
              <a href="/dashboard">Dashboard</a>
              <a href="/payments" class="active">Payments</a>
              <a href="/logout">Logout</a>
            </nav>
          </div>
        </header>
        <main class="page">
          ${flash}
          <section class="lock-card">
            <h1>${approval.paymentUnlocked ? 'Payment options are available.' : 'Payment options are locked until your documents are approved.'}</h1>
            <p>${escapeHtml(approval.summary)}</p>
            ${payments.length ? `
              <div class="history-title">
                <h2>Payment history</h2>
              </div>
              <div class="doc-list">
                ${payments.map(payment => {
                  const badge = getPaymentStatusBadge(payment.status);
                  const methodMeta = PAYMENT_METHODS.find(item => item.id === payment.method) || { label: normalizeValue(payment.method) || 'Payment' };
                  const requestTag = payment.isAdminRequest
                    ? `<span class="doc-meta"> · Admin request${payment.relatedPaymentId ? ` (settled via ${escapeHtml(payment.relatedPaymentId)})` : ''}</span>`
                    : '';
                  return `
                    <article class="doc-card">
                      <div class="doc-head">
                        <div>
                          <div class="doc-type">${escapeHtml(methodMeta.label)}</div>
                          <h4>${escapeHtml(payment.label)}</h4>
                          <p class="doc-meta">Reference <strong>${escapeHtml(payment.reference)}</strong> · ${escapeHtml(formatCurrencyCents(payment.amountCents))} · ${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}${requestTag}</p>
                        </div>
                        <span class="doc-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
                      </div>
                      <div class="doc-body">
                        ${normalizeValue(payment.notes) ? `<p class="doc-notes"><strong>Notes:</strong> ${escapeHtml(payment.notes)}</p>` : ''}
                        ${normalizeValue(payment.reviewerNote) ? `<p class="doc-reviewer"><strong>Admin note:</strong> ${escapeHtml(payment.reviewerNote)} <span class="doc-meta">· ${escapeHtml(formatDateTime(payment.reviewedAtMs || payment.updatedAtMs))}</span></p>` : ''}
                      </div>
                    </article>
                  `;
                }).join('')}
              </div>
              <p style="margin-top:18px"><a class="btn" href="/dashboard">Go back to Dashboard</a></p>
            ` : '<a class="btn" href="/dashboard">Go back to Dashboard</a>'}
          </section>
        </main>
        <script>
          (function () {
            var toggle = document.getElementById('pay-toggle');
            var nav = document.getElementById('pay-nav');
            if (!toggle || !nav) return;
            toggle.addEventListener('click', function () {
              var open = nav.classList.toggle('is-open');
              toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
            nav.addEventListener('click', function (event) {
              var anchor = event.target && event.target.closest && event.target.closest('a');
              if (anchor) {
                nav.classList.remove('is-open');
                toggle.setAttribute('aria-expanded', 'false');
              }
            });
            window.addEventListener('resize', function () {
              if (window.innerWidth > 720) {
                nav.classList.remove('is-open');
                toggle.setAttribute('aria-expanded', 'false');
              }
            });
          })();
        </script>
      </body>
      </html>
    `);
    return;
  }

  const proofDocumentId = normalizeValue(req.query.proofDocumentId);
  const effectiveAmountCents = isValidRequest && activeRequest ? activeRequest.amountCents : APPLICATION_FEE_CENTS;
  const effectiveLabel = isValidRequest && activeRequest ? activeRequest.label : APPLICATION_FEE_LABEL;
  const defaultReference = isValidRequest && activeRequest ? (activeRequest.reference || '') : '';
  const requestBanner = isValidRequest && activeRequest
    ? `
        <section class="request-banner">
          <div>
            <div class="rb-eyebrow">Payment request from admin</div>
            <h1>${escapeHtml(activeRequest.label)}</h1>
            <p class="rb-meta">
              Reference <strong>${escapeHtml(activeRequest.reference || 'N/A')}</strong>
              · Requested by ${escapeHtml(activeRequest.requestedByName || 'Admin')}
              ${activeRequest.dueDateMs ? ` · Due ${escapeHtml(formatDateTime(activeRequest.dueDateMs))}` : ''}
            </p>
            ${normalizeValue(activeRequest.requestNote) ? `<p class="rb-note"><strong>Admin message:</strong> ${escapeHtml(activeRequest.requestNote)}</p>` : ''}
          </div>
          <div class="rb-amount">${escapeHtml(formatCurrencyCents(activeRequest.amountCents))}</div>
        </section>
      `
    : '';
  const paymentMethodOptions = PAYMENT_METHODS
    .map(method => `<option value="${escapeHtml(method.id)}">${escapeHtml(method.label)}</option>`)
    .join('');
  const paymentsMarkup = payments.length
    ? payments.map(payment => {
        const badge = getPaymentStatusBadge(payment.status);
        const methodMeta = PAYMENT_METHODS.find(item => item.id === payment.method) || { label: normalizeValue(payment.method) || 'Payment' };
        const requestTag = payment.isAdminRequest
          ? `<span class="doc-meta"> · Admin request${payment.relatedPaymentId ? ` (settled via ${escapeHtml(payment.relatedPaymentId)})` : ''}</span>`
          : '';
        return `
          <article class="doc-card">
            <div class="doc-head">
              <div>
                <div class="doc-type">${escapeHtml(methodMeta.label)}</div>
                <h4>${escapeHtml(payment.label)}</h4>
                <p class="doc-meta">Reference <strong>${escapeHtml(payment.reference)}</strong> · ${escapeHtml(formatCurrencyCents(payment.amountCents))} · ${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}${requestTag}</p>
              </div>
              <span class="doc-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
            </div>
            <div class="doc-body">
              ${normalizeValue(payment.notes) ? `<p class="doc-notes"><strong>Notes:</strong> ${escapeHtml(payment.notes)}</p>` : ''}
              ${normalizeValue(payment.reviewerNote) ? `<p class="doc-reviewer"><strong>Admin note:</strong> ${escapeHtml(payment.reviewerNote)} <span class="doc-meta">· ${escapeHtml(formatDateTime(payment.reviewedAtMs || payment.updatedAtMs))}</span></p>` : ''}
            </div>
          </article>
        `;
      }).join('')
    : '<div class="empty-state"><h4>No payments yet</h4><p>Create your first payment request from the form below.</p></div>';

  res.send(`
    <!doctype html>
    <html lang="en-NZ">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Payment Options - Immigration New Zealand</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      <style>
        :root{
          --orange:#e35205;
          --orange-dark:#cf4900;
          --bg:#f3f3f3;
          --text:#1f1f1f;
          --muted:#6f6f6f;
          --border:#c9c9c9;
          --line:#d5d5d5;
          --card:#ffffff;
          --shadow:0 2px 8px rgba(0,0,0,.06);
        }
        *{box-sizing:border-box}
        body{margin:0;font-family:"Inter",Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
        .topbar{background:#000;height:64px;display:flex;align-items:center;border-bottom:3px solid var(--orange);position:relative}
        .topbar-inner{width:100%;max-width:1280px;margin:0 auto;padding:0 28px;display:flex;justify-content:space-between;align-items:center;gap:16px}
        .brand{display:flex;align-items:center;gap:14px;color:#fff;min-width:0}
        .brand-mark{width:36px;height:36px;border-radius:8px;background:var(--orange);display:grid;place-items:center;color:#fff;font-weight:800}
        .brand-text .title{font-size:16px;font-weight:700}
        .brand-text .sub{font-size:10px;color:#bdbdbd;margin-top:2px}
        .menu-toggle{
          display:none;
          width:44px;height:44px;border-radius:10px;
          border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.08);
          color:#fff;align-items:center;justify-content:center;cursor:pointer;padding:0;
        }
        .menu-lines{display:grid;gap:5px}
        .menu-lines span{display:block;width:18px;height:2px;border-radius:999px;background:rgba(255,255,255,.9)}
        nav.topnav{display:flex;align-items:center;gap:4px}
        nav.topnav a{color:#e8e8e8;text-decoration:none;font-size:13px;font-weight:500;padding:8px 14px;border-radius:6px}
        nav.topnav a:hover{background:rgba(255,255,255,.08);color:#fff}
        nav.topnav a.active{background:var(--orange);color:#fff}
        .page{max-width:1120px;margin:0 auto;padding:32px 28px 56px}
        .flash{padding:14px 16px;border-radius:14px;font-weight:600;margin-bottom:22px;border:1px solid transparent}
        .flash-success{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
        .flash-error{background:#fef2f2;border-color:#fecaca;color:#991b1b}
        .request-banner{
          background:linear-gradient(135deg,#fff7ed 0%,#ffffff 100%);
          border:1px solid #fed7aa;
          border-radius:18px;
          padding:24px;
          box-shadow:0 6px 20px rgba(227,82,5,.08);
          display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center;
          margin-bottom:22px;
        }
        .request-banner h1{margin:0;font-size:22px;font-weight:600;letter-spacing:-.02em;color:var(--text)}
        .rb-eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9a3412;font-weight:700;margin-bottom:8px}
        .rb-meta{margin:6px 0 0;color:#475569;font-size:13px}
        .rb-note{margin:12px 0 0;background:#fff;border:1px dashed #fdba74;border-radius:12px;padding:10px 12px;color:#1f2937;line-height:1.6;font-size:13px}
        .rb-amount{font-size:34px;font-weight:800;letter-spacing:-.04em;color:var(--orange)}
        .fee-card{
          background:linear-gradient(135deg,var(--orange) 0%,#f26b22 100%);color:#fff;border-radius:18px;padding:24px;margin-bottom:22px;
          display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center;
        }
        .fee-card h1{margin:0;font-size:22px;font-weight:600;letter-spacing:-.02em}
        .fee-card p{margin:6px 0 0;color:rgba(255,255,255,.86);line-height:1.6}
        .fee-amount{font-size:34px;font-weight:800;letter-spacing:-.04em}
        .methods{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:20px 0 26px}
        .method-card{
          background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow);
          display:grid;gap:6px;
        }
        .method-card h3{margin:0;font-size:16px;font-weight:700}
        .method-card p{margin:0;color:var(--muted);line-height:1.6;font-size:13px}
        .method-card .meta{color:#475569;font-size:12px;font-weight:600;margin-top:6px}
        .form-card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px 24px;box-shadow:var(--shadow);margin-bottom:22px}
        .form-card h2{margin:0 0 14px;font-size:20px;font-weight:600;letter-spacing:-.02em}
        form.payment-form{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;align-items:end}
        .span-12{grid-column:span 12 / span 12}
        .span-6{grid-column:span 6 / span 6}
        form.payment-form label{display:grid;gap:6px;font-size:13px;font-weight:600;color:#1f2937}
        form.payment-form input,form.payment-form select,form.payment-form textarea{
          width:100%;border-radius:12px;border:1px solid var(--border);background:#fff;color:var(--text);padding:12px 14px;font:inherit;
        }
        form.payment-form input:focus,form.payment-form select:focus,form.payment-form textarea:focus{
          outline:none;border-color:var(--orange);box-shadow:0 0 0 3px rgba(227,82,5,.12)
        }
        .btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:12px;padding:12px 20px;font:inherit;font-weight:700;cursor:pointer;color:#fff;background:var(--orange);text-decoration:none}
        .btn:hover{background:var(--orange-dark)}
        .btn-block{width:100%}
        .hint{margin:0;color:var(--muted);font-size:12px;line-height:1.6}
        .section-title{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin:10px 0 14px}
        .section-title h2{margin:0;font-size:18px;font-weight:600}
        .doc-list{display:grid;gap:14px}
        .doc-card{border:1px solid var(--line);background:#fcfcfc;border-radius:14px;padding:16px 18px}
        .doc-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}
        .doc-type{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:6px}
        .doc-card h4{margin:0 0 6px;font-size:16px;font-weight:600}
        .doc-meta{color:var(--muted);font-size:12px;margin:0}
        .doc-pill{
          display:inline-flex;align-items:center;justify-content:center;padding:8px 12px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize;border:1px solid transparent;
        }
        .status-pending{background:#fffbeb;color:#92400e;border-color:#fde68a}
        .status-in_review{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}
        .status-approved{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
        .status-rejected{background:#fef2f2;color:#991b1b;border-color:#fecaca}
        .doc-body{margin-top:12px;display:grid;gap:8px}
        .doc-notes{margin:0;color:#334155;line-height:1.6;font-size:13px}
        .doc-reviewer{margin:0;color:#0f172a;background:#f8fafc;border:1px solid var(--line);border-radius:12px;padding:10px 12px;font-size:13px}
        .empty-state{border:1px dashed var(--border);background:#fff;border-radius:14px;padding:22px;text-align:center;color:var(--muted)}
        .empty-state h4{margin:0 0 6px;color:#0f172a}
        @media (max-width:960px){
          .methods{grid-template-columns:1fr}
          form.payment-form{grid-template-columns:repeat(6,minmax(0,1fr))}
          .span-6{grid-column:span 6 / span 6}
        }
        @media (max-width:720px){
          .topbar-inner{padding:0 16px}
          .brand-text .title{font-size:14px}
          .menu-toggle{display:inline-flex}
          nav.topnav{
            display:none;position:absolute;top:64px;left:0;right:0;background:#0b0b0b;
            border-top:1px solid rgba(255,255,255,.08);padding:12px 16px;flex-direction:column;align-items:stretch;gap:4px;
            z-index:30;
          }
          nav.topnav.is-open{display:flex}
          nav.topnav a{padding:12px 14px;border-radius:10px}
          .page{padding:22px 16px 40px}
          .request-banner{grid-template-columns:1fr;padding:20px;border-radius:16px}
          .fee-card{grid-template-columns:1fr;padding:20px;border-radius:16px}
          form.payment-form{grid-template-columns:1fr}
          .span-12,.span-6{grid-column:span 1 / span 1}
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
          <button class="menu-toggle" id="pay-toggle" type="button" aria-label="Toggle navigation" aria-controls="pay-nav" aria-expanded="false">
            <span class="menu-lines" aria-hidden="true"><span></span><span></span><span></span></span>
          </button>
          <nav class="topnav" id="pay-nav">
            <a href="/">Home</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/payments" class="active">Payments</a>
            <a href="/logout">Logout</a>
          </nav>
        </div>
      </header>
      <main class="page">
        ${flash}
        ${requestBanner || `
        <section class="fee-card">
          <div>
            <h1>${escapeHtml(effectiveLabel)}</h1>
            <p>${approval.paymentUnlocked ? 'Your documents have been approved. Choose your preferred payment method to complete the application process.' : 'Documents still pending. A payment request from admin allows you to pay directly from here before document review finishes.'}</p>
          </div>
          <div class="fee-amount">${escapeHtml(formatCurrencyCents(effectiveAmountCents))}</div>
        </section>
        `}
        <section class="methods">
          ${PAYMENT_METHODS.map(method => `
            <article class="method-card">
              <h3>${escapeHtml(method.label)}</h3>
              <p>${escapeHtml(method.description)}</p>
              <div class="meta">Amount: ${escapeHtml(formatCurrencyCents(effectiveAmountCents))}</div>
            </article>
          `).join('')}
        </section>
        <section class="form-card">
          <h2>${isValidRequest ? 'Settle admin payment request' : 'Payment request'}</h2>
          <form class="payment-form" method="POST" action="/payments/create">
            ${isValidRequest ? `<input type="hidden" name="requestId" value="${escapeHtml(activeRequest.id)}">` : ''}
            <label class="span-6">
              Payment method
              <select name="method" required>${paymentMethodOptions}</select>
            </label>
            <label class="span-6">
              Payment reference (optional)
              <input type="text" name="reference" placeholder="e.g. bank payment receipt number" value="${escapeHtml(defaultReference)}">
            </label>
            <label class="span-6">
              Proof of payment document ID (optional)
              <input type="text" name="proofDocumentId" value="${escapeHtml(proofDocumentId)}" placeholder="Optional document ID for a receipt you already uploaded">
            </label>
            <label class="span-6">
              Card number (demo mode)
              <input type="text" name="cardNumber" placeholder="Card payment mode writes a paid demo record. No live card charges.">
            </label>
            <label class="span-12">
              Payment notes
              <textarea name="notes" rows="3" placeholder="Add any notes you want the admin team to see with this payment."></textarea>
            </label>
            <div class="span-12" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
              <p class="hint"><strong>Important:</strong> Bank transfers stay in <em>Verifying payment</em> status until the admin team approves them.</p>
              <button type="submit" class="btn">${isValidRequest ? 'Submit settlement of this request' : 'Submit payment request'}</button>
            </div>
          </form>
        </section>
        <div class="section-title">
          <h2>Payment history</h2>
        </div>
        <section class="doc-list">${paymentsMarkup}</section>
      </main>
      <script>
        (function () {
          var toggle = document.getElementById('pay-toggle');
          var nav = document.getElementById('pay-nav');
          if (!toggle || !nav) return;
          toggle.addEventListener('click', function () {
            var open = nav.classList.toggle('is-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
          });
          nav.addEventListener('click', function (event) {
            var anchor = event.target && event.target.closest && event.target.closest('a');
            if (anchor) {
              nav.classList.remove('is-open');
              toggle.setAttribute('aria-expanded', 'false');
            }
          });
          window.addEventListener('resize', function () {
            if (window.innerWidth > 720) {
              nav.classList.remove('is-open');
              toggle.setAttribute('aria-expanded', 'false');
            }
          });
        })();
      </script>
    </body>
    </html>
  `);
});

app.post('/payments/create', isAuthenticated, async (req, res) => {
  const approval = await getDocumentApprovalStatusForUser(req.user);
  const rawRequestId = normalizeValue(req.body.requestId);
  const targetRequest = rawRequestId ? await getPaymentById(rawRequestId) : null;
  const isOwnRequest = targetRequest
    && ((targetRequest.ownerUid && req.user.uid && targetRequest.ownerUid === req.user.uid)
      || (targetRequest.ownerEmail && req.user.email && targetRequest.ownerEmail.toLowerCase() === normalizeValue(req.user.email).toLowerCase()))
    && (targetRequest.status === 'requested' || targetRequest.status === 'in_review');

  if (!approval.paymentUnlocked && !isOwnRequest) {
    return res.redirect(buildRedirect('/payments', { error: approval.summary || 'Payment is locked until documents are approved.' }));
  }
  const method = normalizeValue(req.body.method);
  const reference = normalizeValue(req.body.reference);
  const proofDocumentId = normalizeValue(req.body.proofDocumentId);
  const notes = normalizeValue(req.body.notes);
  if (!PAYMENT_METHODS.some(item => item.id === method)) {
    return res.redirect(buildRedirect('/payments', { error: 'Please choose a valid payment method.' }));
  }
  if (method === 'bank') {
    const proofs = proofDocumentId ? [await getDocumentById(proofDocumentId)].filter(Boolean) : [];
    const ownerProof = proofs.find(
      doc => (doc.ownerUid && doc.ownerUid === req.user.uid) || (doc.ownerEmail && doc.ownerEmail.toLowerCase() === normalizeValue(req.user.email).toLowerCase())
    );
    if (!ownerProof && !reference) {
      return res.redirect(buildRedirect('/payments', { error: 'Please include a payment reference or upload a proof of payment first.' }));
    }
  }
  try {
    const amountCents = targetRequest && isOwnRequest ? targetRequest.amountCents : APPLICATION_FEE_CENTS;
    const label = targetRequest && isOwnRequest ? targetRequest.label : APPLICATION_FEE_LABEL;
    const created = await createPaymentRecord({
      ownerUid: req.user.uid,
      ownerName: req.user.name || req.user.username,
      ownerEmail: req.user.email,
      method,
      reference,
      proofDocumentId,
      notes,
      amountCents,
      label,
      relatedRequestId: isOwnRequest ? targetRequest.id : undefined,
    });
    if (isOwnRequest) {
      const settleStatus = method === 'card' ? 'paid' : 'in_review';
      await settleAdminPaymentRequest(targetRequest.id, created.id, settleStatus);
    }
    const success = method === 'card'
      ? 'Payment recorded successfully (demo card mode). Your payment is confirmed.'
      : 'Bank transfer received. The admin team will verify your payment and update the status.';
    return res.redirect(buildRedirect('/payments', {
      success: isOwnRequest ? `${success} Your admin request has been linked to this payment.` : success,
      requestId: isOwnRequest ? targetRequest.id : undefined,
    }));
  } catch (error) {
    return res.redirect(buildRedirect('/payments', { error: error.message || 'Unable to create your payment request.' }));
  }
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
    const documents = await listAllDocuments();
    const payments = await listAllPayments();
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

    const documentsMarkup = documents.length
      ? documents.map(document => {
          const badge = getDocumentStatusBadge(document.status);
          const reviewerNote = normalizeValue(document.reviewerNote);
          return `
            <article class="queue-card doc-review-card" id="document-${escapeHtml(document.id)}">
              <div class="queue-top">
                <div>
                  <div class="queue-eyebrow">${escapeHtml(document.documentType)}</div>
                  <h3>${escapeHtml(document.displayName || document.originalName || 'Uploaded document')}</h3>
                  <p class="queue-summary">
                    Applicant: <strong>${escapeHtml(document.ownerName || document.ownerEmail || 'Unknown')}</strong>
                    · ${escapeHtml(document.ownerEmail || 'No email')}
                  </p>
                </div>
                <div class="queue-badges">
                  <span class="status-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
                </div>
              </div>
              <div class="queue-meta">
                <span><strong>Type</strong> ${escapeHtml(document.documentType)}</span>
                <span><strong>Size</strong> ${escapeHtml(humanizeBytes(document.sizeBytes))}</span>
                <span><strong>Submitted</strong> ${escapeHtml(formatDateTime(document.createdAtMs || document.updatedAtMs))}</span>
                <span><strong>File</strong> <a href="/documents/${encodeURIComponent(document.id)}/download">Download</a></span>
              </div>
              <div class="queue-body">
                <div class="queue-history">
                  <h4>Document notes</h4>
                  <ul>
                    <li>
                      <strong>Applicant note</strong>
                      <span>${escapeHtml(formatDateTime(document.createdAtMs || document.updatedAtMs))}</span>
                      <p>${escapeHtml(normalizeValue(document.notes) || 'No notes provided by the applicant.')}</p>
                    </li>
                    ${reviewerNote
                      ? `<li>
                          <strong>Admin note</strong>
                          <span>${escapeHtml(formatDateTime(document.reviewedAtMs || document.updatedAtMs))}</span>
                          <p>${escapeHtml(reviewerNote)}</p>
                        </li>`
                      : ''}
                  </ul>
                </div>
                <form method="POST" action="/admin/documents/${encodeURIComponent(document.id)}/status" class="queue-form">
                  <label>
                    Reviewer note
                    <textarea name="note" placeholder="Explain why the document was approved, rejected, or moved to in review.">${escapeHtml(reviewerNote)}</textarea>
                  </label>
                  <div class="queue-actions">
                    <button type="submit" name="status" value="approved" class="btn btn-approve">Approve document</button>
                    <button type="submit" name="status" value="in_review" class="btn btn-review">Mark In Review</button>
                    <button type="submit" name="status" value="rejected" class="btn btn-reject">Reject document</button>
                  </div>
                </form>
              </div>
            </article>
          `;
        }).join('')
      : '<div class="empty-state"><h3>No documents submitted yet</h3><p>Once users upload passport, identity, medical, or other required files, they appear here for approval.</p></div>';

    const paymentsMarkup = payments.length
      ? payments.map(payment => {
          const badge = getPaymentStatusBadge(payment.status);
          const methodMeta = PAYMENT_METHODS.find(item => item.id === payment.method) || { label: normalizeValue(payment.method) || 'Payment' };
          const reviewerNote = normalizeValue(payment.reviewerNote);
          const proofLink = normalizeValue(payment.proofDocumentId)
            ? `<li><strong>Proof of payment</strong><span>Linked document</span><p><a href="/documents/${encodeURIComponent(payment.proofDocumentId)}/download">Download proof document</a></p></li>`
            : '';
          const requestLine = payment.isAdminRequest
            ? `<li><strong>Requested by</strong><span>${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}</span><p>${escapeHtml(payment.requestedByName || 'Admin')} · ${escapeHtml(payment.requestedByEmail || 'Admin panel')}${payment.requestNote ? `<br><em>${escapeHtml(payment.requestNote)}</em>` : ''}</p></li>`
            : '';
          const dueLine = payment.dueDateMs
            ? `<li><strong>Due date</strong><span>${escapeHtml(formatDateTime(payment.dueDateMs))}</span><p>Payment must reach the office before this date. After it expires admin may cancel the request.</p></li>`
            : '';
          return `
            <article class="queue-card doc-review-card" id="payment-${escapeHtml(payment.id)}">
              <div class="queue-top">
                <div>
                  <div class="queue-eyebrow">${escapeHtml(payment.isAdminRequest ? `Admin request · ${methodMeta.label}` : methodMeta.label)}</div>
                  <h3>${escapeHtml(payment.label)} · ${escapeHtml(formatCurrencyCents(payment.amountCents))}</h3>
                  <p class="queue-summary">
                    Applicant: <strong>${escapeHtml(payment.ownerName || payment.ownerEmail || 'Unknown')}</strong>
                    · ${escapeHtml(payment.ownerEmail || 'No email')}
                  </p>
                </div>
                <div class="queue-badges">
                  <span class="status-pill ${escapeHtml(badge.className)}">${escapeHtml(badge.label)}</span>
                </div>
              </div>
              <div class="queue-meta">
                <span><strong>Reference</strong> ${escapeHtml(payment.reference || 'N/A')}</span>
                <span><strong>Amount</strong> ${escapeHtml(formatCurrencyCents(payment.amountCents))}</span>
                <span><strong>Submitted</strong> ${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}</span>
                <span><strong>Payment ID</strong> ${escapeHtml(payment.id)}</span>
              </div>
              <div class="queue-body">
                <div class="queue-history">
                  <h4>Payment notes</h4>
                  <ul>
                    <li>
                      <strong>Applicant note</strong>
                      <span>${escapeHtml(formatDateTime(payment.createdAtMs || payment.updatedAtMs))}</span>
                      <p>${escapeHtml(normalizeValue(payment.notes) || 'No notes provided by the applicant.')}</p>
                    </li>
                    ${requestLine}
                    ${dueLine}
                    ${proofLink}
                    ${reviewerNote
                      ? `<li>
                          <strong>Admin note</strong>
                          <span>${escapeHtml(formatDateTime(payment.reviewedAtMs || payment.updatedAtMs))}</span>
                          <p>${escapeHtml(reviewerNote)}</p>
                        </li>`
                      : ''}
                  </ul>
                </div>
                <form method="POST" action="/admin/payments/${encodeURIComponent(payment.id)}/status" class="queue-form">
                  <label>
                    Reviewer note
                    <textarea name="note" placeholder="Confirm the payment, request more info, or record a rejection reason.">${escapeHtml(reviewerNote)}</textarea>
                  </label>
                  <div class="queue-actions">
                    <button type="submit" name="status" value="paid" class="btn btn-approve">Mark Paid</button>
                    <button type="submit" name="status" value="in_review" class="btn btn-review">Mark In Review</button>
                    ${payment.isAdminRequest ? `<button type="submit" name="status" value="cancelled" class="btn btn-request">Cancel Request</button>` : ''}
                    <button type="submit" name="status" value="rejected" class="btn btn-reject">Reject payment</button>
                  </div>
                </form>
              </div>
            </article>
          `;
        }).join('')
      : '<div class="empty-state"><h3>No payment requests yet</h3><p>Users can create payment requests only after their uploaded documents are fully approved. You can also send a payment demand directly from the Request Payment panel below.</p></div>';

    const allPortalUsers = await listPortalUsers();
    const userSelectOptions = allPortalUsers.length
      ? allPortalUsers.map(user => {
          const label = `${user.name || user.username || 'User'} · ${user.email || user.username || ''}${user.username ? ` (${user.username})` : ''}`;
          const value = JSON.stringify({ uid: user.uid, name: user.name || user.username || '', email: user.email || '' });
          return `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;
        }).join('')
      : '<option value="">No registered users yet</option>';
    const defaultAmountNaira = (APPLICATION_FEE_CENTS / 100).toFixed(2);
    const requestPaymentMarkup = `
      <form class="admin-form request-payment-form" method="POST" action="/admin/payments/request" autocomplete="off">
        <div class="form-grid">
          <label class="span-12">
            Recipient user
            <select name="targetUser" required>
              <option value="">Choose the registered user to send the payment request to</option>
              ${userSelectOptions}
            </select>
          </label>
          <label>
            Payment label
            <input type="text" name="label" placeholder="e.g. Biometric enrolment fee" value="${escapeHtml(APPLICATION_FEE_LABEL)}" required>
          </label>
          <label>
            Amount (₦)
            <input type="number" name="amount" min="0" step="0.01" value="${escapeHtml(defaultAmountNaira)}" required>
          </label>
          <label>
            Reference (optional)
            <input type="text" name="reference" placeholder="Invoice / demand number (auto-generated if empty)">
          </label>
          <label>
            Due date (optional)
            <input type="date" name="dueDate">
          </label>
          <label class="span-12">
            Email / dashboard note to the user
            <textarea name="requestNote" rows="3" placeholder="This message appears in the user's dashboard and acts as the email body. Explain what the payment is for and how to pay."></textarea>
          </label>
          <label class="span-12">
            Internal admin notes (not shown to the user)
            <textarea name="notes" rows="2" placeholder="Optional: any internal context for your team."></textarea>
          </label>
        </div>
        <p class="hint"><strong>Demo email:</strong> Because no live SMTP server is configured, the request is saved directly to the recipient's dashboard and their email address is recorded in the payment record.</p>
        <div class="actions">
          <button type="submit" class="btn btn-approve">Send payment request to user</button>
        </div>
      </form>
    `;

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
        DOCUMENT_MARKUP: documentsMarkup,
        PAYMENT_MARKUP: paymentsMarkup,
        REQUEST_PAYMENT_MARKUP: requestPaymentMarkup,
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

app.post('/admin/payments/request', requireAdminSession, async (req, res) => {
  const targetUserRaw = normalizeValue(req.body.targetUser);
  const label = normalizeValue(req.body.label);
  const amountRaw = Number(req.body.amount);
  const reference = normalizeValue(req.body.reference);
  const dueDate = normalizeValue(req.body.dueDate);
  const requestNote = normalizeValue(req.body.requestNote);
  const notes = normalizeValue(req.body.notes);

  if (!targetUserRaw) {
    return res.redirect(buildRedirect('/admin', { error: 'Please choose the recipient user before sending the payment request.' }));
  }
  let target;
  try {
    target = JSON.parse(targetUserRaw);
  } catch (error) {
    return res.redirect(buildRedirect('/admin', { error: 'Unable to read the selected user.' }));
  }
  if (!target || (!target.uid && !target.email)) {
    return res.redirect(buildRedirect('/admin', { error: 'Selected user is invalid. Please try again.' }));
  }
  if (!label) {
    return res.redirect(buildRedirect('/admin', { error: 'Payment label is required.' }));
  }
  if (!Number.isFinite(amountRaw) || amountRaw <= 0) {
    return res.redirect(buildRedirect('/admin', { error: 'Amount must be a positive number.' }));
  }
  const amountCents = Math.round(amountRaw * 100);
  try {
    const created = await createAdminPaymentRequest({
      ownerUid: normalizeValue(target.uid),
      ownerName: normalizeValue(target.name),
      ownerEmail: normalizeValue(target.email),
      label,
      amountCents,
      reference,
      dueDate,
      requestNote,
      notes,
    }, req.user);
    const recipientLine = created.ownerEmail ? `${created.ownerName || created.ownerUid} · ${created.ownerEmail}` : created.ownerName || created.ownerUid;
    const success = `Payment demand sent to ${recipientLine} (${escapeHtml(formatCurrencyCents(created.amountCents))}). It now appears on their dashboard under Requests from Admin and is recorded in the email status field.`;
    res.redirect(buildRedirect('/admin#payment-requests', { success }));
  } catch (error) {
    res.redirect(buildRedirect('/admin', { error: error.message || 'Unable to send the payment request.' }));
  }
});

app.post('/admin/documents/:id/status', requireAdminSession, async (req, res) => {
  const id = normalizeValue(req.params.id);
  const status = normalizeValue(req.body.status);
  const note = normalizeValue(req.body.note);
  try {
    await reviewDocument(id, status, req.user, note);
    res.redirect(buildRedirect('/admin#queue', { success: 'Document review decision saved successfully.' }));
  } catch (error) {
    res.redirect(buildRedirect('/admin', { error: error.message || 'Unable to update document status.' }));
  }
});

app.post('/admin/payments/:id/status', requireAdminSession, async (req, res) => {
  const id = normalizeValue(req.params.id);
  const status = normalizeValue(req.body.status);
  const note = normalizeValue(req.body.note);
  try {
    await reviewPayment(id, status, req.user, note);
    res.redirect(buildRedirect('/admin#payments', { success: 'Payment review decision saved successfully.' }));
  } catch (error) {
    res.redirect(buildRedirect('/admin', { error: error.message || 'Unable to update payment status.' }));
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

app.post('/admin/users/create', requireAdminSession, async (req, res) => {
  const name = normalizeValue(req.body.name);
  const username = normalizeValue(req.body.username);
  const email = normalizeValue(req.body.email);
  const password = normalizeValue(req.body.password);
  const confirmPassword = normalizeValue(req.body.confirmPassword);

  if (!name || !username || !email || !password || !confirmPassword) {
    res.redirect(buildRedirect('/admin', { error: 'All user profile fields are required.' }));
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    res.redirect(buildRedirect('/admin', { error: 'Please enter a valid email address.' }));
    return;
  }

  if (username.length < 4) {
    res.redirect(buildRedirect('/admin', { error: 'Username must be at least 4 characters.' }));
    return;
  }

  if (password.length < 8) {
    res.redirect(buildRedirect('/admin', { error: 'Password must be at least 8 characters.' }));
    return;
  }

  if (password !== confirmPassword) {
    res.redirect(buildRedirect('/admin', { error: 'Passwords do not match.' }));
    return;
  }

  try {
    const existingUsername = await findUserByField('usernameLower', username.toLowerCase());
    if (existingUsername) {
      res.redirect(buildRedirect('/admin', { error: 'That username is already registered.' }));
      return;
    }

    const existingEmail = await findUserByField('emailLower', email.toLowerCase());
    if (existingEmail) {
      res.redirect(buildRedirect('/admin', { error: 'That email address is already registered.' }));
      return;
    }

    const { salt, hash } = hashPassword(password);
    await createUser({
      username,
      usernameLower: username.toLowerCase(),
      email,
      emailLower: email.toLowerCase(),
      name,
      passwordHash: hash,
      passwordSalt: salt,
    });

    res.redirect(buildRedirect('/admin', { success: `User profile created for ${username}.` }));
  } catch (error) {
    res.redirect(buildRedirect('/admin', { error: error.message || 'Unable to create the user profile right now.' }));
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

async function startServer() {
  try {
    await ensureDefaultAdminAccount();
  } catch (error) {
    console.error('Unable to ensure default admin account:', error.message || error);
  }

  try {
    const storageReady = ensureUploadDirectory();
    console.log(`[storage] Local upload directory ${storageReady ? 'READY' : 'UNAVAILABLE'} (${DOCUMENT_UPLOAD_DIR})`);
  } catch (error) {
    console.warn('[storage] ensureUploadDirectory deferred, continuing with Firestore/base64 fallback:', error.message || error);
  }

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
  });
}

startServer();
