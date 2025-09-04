// ATC Emergency Backend - Auth, Leaderboards, Sessions
// Run: node server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
// Firebase Realtime Database URL (required for production). Defaults to provided project.
const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL || 'https://atc-emergency-default-rtdb.europe-west1.firebasedatabase.app';

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// --- Firebase initialization ---
// Expect either FIREBASE_SERVICE_ACCOUNT_JSON env var or Application Default Credentials.
if (!admin.apps.length) {
  try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: FIREBASE_DATABASE_URL,
      });
    } else {
      // For local development: set GOOGLE_APPLICATION_CREDENTIALS to a service account file
      admin.initializeApp({
        credential: admin.credential.applicationDefault(),
        databaseURL: FIREBASE_DATABASE_URL,
      });
    }
    console.log('Firebase initialized with DB:', FIREBASE_DATABASE_URL);
  } catch (e) {
    console.error('Failed to initialize Firebase Admin SDK:', e);
  }
}
const rtdb = admin.database();
const usersRef = rtdb.ref('users');

function defaultStats() {
  return {
    planesLanded: 0,
    passengersLanded: 0,
    cratesDelivered: 0,
    planesLost: 0,
    passengersLost: 0,
    cratesDestroyed: 0,
    emergencies: 0,
  };
}

// --- DB helper functions (Firebase) ---
async function getUser(username) {
  const snap = await usersRef.child(username).once('value');
  return snap.val() || null;
}
async function setUser(username, data) {
  await usersRef.child(username).set(data);
}
async function updateUser(username, data) {
  await usersRef.child(username).update(data);
}
async function getAllUsers() {
  const snap = await usersRef.once('value');
  return snap.val() || {};
}

// --- Auth middleware ---
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { username: payload.username };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---
app.post('/api/signup', async (req, res) => {
  try {
    const username = String((req.body.username || '')).trim();
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    if (!/^[A-Za-z0-9_\-]{3,20}$/.test(username)) return res.status(400).json({ error: 'invalid username' });

    const existing = await getUser(username);
    if (existing) return res.status(409).json({ error: 'username exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const userDoc = {
      passwordHash,
      careerScore: 0,
      stats: defaultStats(),
      sessions: [],
      maxSessionScore: 0,
    };
    await setUser(username, userDoc);

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ username, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String((req.body.username || '')).trim();
    const password = String(req.body.password || '');
    const user = await getUser(username);
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ username, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/leaderboards/sessionTop', async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));
    const users = await getAllUsers();
    const rows = Object.entries(users).map(([username, u]) => ({ username, score: (u && u.maxSessionScore) || 0 }));
    rows.sort((a, b) => b.score - a.score);
    return res.json({ results: rows.slice(0, limit) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/leaderboards/careerTop', async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));
    const users = await getAllUsers();
    const rows = Object.entries(users).map(([username, u]) => ({ username, careerScore: (u && u.careerScore) || 0 }));
    rows.sort((a, b) => b.careerScore - a.careerScore);
    return res.json({ results: rows.slice(0, limit) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/stats/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const user = await getUser(username);
    if (!user) return res.status(404).json({ error: 'not found' });
    return res.json({ username, careerScore: user.careerScore || 0, stats: user.stats || defaultStats() });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/session', authRequired, async (req, res) => {
  try {
    const { score, stats, startedAt, endedAt, durationMs } = req.body || {};
    const username = req.user.username;
    const user = await getUser(username);
    if (!user) return res.status(401).json({ error: 'auth error' });

    const sessions = Array.isArray(user.sessions) ? user.sessions.slice() : [];
    const numericScore = Number(score) || 0;
    sessions.push({
      score: numericScore,
      durationMs: Number(durationMs) || 0,
      startedAt: startedAt || new Date().toISOString(),
      endedAt: endedAt || new Date().toISOString(),
    });

    // Update aggregates
    const s = stats || {};
    const keys = Object.keys(defaultStats());
    const newStats = Object.assign({}, defaultStats(), user.stats || {});
    for (const k of keys) {
      newStats[k] = Number(newStats[k] || 0) + Number(s[k] || 0);
    }

    const updated = {
      sessions,
      stats: newStats,
      careerScore: Number(user.careerScore || 0) + numericScore,
      maxSessionScore: Math.max(Number(user.maxSessionScore || 0), numericScore),
    };
    await updateUser(username, updated);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'ATC Emergency Backend' });
});

app.listen(PORT, () => {
  console.log(`ATC Emergency backend running on http://localhost:${PORT}`);
});
