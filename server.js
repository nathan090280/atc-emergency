// ATC Emergency Backend - Auth, Leaderboards, Sessions
// Run: node server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
// Allow overriding the scoreboard path for cloud providers (e.g., Render persistent disk)
const DB_PATH = process.env.SCOREBOARD_PATH || path.join(__dirname, 'scoreboard.json');

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// --- Storage helpers ---
function ensureDb() {
  // Ensure parent directory exists
  const dir = path.dirname(DB_PATH);
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  if (!fs.existsSync(DB_PATH)) {
    const initial = { users: {} };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
  }
}

function readDb() {
  ensureDb();
  const raw = fs.readFileSync(DB_PATH, 'utf8');
  try { return JSON.parse(raw); } catch { return { users: {} }; }
}

function writeDb(db) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

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

    const db = readDb();
    if (db.users[username]) return res.status(409).json({ error: 'username exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    db.users[username] = {
      passwordHash,
      careerScore: 0,
      stats: defaultStats(),
      sessions: [],
      maxSessionScore: 0,
    };
    writeDb(db);

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
    const db = readDb();
    const user = db.users[username];
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

app.get('/api/leaderboards/sessionTop', (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));
    const db = readDb();
    const rows = Object.entries(db.users).map(([username, u]) => ({ username, score: u.maxSessionScore || 0 }));
    rows.sort((a, b) => b.score - a.score);
    return res.json({ results: rows.slice(0, limit) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/leaderboards/careerTop', (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));
    const db = readDb();
    const rows = Object.entries(db.users).map(([username, u]) => ({ username, careerScore: u.careerScore || 0 }));
    rows.sort((a, b) => b.careerScore - a.careerScore);
    return res.json({ results: rows.slice(0, limit) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/stats/:username', (req, res) => {
  try {
    const username = req.params.username;
    const db = readDb();
    const user = db.users[username];
    if (!user) return res.status(404).json({ error: 'not found' });
    return res.json({ username, careerScore: user.careerScore || 0, stats: user.stats || defaultStats() });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/session', authRequired, (req, res) => {
  try {
    const { score, stats, startedAt, endedAt, durationMs } = req.body || {};
    const username = req.user.username;
    const db = readDb();
    const user = db.users[username];
    if (!user) return res.status(401).json({ error: 'auth error' });

    // Append session
    user.sessions.push({
      score: Number(score) || 0,
      durationMs: Number(durationMs) || 0,
      startedAt: startedAt || new Date().toISOString(),
      endedAt: endedAt || new Date().toISOString(),
    });

    // Update aggregates
    const s = stats || {};
    const keys = Object.keys(defaultStats());
    user.stats = user.stats || defaultStats();
    for (const k of keys) {
      user.stats[k] = Number(user.stats[k] || 0) + Number(s[k] || 0);
    }

    // Update career score (sum of best session or additive — here additive)
    const numericScore = Number(score) || 0;
    user.careerScore = Number(user.careerScore || 0) + numericScore;
    user.maxSessionScore = Math.max(Number(user.maxSessionScore || 0), numericScore);

    writeDb(db);
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
