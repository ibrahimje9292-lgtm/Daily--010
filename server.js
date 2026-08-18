/* Site Attendance — single-file server.
 * Everything (DB setup, schema, auth, routes, auto-seeding, static page) lives
 * here on purpose so the whole app is just 4 flat files with no folders:
 * package.json, server.js, index.html, seed_workers.json.
 */

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { stringify } = require('csv-stringify/sync');

/* ---------------------------------------------------------------- DB setup */

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'attendance.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'foreman')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  trade TEXT,
  zone TEXT,
  crew_tab TEXT,
  foreman_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id INTEGER NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('P', 'V', 'A')),
  activity TEXT,
  duration TEXT,
  location TEXT,
  recorded_by INTEGER REFERENCES users(id),
  recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(worker_id, date)
);

CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(date);
CREATE INDEX IF NOT EXISTS idx_workers_foreman ON workers(foreman_id);
`);

/* ------------------------------------------------------------- Auto-seed */

const FOREMAN_DISPLAY = {
  ABDULJABBAR: 'Abdul Jabbar Khial Zada',
  RAMAKHANT: 'Rama Kant Jangir',
  SHUBKHARAN: 'Subhkaran Jangir',
  AHMED: 'Ahmed Abdelwahab',
};
const ZONE_TO_FOREMAN_KEY = { 1: 'ABDULJABBAR', 2: 'SHUBKHARAN' };

function slugUsername(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '')
    .slice(0, 24);
}

function upsertUser({ username, password, fullName, role }) {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return existing.id;
  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
    .run(username, hash, fullName, role);
  return info.lastInsertRowid;
}

function seedIfEmpty() {
  const adminId = upsertUser({
    username: 'ibrahim',
    password: 'ChangeMe123!',
    fullName: 'Ibrahim Abu Jalboush',
    role: 'admin',
  });

  const foremanIdByKey = {};
  for (const [key, displayName] of Object.entries(FOREMAN_DISPLAY)) {
    foremanIdByKey[key] = upsertUser({
      username: slugUsername(displayName),
      password: 'ChangeMe123!',
      fullName: displayName,
      role: 'foreman',
    });
  }

  const existingWorkerCount = db.prepare('SELECT COUNT(*) AS c FROM workers').get().c;
  if (existingWorkerCount > 0) return;

  const seedFile = path.join(__dirname, 'seed_workers.json');
  if (!fs.existsSync(seedFile)) {
    console.log('No seed_workers.json found next to server.js — skipping worker import.');
    return;
  }
  const workers = JSON.parse(fs.readFileSync(seedFile, 'utf8'));

  const insertWorker = db.prepare(`
    INSERT INTO workers (name, trade, zone, crew_tab, foreman_id) VALUES (?, ?, ?, ?, ?)
  `);
  const insertAttendance = db.prepare(`
    INSERT OR IGNORE INTO attendance (worker_id, date, status, activity, duration, location, recorded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const today = new Date().toISOString().slice(0, 10);

  const tx = db.transaction((rows) => {
    let count = 0;
    for (const w of rows) {
      if (!w.name) continue;
      let foremanKey = null;
      if (w.foreman && FOREMAN_DISPLAY[w.foreman]) {
        foremanKey = w.foreman;
      } else if (w.zone != null && ZONE_TO_FOREMAN_KEY[String(w.zone)]) {
        foremanKey = ZONE_TO_FOREMAN_KEY[String(w.zone)];
      }
      const foremanId = foremanKey ? foremanIdByKey[foremanKey] : null;
      const info = insertWorker.run(
        w.name,
        w.trade || null,
        w.zone != null ? String(w.zone) : null,
        w.source_tab || null,
        foremanId
      );
      count += 1;
      if (w.attendance) {
        insertAttendance.run(
          info.lastInsertRowid,
          today,
          w.attendance,
          w.activity || null,
          w.duration || null,
          w.location || null,
          adminId
        );
      }
    }
    return count;
  });

  const imported = tx(workers);
  console.log(`Seeded ${imported} workers + admin + foreman accounts. Default password: ChangeMe123!`);
}

seedIfEmpty();

/* -------------------------------------------------------------------- Auth */

function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username);
}
function verifyPassword(user, password) {
  return bcrypt.compareSync(password, user.password_hash);
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const user = db.prepare('SELECT id, username, full_name, role FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Session invalid' });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

/* --------------------------------------------------------------- App setup */

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 12 },
  })
);

/* ----------------------------------------------------------- Auth routes */

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
  const user = findUserByUsername(username.trim());
  if (!user || !verifyPassword(user, password)) return res.status(401).json({ error: 'Invalid username or password' });
  req.session.userId = user.id;
  res.json({ id: user.id, username: user.username, fullName: user.full_name, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

app.post('/api/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(user, oldPassword)) return res.status(401).json({ error: 'Current password is incorrect' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

/* -------------------------------------------------------- Worker routes */

app.get('/api/workers', requireAuth, (req, res) => {
  const { foremanId, zone, trade, includeInactive } = req.query;
  let sql = `SELECT w.*, u.full_name AS foreman_name FROM workers w LEFT JOIN users u ON u.id = w.foreman_id WHERE 1=1`;
  const params = [];
  if (req.user.role === 'foreman') {
    sql += ' AND w.foreman_id = ?';
    params.push(req.user.id);
  } else if (foremanId) {
    sql += ' AND w.foreman_id = ?';
    params.push(foremanId);
  }
  if (!includeInactive) sql += ' AND w.active = 1';
  if (zone) {
    sql += ' AND w.zone = ?';
    params.push(zone);
  }
  if (trade) {
    sql += ' AND w.trade = ?';
    params.push(trade);
  }
  sql += ' ORDER BY w.name';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/workers', requireAuth, requireAdmin, (req, res) => {
  const { name, trade, zone, foremanId } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Worker name is required' });
  const info = db
    .prepare('INSERT INTO workers (name, trade, zone, foreman_id) VALUES (?, ?, ?, ?)')
    .run(name, trade || null, zone || null, foremanId || null);
  res.status(201).json({ id: info.lastInsertRowid });
});

app.put('/api/workers/:id', requireAuth, requireAdmin, (req, res) => {
  const { name, trade, zone, foremanId, active } = req.body || {};
  const existing = db.prepare('SELECT * FROM workers WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Worker not found' });
  db.prepare(`UPDATE workers SET name = ?, trade = ?, zone = ?, foreman_id = ?, active = ? WHERE id = ?`).run(
    name ?? existing.name,
    trade ?? existing.trade,
    zone ?? existing.zone,
    foremanId ?? existing.foreman_id,
    active === undefined ? existing.active : active ? 1 : 0,
    req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/workers/:id', requireAuth, requireAdmin, (req, res) => {
  db.prepare('UPDATE workers SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* ----------------------------------------------------------- User routes */

app.get('/api/users/foremen', requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare("SELECT id, username, full_name, active FROM users WHERE role = 'foreman' ORDER BY full_name").all());
});

app.post('/api/users/foremen', requireAuth, requireAdmin, (req, res) => {
  const { username, fullName, password } = req.body || {};
  if (!username || !fullName || !password) return res.status(400).json({ error: 'username, fullName and password are required' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
    .run(username, hash, fullName, 'foreman');
  res.status(201).json({ id: info.lastInsertRowid });
});

app.put('/api/users/foremen/:id', requireAuth, requireAdmin, (req, res) => {
  const { fullName, active, password } = req.body || {};
  const existing = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'foreman'").get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Foreman not found' });
  db.prepare('UPDATE users SET full_name = ?, active = ? WHERE id = ?').run(
    fullName ?? existing.full_name,
    active === undefined ? existing.active : active ? 1 : 0,
    req.params.id
  );
  if (password) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  }
  res.json({ ok: true });
});

/* ------------------------------------------------------ Attendance routes */

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}
function isValidDate(d) {
  return /^\d{4}-\d{2}-\d{2}$/.test(d || '');
}

app.get('/api/attendance', requireAuth, (req, res) => {
  const date = isValidDate(req.query.date) ? req.query.date : todayStr();
  let workerSql = `SELECT w.*, u.full_name AS foreman_name FROM workers w LEFT JOIN users u ON u.id = w.foreman_id WHERE w.active = 1`;
  const params = [];
  if (req.user.role === 'foreman') {
    workerSql += ' AND w.foreman_id = ?';
    params.push(req.user.id);
  } else if (req.query.foremanId) {
    workerSql += ' AND w.foreman_id = ?';
    params.push(req.query.foremanId);
  }
  workerSql += ' ORDER BY w.name';

  const workers = db.prepare(workerSql).all(...params);
  const attByWorker = new Map(db.prepare('SELECT * FROM attendance WHERE date = ?').all(date).map((a) => [a.worker_id, a]));

  const result = workers.map((w) => {
    const a = attByWorker.get(w.id);
    return {
      workerId: w.id,
      name: w.name,
      trade: w.trade,
      zone: w.zone,
      foremanName: w.foreman_name,
      status: a ? a.status : null,
      activity: a ? a.activity : null,
      duration: a ? a.duration : null,
      location: a ? a.location : null,
    };
  });

  res.json({ date, workers: result });
});

app.post('/api/attendance', requireAuth, (req, res) => {
  const { date, records } = req.body || {};
  if (!isValidDate(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  if (!Array.isArray(records) || records.length === 0) return res.status(400).json({ error: 'records must be a non-empty array' });

  let allowedWorkerIds = null;
  if (req.user.role === 'foreman') {
    allowedWorkerIds = new Set(db.prepare('SELECT id FROM workers WHERE foreman_id = ?').all(req.user.id).map((r) => r.id));
  }

  const upsert = db.prepare(`
    INSERT INTO attendance (worker_id, date, status, activity, duration, location, recorded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(worker_id, date) DO UPDATE SET
      status = excluded.status, activity = excluded.activity, duration = excluded.duration,
      location = excluded.location, recorded_by = excluded.recorded_by, recorded_at = datetime('now')
  `);

  const tx = db.transaction((rows) => {
    let written = 0;
    for (const r of rows) {
      if (!r.workerId || !['P', 'V', 'A'].includes(r.status)) continue;
      if (allowedWorkerIds && !allowedWorkerIds.has(r.workerId)) continue;
      upsert.run(r.workerId, date, r.status, r.activity || null, r.duration || null, r.location || null, req.user.id);
      written += 1;
    }
    return written;
  });

  res.json({ ok: true, written: tx(records) });
});

app.get('/api/attendance/history', requireAuth, (req, res) => {
  const { workerId, from, to } = req.query;
  if (!workerId) return res.status(400).json({ error: 'workerId is required' });
  if (req.user.role === 'foreman') {
    const w = db.prepare('SELECT foreman_id FROM workers WHERE id = ?').get(workerId);
    if (!w || w.foreman_id !== req.user.id) return res.status(403).json({ error: 'Not your crew' });
  }
  let sql = 'SELECT * FROM attendance WHERE worker_id = ?';
  const params = [workerId];
  if (isValidDate(from)) {
    sql += ' AND date >= ?';
    params.push(from);
  }
  if (isValidDate(to)) {
    sql += ' AND date <= ?';
    params.push(to);
  }
  sql += ' ORDER BY date DESC';
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/attendance/summary', requireAuth, (req, res) => {
  const date = isValidDate(req.query.date) ? req.query.date : todayStr();
  let sql = `SELECT w.zone AS zone, a.status AS status, COUNT(*) AS count FROM attendance a JOIN workers w ON w.id = a.worker_id WHERE a.date = ? AND w.active = 1`;
  const params = [date];
  if (req.user.role === 'foreman') {
    sql += ' AND w.foreman_id = ?';
    params.push(req.user.id);
  }
  sql += ' GROUP BY w.zone, a.status';
  const rows = db.prepare(sql).all(...params);

  let totalSql = `SELECT COUNT(*) AS c FROM workers w WHERE w.active = 1`;
  const totalParams = [];
  if (req.user.role === 'foreman') {
    totalSql += ' AND w.foreman_id = ?';
    totalParams.push(req.user.id);
  }
  res.json({ date, totalWorkers: db.prepare(totalSql).get(...totalParams).c, breakdown: rows });
});

app.get('/api/attendance/export', requireAuth, (req, res) => {
  const { date, from, to } = req.query;
  let sql = `
    SELECT a.date, w.name AS worker_name, w.trade, w.zone, a.status, a.activity, a.duration, a.location, u.full_name AS recorded_by
    FROM attendance a JOIN workers w ON w.id = a.worker_id LEFT JOIN users u ON u.id = a.recorded_by WHERE 1=1
  `;
  const params = [];
  if (isValidDate(date)) {
    sql += ' AND a.date = ?';
    params.push(date);
  } else {
    if (isValidDate(from)) {
      sql += ' AND a.date >= ?';
      params.push(from);
    }
    if (isValidDate(to)) {
      sql += ' AND a.date <= ?';
      params.push(to);
    }
  }
  if (req.user.role === 'foreman') {
    sql += ' AND w.foreman_id = ?';
    params.push(req.user.id);
  }
  sql += ' ORDER BY a.date DESC, w.name';
  const csv = stringify(db.prepare(sql).all(...params), { header: true });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="attendance-export.csv"');
  res.send(csv);
});

/* ------------------------------------------------------------- Static page */

app.use((req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => {
  console.log(`Site Attendance app listening on http://localhost:${PORT}`);
});
