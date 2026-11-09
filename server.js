const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
// Set JWT_SECRET in production, otherwise everyone is signed out on each restart.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;

/* ---------- Database ---------- */
const db = new Database(path.join(__dirname, 'lms.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student',
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  reset_token_hash TEXT,
  reset_expires INTEGER
)`);
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const pw = process.env.SEED_PASSWORD || 'Welcome123!';
  db.prepare('INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)')
    .run('student', 'student@example.com', bcrypt.hashSync(pw, 12), 'student');
  console.log('Demo user created -> username: student  password:', pw, '(change this!)');
}
const DUMMY_HASH = bcrypt.hashSync('timing-guard', 12); // equalises timing for unknown users

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' } });

function auth(req, res, next) {
  try { req.user = jwt.verify(req.cookies.token, JWT_SECRET); next(); }
  catch { req.accepts('html') && !req.path.startsWith('/api') ? res.redirect('/login.html') : res.status(401).json({ error: 'Not signed in' }); }
}

/* ---------- Auth API ---------- */
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password, remember } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username.trim(), username.trim());
  if (user && user.locked_until > Date.now())
    return res.status(423).json({ error: 'Account temporarily locked. Try again in a few minutes.' });

  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) {
    if (user) {
      const fails = user.failed_attempts + 1;
      db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?')
        .run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0, user.id);
    }
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  db.prepare('UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?').run(user.id);
  const ttl = remember ? 30 * 24 * 3600 : 8 * 3600;
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: ttl });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: IS_PROD, maxAge: ttl * 1000 });
  res.json({ redirect: '/dashboard' });
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));

app.post('/api/auth/forgot', loginLimiter, (req, res) => {
  const generic = { message: 'If that email is registered, a reset link has been sent.' };
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  const user = email && db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('UPDATE users SET reset_token_hash=?, reset_expires=? WHERE id=?')
      .run(crypto.createHash('sha256').update(token).digest('hex'), Date.now() + 30 * 60 * 1000, user.id);
    // TODO: send by email (Nodemailer/SendGrid). Logged for development only.
    console.log(`Password reset link for ${email}: http://localhost:${PORT}/reset-password.html?token=${token}`);
  }
  res.json(generic); // same reply whether or not the email exists
});

/* ---------- Pages ---------- */
app.get('/dashboard', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(PORT, () => console.log(`LMS running at http://localhost:${PORT}`));
