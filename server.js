const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
// Set JWT_SECRET in production, otherwise everyone is signed out on each restart.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;

/* ---------- Database (XAMPP MySQL defaults; override with environment variables) ---------- */
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'lms_db',
  waitForConnections: true,
  connectionLimit: 10,
});
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
// Catches errors from async routes so the server never crashes on a bad query
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch((err) => {
  console.error(err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

/* ---------- Auth API ---------- */
app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const { username, password, remember } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });

  const id = username.trim();
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1', [id, id]);
  const user = rows[0];
  if (user && Number(user.locked_until) > Date.now())
    return res.status(423).json({ error: 'Account temporarily locked. Try again in a few minutes.' });

  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) {
    if (user) {
      const fails = user.failed_attempts + 1, lock = fails >= MAX_FAILS;
      await pool.execute('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
        [lock ? 0 : fails, lock ? Date.now() + LOCK_MS : 0, user.id]);
    }
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  await pool.execute('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?', [user.id]);
  const ttl = remember ? 30 * 24 * 3600 : 8 * 3600;
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: ttl });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: IS_PROD, maxAge: ttl * 1000 });
  res.json({ redirect: '/dashboard' });
}));

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));

app.post('/api/auth/forgot', loginLimiter, wrap(async (req, res) => {
  const generic = { message: 'If that email is registered, a reset link has been sent.' };
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  const [rows] = email ? await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]) : [[]];
  if (rows[0]) {
    const token = crypto.randomBytes(32).toString('hex');
    await pool.execute('UPDATE users SET reset_token_hash = ?, reset_expires = ? WHERE id = ?',
      [crypto.createHash('sha256').update(token).digest('hex'), Date.now() + 30 * 60 * 1000, rows[0].id]);
    // TODO: send by email (Nodemailer/SendGrid). Logged for development only.
    console.log(`Password reset link for ${email}: http://localhost:${PORT}/reset-password.html?token=${token}`);
  }
  res.json(generic); // same reply whether or not the email exists
}));

/* ---------- Pages ---------- */
app.get('/dashboard', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.get('/', (req, res) => res.redirect('/login.html'));

/* ---------- Start (checks the database first) ---------- */
pool.query('SELECT 1').then(() => {
  app.listen(PORT, () => console.log(`LMS running at http://localhost:${PORT}  (connected to MySQL database "${process.env.DB_NAME || 'lms_db'}")`));
}).catch((err) => {
  console.error('Cannot connect to MySQL:', err.code || err.message);
  console.error('Check that XAMPP MySQL is started (green) and that the database "lms_db" exists.');
  process.exit(1);
});
