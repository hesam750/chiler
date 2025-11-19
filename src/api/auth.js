const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const COOKIE_NAME = 'auth_token';
// Static development credentials (predictable access)
const STATIC_CREDS = {
  admin: { username: 'admin', password: '123456' },
  user: { username: 'user', password: '1234' }
};

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const result = {};
  header.split(';').forEach((part) => {
    const [name, ...rest] = part.trim().split('=');
    if (!name) return;
    result[name] = decodeURIComponent(rest.join('=') || '');
  });
  return result;
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (_) { return null; }
}

function getRoleForCredentials(username, password) {
  const uname = String(username || '').trim().toLowerCase();
  const pwd = String(password || '').trim();
  const isProd = (process.env.NODE_ENV === 'production');

  // Prefer static creds first (for guaranteed dev login)
  if (uname === STATIC_CREDS.admin.username && pwd === STATIC_CREDS.admin.password) return 'admin';
  if (uname === STATIC_CREDS.user.username && pwd === STATIC_CREDS.user.password) return 'user';

  // Admin credentials
  const adminUser = String(process.env.ADMIN_USER || 'admin').toLowerCase();
  const adminPassHash = process.env.ADMIN_PASS_HASH;
  const adminPass = process.env.ADMIN_PASS || 'admin';
  if (uname === adminUser) {
    const passOk = adminPassHash ? bcrypt.compareSync(pwd, adminPassHash) : (pwd === adminPass);
    return passOk ? 'admin' : null;
  }
  // User credentials
  const userUser = String(process.env.USER_USER || 'user').toLowerCase();
  const userPassHash = process.env.USER_PASS_HASH;
  const userPass = process.env.USER_PASS || 'user';
  if (uname === userUser) {
    const passOkHash = userPassHash ? bcrypt.compareSync(pwd, userPassHash) : false;
    const passOkPlain = (pwd === userPass);
    const passOk = userPassHash ? (passOkHash || passOkPlain) : passOkPlain;
    return passOk ? 'user' : null;
  }
  return null;
}

router.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'نام کاربری و رمز عبور لازم است' });
  }
  const role = getRoleForCredentials(username, password);
  if (!role) {
    return res.status(401).json({ error: 'ورود نامعتبر' });
  }
  const token = jwt.sign({ sub: username, role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: !!process.env.COOKIE_SECURE,
    sameSite: 'lax',
    path: '/',
  });
  return res.json({ success: true, user: { username, role } });
});

router.post('/auth/logout', (req, res) => {
  res.cookie(COOKIE_NAME, '', {
    httpOnly: true,
    secure: !!process.env.COOKIE_SECURE,
    sameSite: 'lax',
    path: '/',
    expires: new Date(0),
  });
  return res.json({ success: true });
});

router.get('/auth/me', (req, res) => {
  const token = parseCookies(req)[COOKIE_NAME];
  const payload = token ? verifyToken(token) : null;
  if (!payload) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: { username: payload.sub, role: payload.role || 'admin' } });
});

function requireAdmin(req, res, next) {
  const token = parseCookies(req)[COOKIE_NAME];
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.role !== 'admin') return res.status(401).json({ error: 'Unauthorized' });
  req.user = payload;
  next();
}

module.exports = { router, requireAdmin };