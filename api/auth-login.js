const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const COOKIE_NAME = 'auth_token';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function getRoleForCredentials(username, password) {
  // Admin
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPassHash = process.env.ADMIN_PASS_HASH;
  const adminPass = process.env.ADMIN_PASS || 'admin';
  if (username === adminUser) {
    if (adminPassHash) return bcrypt.compareSync(password, adminPassHash) ? 'admin' : null;
    return password === adminPass ? 'admin' : null;
  }
  // User
  const userUser = process.env.USER_USER || 'user';
  const userPassHash = process.env.USER_PASS_HASH;
  const userPass = process.env.USER_PASS || 'user';
  if (username === userUser) {
    if (userPassHash) return bcrypt.compareSync(password, userPassHash) ? 'user' : null;
    return password === userPass ? 'user' : null;
  }
  return null;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'نام کاربری و رمز عبور لازم است' });
    }
    const role = getRoleForCredentials(username, password);
    if (!role) {
      return res.status(401).json({ error: 'ورود نامعتبر' });
    }
    const token = jwt.sign({ sub: username, role }, JWT_SECRET, { expiresIn: '7d' });
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax${process.env.COOKIE_SECURE ? '; Secure' : ''}`);
    return res.status(200).json({ success: true, user: { username, role } });
  } catch (e) {
    return res.status(500).json({ error: 'Server Error', details: String(e) });
  }
};