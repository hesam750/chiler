const jwt = require('jsonwebtoken');

const COOKIE_NAME = 'auth_token';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

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

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

  try {
    const token = parseCookies(req)[COOKIE_NAME];
    const payload = token ? verifyToken(token) : null;
    if (!payload) return res.status(401).json({ authenticated: false });
    return res.status(200).json({ authenticated: true, user: { username: payload.sub, role: payload.role || 'admin' } });
  } catch (e) {
    return res.status(500).json({ error: 'Server Error', details: String(e) });
  }
};