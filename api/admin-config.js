// Serverless function for /api/admin/config on Vercel
// Uses Vercel KV if available; falls back to local file when running outside Vercel

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const DEFAULT_CFG = { pollingMs: 1000, deviceUrl: null, units: [] };
const LOCAL_CONFIG_PATH = path.resolve('src/assets/admin/config.json');

function normalizeConfig(body) {
  const b = body || {};
  return {
    pollingMs: typeof b.pollingMs === 'number' ? b.pollingMs : 1000,
    deviceUrl: b.deviceUrl || null,
    units: Array.isArray(b.units)
      ? b.units.map((u) => ({
          name: String((u && u.name) || ''),
          maintenance: !!(u && u.maintenance),
          disabled: !!(u && u.disabled),
          deviceUrl: typeof (u && u.deviceUrl) === 'string' ? u.deviceUrl : null,
          vars: (u && u.vars) || {},
        }))
      : [],
  };
}

async function getKV() {
  try {
    // Lazy require to avoid local dev failing if package not installed
    const { kv } = require('@vercel/kv');
    return kv;
  } catch (e) {
    return null;
  }
}

async function readConfig() {
  // On Vercel, prefer KV
  if (process.env.VERCEL) {
    const kv = await getKV();
    if (kv) {
      const data = await kv.get('admin:config');
      return data || DEFAULT_CFG;
    }
  }
  // Local file fallback
  try {
    const raw = fs.readFileSync(LOCAL_CONFIG_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return DEFAULT_CFG;
  }
}

async function writeConfig(obj) {
  // On Vercel, prefer KV for persistence
  if (process.env.VERCEL) {
    const kv = await getKV();
    if (kv) {
      await kv.set('admin:config', obj);
      return;
    }
  }
  // Local file fallback
  fs.mkdirSync(path.dirname(LOCAL_CONFIG_PATH), { recursive: true });
  fs.writeFileSync(LOCAL_CONFIG_PATH, JSON.stringify(obj, null, 2), 'utf8');
}

// --- Auth helpers for Vercel function ---
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
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    if (req.method === 'GET') {
      // Only admin can read admin config via API
      const token = parseCookies(req)[COOKIE_NAME];
      const payload = token ? verifyToken(token) : null;
      if (!payload || payload.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const cfg = await readConfig();
      return res.status(200).json(cfg);
    }
    if (req.method === 'POST') {
      // Require admin auth for writes
      const token = parseCookies(req)[COOKIE_NAME];
      const payload = token ? verifyToken(token) : null;
      if (!payload || payload.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const cfg = normalizeConfig(req.body);
      await writeConfig(cfg);
      return res.status(200).json({ success: true });
    }
    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (e) {
    return res.status(500).json({ error: 'Server Error', details: String(e) });
  }
};