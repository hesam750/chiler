// Serverless function for /api/proxy and /proxy on Vercel
// Proxies GET requests to allowed PLC endpoints

const { URL } = require('url');

function isHostAllowed(targetUrl) {
  const allowed = (process.env.ALLOWED_PROXY_HOSTS || '').trim();
  if (!allowed) return true; // allow all if not specified
  const set = new Set(allowed.split(',').map((s) => s.trim()).filter(Boolean));
  try {
    const u = new URL(targetUrl);
    return set.has(u.hostname);
  } catch (_) {
    return false;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    const q = req.query || {};
    const rawUrl = q.url || q.u || q.target;
    if (!rawUrl) return res.status(400).json({ error: 'Missing url parameter' });
    if (!/^https?:\/\//i.test(rawUrl)) return res.status(400).json({ error: 'Invalid url scheme' });
    if (!isHostAllowed(rawUrl)) return res.status(403).json({ error: 'Host not allowed' });

    const response = await fetch(rawUrl, { method: 'GET' });
    const contentType = response.headers.get('content-type') || 'text/plain';
    const body = await response.text();
    res.setHeader('Content-Type', contentType);
    return res.status(response.status).send(body);
  } catch (e) {
    return res.status(502).json({ error: 'Upstream fetch failed', details: String(e) });
  }
};