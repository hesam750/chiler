const { URL } = require('url');

function getAllowedHosts() {
  const raw = process.env.ALLOWED_PROXY_HOSTS || '';
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

function isAllowedHost(host) {
  const allowed = getAllowedHosts();
  if (allowed.length === 0) return true;
  const h = String(host || '').toLowerCase();
  return allowed.some(a => a === h);
}

async function fetchWrap(url, opts) {
  if (typeof fetch === 'function') return fetch(url, opts);
  const { default: f } = await import('node-fetch');
  return f(url, opts);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }

  const qs = (req.url.split('?')[1] || '');
  const params = new URLSearchParams(qs);
  const targetStr = params.get('url');
  if (!targetStr) { res.statusCode = 400; return res.end('Missing query parameter: url'); }

  let target;
  try { target = new URL(targetStr); } catch (e) { res.statusCode = 400; return res.end('Invalid URL'); }
  if (!/^https?:$/.test(target.protocol)) { res.statusCode = 400; return res.end('Only http/https is supported'); }
  if (!isAllowedHost(target.host)) { res.statusCode = 403; return res.end('Target host not allowed'); }

  let body = undefined;
  if (req.method === 'POST') {
    body = await new Promise((resolve, reject) => {
      let acc = '';
      req.on('data', chunk => { acc += chunk; });
      req.on('end', () => resolve(acc));
      req.on('error', reject);
    });
  }

  try {
    const upstream = await fetchWrap(target.href, {
      method: req.method,
      headers: { 'Content-Type': req.headers['content-type'] || (req.method === 'POST' ? 'application/x-www-form-urlencoded' : undefined) },
      body: req.method === 'POST' ? body : undefined,
    });
    const ct = upstream.headers.get('content-type') || 'text/plain; charset=utf-8';
    res.statusCode = upstream.status;
    res.setHeader('Content-Type', ct);
    const buf = Buffer.from(await upstream.arrayBuffer());
    return res.end(buf);
  } catch (e) {
    res.statusCode = 502;
    return res.end('Upstream error: ' + (e && e.message ? e.message : String(e)));
  }
};