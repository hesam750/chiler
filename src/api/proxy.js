// Simple HTTP proxy for PLC endpoints used by dashboard.html via "/proxy?url=<...>"
// Restrictable via env: ALLOWED_PROXY_HOSTS (comma-separated host:port list), e.g. "1.2.3.4:8080,plc.example.com"
// Note: This forwards only HTTP/HTTPS. If the PLC requires non-HTTP protocols (e.g., Modbus/TCP), a different backend is needed.

const fetch = require('node-fetch');
const { URL } = require('url');

function getAllowedHosts() {
  const raw = process.env.ALLOWED_PROXY_HOSTS || '';
  return raw
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
}

function isAllowedHost(host) {
  const allowed = getAllowedHosts();
  if (allowed.length === 0) return true;
  const h = String(host || '').toLowerCase();
  return allowed.some(a => a === h);
}

module.exports = async (req, res) => {
  console.log(`[PROXY] Received request: ${req.method} ${req.url}`);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  const qs = (req.url.split('?')[1] || '');
  const params = new URLSearchParams(qs);
  const targetStr = params.get('url');
  console.log(`[PROXY] Target URL string: ${targetStr}`);

  if (!targetStr) {
    res.statusCode = 400;
    return res.end('Missing query parameter: url');
  }

  let target;
  try {
    target = new URL(targetStr);
    console.log(`[PROXY] Parsed Target URL: ${target.href}`);
  } catch (e) {
    console.error('[PROXY] Invalid URL error:', e);
    res.statusCode = 400;
    return res.end('Invalid URL');
  }

  if (!/^https?:$/.test(target.protocol)) {
    res.statusCode = 400;
    return res.end('Only http/https is supported');
  }

  if (!isAllowedHost(target.host)) {
    res.statusCode = 403;
    return res.end('Target host not allowed');
  }

  let body = undefined;
  if (req.method === 'POST') {
    body = await new Promise((resolve, reject) => {
      let acc = '';
      req.on('data', chunk => { acc += chunk; });
      req.on('end', () => resolve(acc));
      req.on('error', reject);
    });
    console.log(`[PROXY] POST body: ${body}`);
  }

  try {
    console.log(`[PROXY] Fetching: ${target.href}`);
    const upstream = await fetch(target.href, {
      method: req.method,
      headers: {
        'Content-Type': req.headers['content-type'] || (req.method === 'POST' ? 'application/x-www-form-urlencoded' : undefined),
        'Authorization': req.headers['authorization']
      },
      body: req.method === 'POST' ? body : undefined,
    });

    console.log(`[PROXY] Upstream status: ${upstream.status}`);
    const buf = Buffer.from(await upstream.arrayBuffer());
    console.log(`[PROXY] Upstream response length: ${buf.length}`);

    const ct = upstream.headers.get('content-type') || 'text/plain; charset=utf-8';
    res.statusCode = upstream.status;
    res.setHeader('Content-Type', ct);
    return res.end(buf);
  } catch (e) {
    console.error('[PROXY] Upstream fetch error:', e);
    res.statusCode = 502;
    return res.end('Upstream error: ' + (e && e.message ? e.message : String(e)));
  }
};