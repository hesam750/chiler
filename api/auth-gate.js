// Server-side auth gate: redirects unauthenticated users to login with `next`
// Usage via rewrites: /admin -> /api/auth-gate.js?dest=/src/admin.html&role=admin&next=/admin

const jwt = require('jsonwebtoken');

function parseCookies(req){
  const header = req.headers && req.headers.cookie || '';
  return header.split(';').reduce((acc, part)=>{
    const idx = part.indexOf('=');
    if(idx > -1){ const k = part.slice(0, idx).trim(); const v = part.slice(idx+1).trim(); acc[k] = decodeURIComponent(v); }
    return acc;
  }, {});
}

function getQuery(req){
  try {
    const u = new URL(req.url, 'http://local');
    const params = Object.fromEntries(u.searchParams.entries());
    return params;
  } catch { return {}; }
}

module.exports = async (req, res) => {
  // only allow GET/HEAD/OPTIONS
  if(req.method === 'OPTIONS'){ res.statusCode = 204; return res.end(); }
  if(req.method !== 'GET' && req.method !== 'HEAD'){ res.statusCode = 405; return res.end('Method Not Allowed'); }

  const { dest = '/src/dashboard.html', role, next } = getQuery(req);
  const cookies = parseCookies(req);
  const token = cookies['auth_token'];

  const redirect = (location) => {
    res.statusCode = 302;
    res.setHeader('Location', location);
    res.end();
  };

  if(!token){
    const loginUrl = '/login' + (next ? ('?next=' + encodeURIComponent(next)) : '');
    return redirect(loginUrl);
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    const userRole = (payload && payload.user && payload.user.role) || 'user';

    if(role && role !== userRole){
      // role mismatch: send to dashboard (or login if you prefer)
      return redirect('/dashboard');
    }

    return redirect(dest);
  } catch(err){
    const loginUrl = '/login' + (next ? ('?next=' + encodeURIComponent(next)) : '');
    return redirect(loginUrl);
  }
};