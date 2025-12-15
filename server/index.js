const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const proxy = require('./proxy');
const net = require('net');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const publicDir = path.join(__dirname, '..');

app.use('/proxy', (req, res) => proxy(req, res));

// Simple auth and CRUD for chillers
const AUTH_SECRET = process.env.AUTH_SECRET || 'dev-secret';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin@ch.fanap';
const USER_USER = process.env.USER_USER || 'user';
const USER_PASS = process.env.USER_PASS || 'user123';

const dataFile = path.join(publicDir, 'assets', 'data', 'dashboard.config.json');

function safeReadJSON(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const obj = JSON.parse(raw);
    return obj || {};
  } catch (e) {
    return {};
  }
}

function safeWriteJSON(filePath, obj) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function ensureConfigStructure() {
  const cfg = safeReadJSON(dataFile);
  if (!cfg.units || !Array.isArray(cfg.units)) cfg.units = [];
  if (!cfg.chillers || !Array.isArray(cfg.chillers)) cfg.chillers = [];
  if (!cfg.generators || !Array.isArray(cfg.generators)) cfg.generators = [];
  if (cfg.chillers.length) {
    cfg.chillers = cfg.chillers.map((c) => ({
      id: c.id || crypto.randomBytes(8).toString('hex'),
      name: String((c.name || '').trim() || 'بدون نام'),
      ip: String((c.ip || '').trim()),
      active: !!c.active,
    }));
    const seen = new Set();
    cfg.chillers = cfg.chillers.filter((c) => {
      const key = (c.ip ? ('ip:' + c.ip.toLowerCase()) : ('name:' + c.name.toLowerCase()));
      if (!c.ip && !c.name) return false;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  safeWriteJSON(dataFile, cfg);
  return cfg;
}

function parseCookies(cookieHeader) {
  const out = {};
  String(cookieHeader || '').split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('hex');
  return `${data}.${sig}`;
}
function verify(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (_) { return null; }
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.session;
  const payload = verify(token);
  return payload || { role: 'guest' };
}

function isAuthed(req){
  const s = getSession(req);
  return s && (s.role === 'admin' || s.role === 'user');
}
function requireAuth(req, res, next){
  if(isAuthed(req)) return next();
  res.redirect('/login');
}

function setSession(res, payload) {
  const token = sign(payload);
  const cookie = `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`;
  res.setHeader('Set-Cookie', cookie);
}

function clearSession(res) {
  res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
}

function requireAdmin(req, res, next) {
  const s = getSession(req);
  if (s && s.role === 'admin') return next();
  const wantsHtml = String(req.headers.accept||'').indexOf('text/html') > -1;
  const isApi = String(req.path||'').startsWith('/api');
  if (wantsHtml && req.method === 'GET' && !isApi) {
    return res.redirect('/login');
  }
  res.status(403).json({ error: 'forbidden' });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  let role = null;
  if (String(username) === ADMIN_USER && String(password) === ADMIN_PASS) role = 'admin';
  else if (String(username) === USER_USER && String(password) === USER_PASS) role = 'user';
  if (!role) return res.status(401).json({ ok: false });
  const payload = { role, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 };
  setSession(res, payload);
  res.json({ ok: true, role });
});

app.post('/api/logout', (req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const s = getSession(req);
  res.json({ role: s.role || 'guest' });
});

app.get('/api/chillers', (req, res) => {
  const cfg = ensureConfigStructure();
  res.json({ items: cfg.chillers });
});

app.post('/api/chillers', requireAdmin, (req, res) => {
  const { name, ip, active } = req.body || {};
  const cfg = ensureConfigStructure();
  const item = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(name || 'بدون نام'),
    ip: String(ip || ''),
    active: !!active,
  };
  cfg.chillers.push(item);
  safeWriteJSON(dataFile, cfg);
  res.json({ ok: true, item });
});

app.put('/api/chillers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, ip, active } = req.body || {};
  const cfg = ensureConfigStructure();
  const idx = cfg.chillers.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  const prev = cfg.chillers[idx];
  cfg.chillers[idx] = {
    id: prev.id,
    name: name != null ? String(name) : prev.name,
    ip: ip != null ? String(ip) : prev.ip,
    active: active != null ? !!active : prev.active,
  };
  safeWriteJSON(dataFile, cfg);
  res.json({ ok: true, item: cfg.chillers[idx] });
});

app.delete('/api/chillers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const cfg = ensureConfigStructure();
  const idx = cfg.chillers.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  const removed = cfg.chillers.splice(idx, 1)[0];
  safeWriteJSON(dataFile, cfg);
  res.json({ ok: true, item: removed });
});

app.get('/login', (req, res) => {
  const s = getSession(req);
  if(s && s.role === 'admin') return res.redirect('/admin');
  if(s && s.role === 'user') return res.redirect('/dashboard');
  res.sendFile(path.join(publicDir, 'login.html'));
});
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(publicDir, 'dashboard.html'));
});
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});
app.get('/dashboard.html', requireAuth, (req, res) => {
  res.sendFile(path.join(publicDir, 'dashboard.html'));
});
app.get('/admin.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});
app.get('/', (req, res) => {
  const s = getSession(req);
  if(s && s.role === 'admin') return res.redirect('/admin');
  if(s && s.role === 'user') return res.redirect('/dashboard');
  res.redirect('/login');
});

app.use(express.static(publicDir));

const port = process.env.PORT || 8000;
app.listen(port);
// (ensureConfigStructure defined earlier)

// Generators CRUD (similar to chillers)
// function genId() {
//   try { return crypto.randomBytes(8).toString('hex'); } catch(_) { return String(Date.now()); }
// }
// app.get('/api/generators', (req, res) => {
//   const cfg = ensureConfigStructure();
//   res.json({ items: cfg.generators });
// });
// app.post('/api/generators', requireAdmin, (req, res) => {
//   const { name, ip, active } = req.body || {};
//   const cfg = ensureConfigStructure();
//   const item = { id: genId(), name: String(name || 'ژنراتور'), ip: String(ip || ''), active: !!active };
//   cfg.generators.push(item);
//   safeWriteJSON(dataFile, cfg);
//   res.json({ ok: true, item });
// });
// app.put('/api/generators/:id', requireAdmin, (req, res) => {
//   const { id } = req.params;
//   const { name, ip, active } = req.body || {};
//   const cfg = ensureConfigStructure();
//   const idx = cfg.generators.findIndex((c) => c.id === id);
//   if (idx === -1) return res.status(404).json({ error: 'not_found' });
//   const prev = cfg.generators[idx];
//   cfg.generators[idx] = {
//     id: prev.id,
//     name: name != null ? String(name) : prev.name,
//     ip: ip != null ? String(ip) : prev.ip,
//     active: active != null ? !!active : prev.active,
//   };
//   safeWriteJSON(dataFile, cfg);
//   res.json({ ok: true, item: cfg.generators[idx] });
// });
// app.delete('/api/generators/:id', requireAdmin, (req, res) => {
//   const { id } = req.params;
//   const cfg = ensureConfigStructure();
//   const idx = cfg.generators.findIndex((c) => c.id === id);
//   if (idx === -1) return res.status(404).json({ error: 'not_found' });
//   const removed = cfg.generators.splice(idx, 1)[0];
//   safeWriteJSON(dataFile, cfg);
//   res.json({ ok: true, item: removed });
// });

// // Minimal Modbus TCP client for DSE8610 MKII
// function modbusReadHolding(ip, unitId, startAddr, qty) {
//   return new Promise((resolve, reject) => {
//     try {
//       const socket = new net.Socket();
//       const tid = Math.floor(Math.random() * 0xffff);
//       const buf = Buffer.alloc(12);
//       buf.writeUInt16BE(tid, 0); // Transaction ID
//       buf.writeUInt16BE(0, 2);   // Protocol ID
//       buf.writeUInt16BE(6, 4);   // Length
//       buf.writeUInt8(unitId || 1, 6); // Unit ID
//       buf.writeUInt8(3, 7);      // Function 3
//       buf.writeUInt16BE(startAddr, 8);
//       buf.writeUInt16BE(qty, 10);
//       let result = null; let done = false;
//       socket.setTimeout(5000);
//       socket.on('timeout', () => { if (!done) { done = true; try{ socket.destroy(); }catch(_){} reject(new Error('timeout')); } });
//       socket.on('error', (e) => { if (!done) { done = true; try{ socket.destroy(); }catch(_){} reject(e); } });
//       socket.connect(502, ip, () => socket.write(buf));
//       socket.on('data', (data) => {
//         try {
//           if (data.length < 9) return;
//           const fc = data.readUInt8(7);
//           if (fc !== 3) return;
//           const byteCount = data.readUInt8(8);
//           if (data.length < 9 + byteCount) return;
//           const regs = [];
//           for (let i = 0; i < byteCount / 2; i++) {
//             regs.push(data.readUInt16BE(9 + i * 2));
//           }
//           result = regs;
//           if (!done) { done = true; try{ socket.end(); }catch(_){} resolve(result); }
//         } catch (e) { if (!done) { done = true; try{ socket.destroy(); }catch(_){} reject(e); } }
//       });
//     } catch (e) { reject(e); }
//   });
// }
// function modbusWriteSingle(ip, unitId, addr, val) {
//   return new Promise((resolve, reject) => {
//     try {
//       const socket = new net.Socket();
//       const tid = Math.floor(Math.random() * 0xffff);
//       const buf = Buffer.alloc(12);
//       buf.writeUInt16BE(tid, 0);
//       buf.writeUInt16BE(0, 2);
//       buf.writeUInt16BE(6, 4);
//       buf.writeUInt8(unitId || 1, 6);
//       buf.writeUInt8(6, 7); // Function 6
//       buf.writeUInt16BE(addr, 8);
//       buf.writeUInt16BE(val, 10);
//       let done = false;
//       socket.setTimeout(5000);
//       socket.on('timeout', () => { if (!done) { done = true; try{ socket.destroy(); }catch(_){} reject(new Error('timeout')); } });
//       socket.on('error', (e) => { if (!done) { done = true; try{ socket.destroy(); }catch(_){} reject(e); } });
//       socket.connect(502, ip, () => socket.write(buf));
//       socket.on('data', () => { if (!done) { done = true; try{ socket.end(); }catch(_){} resolve(true); } });
//     } catch (e) { reject(e); }
//   });
// }

// function parseAddr(s) {
//   const n = Number(String(s||'').trim());
//   if (isNaN(n)) return null;
//   // If provided like 40001, convert to 0-based
//   return n >= 40001 ? (n - 40001) : n;
// }

// app.get('/api/dse8610/regs', (req, res) => {
//   const ip = String(req.query.ip||'').trim();
//   const addrs = String(req.query.addrs||'').split(',').map(parseAddr).filter((v) => v != null);
//   if (!ip || !addrs.length) return res.status(400).json({ error: 'bad_request' });
//   // Read in batches of up to 10
//   const unitId = Number(req.query.uid||1) || 1;
//   const promises = addrs.map((addr) => modbusReadHolding(ip, unitId, addr, 1).then((regs) => ({ addr, val: regs && regs[0] })));
//   Promise.allSettled(promises).then((results) => {
//     const out = {};
//     results.forEach((r, i) => { const a = addrs[i]; out[a] = (r.status === 'fulfilled') ? r.value.val : null; });
//     res.json({ ok: true, values: out });
//   }).catch((e) => res.status(500).json({ error: String(e||'read_error') }));
// });
// app.get('/api/dse8610/reg', (req, res) => {
//   const ip = String(req.query.ip||'').trim();
//   const addr = parseAddr(req.query.addr);
//   if (!ip || addr == null) return res.status(400).json({ error: 'bad_request' });
//   modbusReadHolding(ip, Number(req.query.uid||1)||1, addr, 1).then((regs) => {
//     res.json({ ok: true, value: regs && regs[0] });
//   }).catch((e) => res.status(500).json({ error: String(e||'read_error') }));
// });
// app.post('/api/dse8610/write', (req, res) => {
//   const ip = String(req.body && req.body.ip || '').trim();
//   const addr = parseAddr(req.body && req.body.addr);
//   const val = Number(req.body && req.body.val);
//   if (!ip || addr == null || isNaN(val)) return res.status(400).json({ error: 'bad_request' });
//   modbusWriteSingle(ip, Number(req.body && req.body.uid || 1)||1, addr, val).then(() => {
//     res.json({ ok: true });
//   }).catch((e) => res.status(500).json({ error: String(e||'write_error') }));
// });
