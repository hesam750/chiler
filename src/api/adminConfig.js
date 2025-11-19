const express = require('express');
const fs = require('fs');
const path = require('path');
const { requireAdmin } = require('./auth.js');

const router = express.Router();

// Store admin config under src/assets/admin/config.json
const CONFIG_PATH = path.resolve(__dirname, '../assets/admin/config.json');

function ensureDir(p) {
  try { fs.mkdirSync(p, { recursive: true }); } catch (_) {}
}

function readConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return { pollingMs: 1000, deviceUrl: null, units: [] };
  }
}

function writeConfig(obj) {
  ensureDir(path.dirname(CONFIG_PATH));
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(obj, null, 2), 'utf8');
}

router.get('/admin/config', requireAdmin, (req, res) => {
  const cfg = readConfig();
  res.json(cfg);
});

router.post('/admin/config', requireAdmin, (req, res) => {
  const body = req.body || {};
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const cfg = {
    pollingMs: typeof body.pollingMs === 'number' ? body.pollingMs : 1000,
    deviceUrl: body.deviceUrl || null,
    units: Array.isArray(body.units)
      ? body.units.map((u) => ({
          name: String(u.name || ''),
          maintenance: !!u.maintenance,
          disabled: !!u.disabled,
          deviceUrl: typeof u.deviceUrl === 'string' ? u.deviceUrl : null,
          vars: u.vars || {},
        }))
      : [],
  };

  try {
    writeConfig(cfg);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Write failed', details: String(e) });
  }
});

module.exports = router;