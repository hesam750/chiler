const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT ? Number(process.env.PORT) : 8006;
const ROOT = process.cwd();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.map': 'application/json; charset=utf-8'
};

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

function serveFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const type = MIME[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        return send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
      }
      return send(res, 500, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Internal Server Error');
    }
    send(res, 200, { 'Content-Type': type }, data);
  });
}

const server = http.createServer((req, res) => {
  try {
    const urlPath = new URL(req.url, 'http://localhost').pathname;
    let safe = path.normalize(urlPath).replace(/^([.]{1,2}[\\/])+/, '');
    let filePath = path.join(ROOT, safe);

    // Prevent path traversal
    if (!filePath.startsWith(ROOT)) {
      return send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Forbidden');
    }

    fs.stat(filePath, (err, stat) => {
      if (err) {
        return send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
      }
      if (stat.isDirectory()) {
        const indexFile = path.join(filePath, 'index.html');
        return fs.existsSync(indexFile)
          ? serveFile(res, indexFile)
          : send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Directory listing forbidden');
      }
      serveFile(res, filePath);
    });
  } catch (e) {
    send(res, 500, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Internal Server Error');
  }
});

server.listen(PORT, () => {
  console.log(`Dev server running at http://localhost:${PORT}/`);
});