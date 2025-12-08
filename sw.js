const CACHE_NAME = 'chiller-dashboard-v2';
const STATIC_ASSETS = [
  '/',
  '/dashboard',
  '/dashboard.html',
  '/admin.html',
  '/login.html',
  '/manifest.json',
  '/fanap.png',
  '/icon-192.svg',
  '/icon-512.svg',
  '/css/bootstrap.min.css',
  '/css/base-page.css',
  '/css/theme.css',
  '/css/rtl.css'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

function isDynamic(url) {
  try {
    const u = new URL(url);
    if (u.pathname.startsWith('/proxy')) return true; // never cache proxy traffic
    if (u.pathname.startsWith('/assets/data/')) return true; // network-first
    if (u.pathname.startsWith('/api/')) return true; // api should be network-first
    return false;
  } catch (_) { return false; }
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = req.url;
  let isApi = false;
  try { isApi = new URL(url).pathname.startsWith('/api/'); } catch(_) { isApi = false; }

  // Bypass non-GET requests
  if (req.method !== 'GET') return;

  // Network-first for dynamic endpoints
  if (isDynamic(url) || url.endsWith('.html')) {
    event.respondWith(
      fetch(req).then((res) => {
        if (!isApi) {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone)).catch(() => {});
        }
        return res;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // Cache-first for static assets
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (!isApi) {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone)).catch(() => {});
        }
        return res;
      });
    })
  );
});
