const CACHE_NAME = 'chiller-dashboard-v3';
const urlsToCache = [
  '/dashboard.html',
  '/css/bootstrap.min.css',
  '/css/base-page.css',
  '/css/base-component.css',
  '/lib/jquery.min.js',
  '/lib/bootstrap.min.js',
  '/lib/knockout-latest.js',
  '/lib/deviceengine.js',
  '/lib/cfield.app.js',
  '/fanap.png',
  '/favicon.ico',
  '/assets/data/dashboard.config.json',
  '/manifest.json'
];

// Install event - cache resources
self.addEventListener('install', event => {
  // Activate new SW immediately
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
      .catch(err => {
        console.log('Cache install failed:', err);
      })
  );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Return cached version or fetch from network
        if (response) {
          return response;
        }
        
        // Clone the request because it's a stream
        const fetchRequest = event.request.clone();
        
        return fetch(fetchRequest).then(response => {
          // Check if we received a valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          
          // Clone the response because it's a stream
          const responseToCache = response.clone();
          
          caches.open(CACHE_NAME)
            .then(cache => {
              cache.put(event.request, responseToCache);
            });
          
          return response;
        }).catch(() => {
          // If both cache and network fail, return offline page
          if (event.request.destination === 'document') {
            return caches.match('/dashboard.html');
          }
        });
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  // Take control of all clients right away
  self.clients.claim();
});

// Background sync for data updates
self.addEventListener('sync', event => {
  if (event.tag === 'background-sync') {
    event.waitUntil(doBackgroundSync());
  }
});

function doBackgroundSync() {
  // Sync data when connection is restored
  return fetch('/api/proxy?url=' + encodeURIComponent('https://assist-nutrition-disabled-architects.trycloudflare.com/pgd/getvar.csv'))
    .then(response => response.text())
    .then(data => {
      // Store updated data in cache
      return caches.open(CACHE_NAME).then(cache => {
        cache.put('/api/sync-data', new Response(data));
      });
    })
    .catch(err => console.log('Background sync failed:', err));
}