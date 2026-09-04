const CACHE_NAME = 'supporthub-v1';
const STATIC_ASSETS = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Push ─────────────────────────────────────────────────────────────
//
// Support is answered only in this dashboard now, so a missed notification is
// a support request nobody has seen. The payload is JSON from the server; a
// push with an unreadable body still shows something rather than nothing,
// because a silent failure here is indistinguishable from no tickets.
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data && e.data.text ? e.data.text() : '' }; }
  const title = d.title || 'Support Dashboard';
  e.waitUntil(
    self.registration.showNotification(title, {
      body: d.body || 'You have a new support message.',
      icon: '/icon-192.svg',
      badge: '/icon-192.svg',
      data: { url: d.url || '/' },
      // Collapses repeats from a burst into one entry rather than a stack of
      // near-identical notifications.
      tag: 'support-ticket',
      renotify: true,
    })
  );
});

// Focus an already-open dashboard rather than opening a second copy of it.
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if ('focus' in c) { c.navigate(url); return c.focus(); }
      }
      return clients.openWindow(url);
    })
  );
});

self.addEventListener('fetch', e => {
  // Network-first for API calls, cache-first for static assets
  if (e.request.url.includes('/api/')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
  } else {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
  }
});
