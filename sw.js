self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

// Uygulama olarak kurulabilmek için gereken basit ağ katmanı: sayfalar her zaman
// internetten alınır (eski sürüm takılı kalmaz); bağlantı yoksa kısa bir uyarı gösterilir.
self.addEventListener('fetch', event => {
  if (event.request.mode !== 'navigate') return;
  event.respondWith(fetch(event.request).catch(() => new Response(
    '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bağlantı yok</title><body style="font-family:-apple-system,Segoe UI,Arial;display:grid;place-items:center;min-height:100vh;margin:0;background:#123c7c;color:#fff;text-align:center;padding:20px"><div><h2>İnternet bağlantısı yok</h2><p>Bağlantı gelince sayfayı yenileyin.</p><button onclick="location.reload()" style="font:inherit;padding:12px 20px;border:0;border-radius:10px;background:#f28c00;color:#fff;font-weight:700">Yeniden dene</button></div>',
    { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
});

self.addEventListener('push', event => {
  event.waitUntil((async () => {
    let data = {};
    try {
      data = event.data ? event.data.json() : {};
    } catch (error) {
      data = { title: 'AK Parti Kepez', body: event.data ? event.data.text() : '' };
    }

    if (!data.body) {
      try {
        const response = await fetch('https://ak-parti-kepez-push.aytride.workers.dev/latest?t=' + Date.now(), { cache: 'no-store' });
        if (response.ok) data = await response.json();
      } catch (error) {
        data = {};
      }
    }

    const title = data.title || 'AK Parti Kepez';
    const options = {
      body: data.body || 'Yeni bildirim var.',
      icon: './icon-180.png',
      badge: './icon-180.png',
      data: { url: data.url || './' },
      requireInteraction: true
    };
    await self.registration.showNotification(title, options);
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url ? event.notification.data.url : './';
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const client of list) {
      if ('focus' in client) return client.focus();
    }
    return clients.openWindow(url);
  }));
});
