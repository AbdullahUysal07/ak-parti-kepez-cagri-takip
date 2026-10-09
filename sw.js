self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
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
