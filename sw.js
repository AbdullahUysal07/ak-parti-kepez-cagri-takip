self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (error) {
    data = { title: 'AK Parti Kepez', body: event.data ? event.data.text() : 'Yeni bildirim var.' };
  }

  const title = data.title || 'AK Parti Kepez';
  const options = {
    body: data.body || 'Yeni bildirim var.',
    icon: data.icon || './',
    badge: data.badge || './',
    data: { url: data.url || './' },
    requireInteraction: true
  };
  event.waitUntil(self.registration.showNotification(title, options));
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
