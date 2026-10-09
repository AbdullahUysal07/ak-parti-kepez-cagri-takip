const encoder = new TextEncoder();

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders() }
  });
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256Hex(text) {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importVapidPrivateKey(privateKey, publicKey) {
  const d = base64UrlToBytes(privateKey);
  const publicRaw = base64UrlToBytes(publicKey);
  const x = bytesToBase64Url(publicRaw.slice(1, 33));
  const y = bytesToBase64Url(publicRaw.slice(33, 65));
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x, y, d: bytesToBase64Url(d), ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

async function signJwt(env, audience) {
  const header = bytesToBase64Url(encoder.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = bytesToBase64Url(encoder.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com'
  })));
  const token = `${header}.${payload}`;
  const key = await importVapidPrivateKey(env.VAPID_PRIVATE_KEY, env.VAPID_PUBLIC_KEY);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(token));
  return `${token}.${bytesToBase64Url(ecdsaToJose(new Uint8Array(signature)))}`;
}

function ecdsaToJose(signature) {
  if (signature.length === 64) return signature;
  if (signature[0] !== 0x30) return signature;
  let offset = 2;
  if (signature[offset] !== 0x02) return signature;
  let rLen = signature[offset + 1];
  let r = signature.slice(offset + 2, offset + 2 + rLen);
  offset = offset + 2 + rLen;
  if (signature[offset] !== 0x02) return signature;
  let sLen = signature[offset + 1];
  let s = signature.slice(offset + 2, offset + 2 + sLen);
  if (r.length > 32) r = r.slice(r.length - 32);
  if (s.length > 32) s = s.slice(s.length - 32);
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

async function encryptPayload(subscription, payload) {
  const userPublicKey = base64UrlToBytes(subscription.keys.p256dh);
  const authSecret = base64UrlToBytes(subscription.keys.auth);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const localKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const localPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', localKeys.publicKey));
  const remotePublic = await crypto.subtle.importKey('raw', userPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: remotePublic }, localKeys.privateKey, 256));

  const prkKey = await crypto.subtle.importKey('raw', authSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const ikm = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, prkKey, sharedSecret));
  const ikmKey = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const prk = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, ikmKey, ikm));

  const context = concatBytes(
    encoder.encode('P-256\0'),
    uint16(userPublicKey.length),
    userPublicKey,
    uint16(localPublicRaw.length),
    localPublicRaw
  );
  const keyInfo = concatBytes(encoder.encode('Content-Encoding: aes128gcm\0'), context);
  const nonceInfo = concatBytes(encoder.encode('Content-Encoding: nonce\0'), context);
  const prkKey2 = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const keyMaterial = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, prkKey2, concatBytes(keyInfo, new Uint8Array([1]))));
  const nonceMaterial = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, prkKey2, concatBytes(nonceInfo, new Uint8Array([1]))));
  const key = await crypto.subtle.importKey('raw', keyMaterial.slice(0, 16), { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = nonceMaterial.slice(0, 12);
  const plaintext = concatBytes(encoder.encode(JSON.stringify(payload)), new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plaintext));
  const header = concatBytes(salt, uint32(4096), new Uint8Array([localPublicRaw.length]), localPublicRaw);
  return concatBytes(header, ciphertext);
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function uint32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function uint16(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value);
  return out;
}

function originFromEndpoint(endpoint) {
  const url = new URL(endpoint);
  return `${url.protocol}//${url.host}`;
}

async function sendPush(env, subscription) {
  const audience = originFromEndpoint(subscription.endpoint);
  const jwt = await signJwt(env, audience);
  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      TTL: '86400',
      Authorization: `WebPush ${jwt}`,
      'Crypto-Key': `p256ecdsa=${env.VAPID_PUBLIC_KEY}`
    }
  });
}

async function getAnnouncements(env) {
  return (await env.SUBSCRIPTIONS.get('__announcements__', 'json')) || [];
}

async function putAnnouncements(env, announcements) {
  await env.SUBSCRIPTIONS.put('__announcements__', JSON.stringify(announcements.slice(0, 100)));
}

function upsertPerson(list, body) {
  const username = String(body.username || '').trim();
  if (!username) return list || [];
  const next = (list || []).filter(item => item.username !== username);
  next.push({ username, name: body.name || username, at: new Date().toISOString() });
  return next;
}

async function requireAdmin(request, env) {
  const expected = env.ADMIN_TOKEN;
  const actual = request.headers.get('Authorization') || '';
  return expected && actual === `Bearer ${expected}`;
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return json({ ok: true });
    }

    if (url.pathname === '/latest') {
      const latest = await env.SUBSCRIPTIONS.get('__latest_notification__', 'json');
      return json(latest || { title: 'AK Parti Kepez', body: 'Yeni bildirim var.', url: 'https://abdullahuysal07.github.io/ak-parti-kepez-cagri-takip/' });
    }

    if (url.pathname === '/announcements' && request.method === 'GET') {
      const announcements = await getAnnouncements(env);
      return json({ ok: true, announcements });
    }

    if (url.pathname === '/announcements' && request.method === 'POST') {
      if (!(await requireAdmin(request, env))) return json({ error: 'unauthorized' }, 401);
      const body = await request.json();
      const text = String(body.body || '').trim();
      if (!text) return json({ error: 'body_required' }, 400);
      const announcements = await getAnnouncements(env);
      const announcement = {
        id: crypto.randomUUID(),
        body: text,
        authorName: body.authorName || 'Hasan Demir',
        createdAt: new Date().toISOString(),
        reads: [],
        likes: []
      };
      announcements.unshift(announcement);
      await putAnnouncements(env, announcements);
      await env.SUBSCRIPTIONS.put('__latest_notification__', JSON.stringify({
        title: 'Yeni duyuru var',
        body: text,
        url: body.url || 'https://abdullahuysal07.github.io/ak-parti-kepez-cagri-takip/',
        sentAt: new Date().toISOString()
      }));
      const list = await env.SUBSCRIPTIONS.list();
      let sent = 0;
      let failed = 0;
      for (const key of list.keys) {
        if (key.name.startsWith('__')) continue;
        const saved = await env.SUBSCRIPTIONS.get(key.name, 'json');
        if (!saved || !saved.subscription) continue;
        const res = await sendPush(env, saved.subscription);
        if (res.ok) sent += 1;
        else {
          failed += 1;
          if (res.status === 404 || res.status === 410) await env.SUBSCRIPTIONS.delete(key.name);
        }
      }
      return json({ ok: true, announcement, sent, failed });
    }

    if (url.pathname === '/announcements/read' && request.method === 'POST') {
      const body = await request.json();
      const announcements = await getAnnouncements(env);
      const item = announcements.find(a => a.id === body.announcementId);
      if (!item) return json({ error: 'not_found' }, 404);
      item.reads = upsertPerson(item.reads, body);
      await putAnnouncements(env, announcements);
      return json({ ok: true });
    }

    if (url.pathname === '/announcements/like' && request.method === 'POST') {
      const body = await request.json();
      const announcements = await getAnnouncements(env);
      const item = announcements.find(a => a.id === body.announcementId);
      if (!item) return json({ error: 'not_found' }, 404);
      item.likes = upsertPerson(item.likes, body);
      item.reads = upsertPerson(item.reads, body);
      await putAnnouncements(env, announcements);
      return json({ ok: true });
    }

    if (url.pathname === '/subscribe' && request.method === 'POST') {
      const body = await request.json();
      if (!body.subscription || !body.subscription.endpoint) return json({ error: 'subscription_missing' }, 400);
      const id = await sha256Hex(body.subscription.endpoint);
      await env.SUBSCRIPTIONS.put(id, JSON.stringify({
        subscription: body.subscription,
        username: body.username || '',
        createdAt: new Date().toISOString()
      }));
      return json({ ok: true, id });
    }

    if (url.pathname === '/send' && request.method === 'POST') {
      if (!(await requireAdmin(request, env))) return json({ error: 'unauthorized' }, 401);
      const body = await request.json();
      const payload = {
        title: body.title || 'AK Parti Kepez',
        body: body.body || 'Yeni bildirim var.',
        url: body.url || 'https://abdullahuysal07.github.io/ak-parti-kepez-cagri-takip/'
      };
      await env.SUBSCRIPTIONS.put('__latest_notification__', JSON.stringify({ ...payload, sentAt: new Date().toISOString() }));
      const list = await env.SUBSCRIPTIONS.list();
      let sent = 0;
      let failed = 0;
      const failures = [];
      for (const key of list.keys) {
        if (key.name.startsWith('__')) continue;
        const saved = await env.SUBSCRIPTIONS.get(key.name, 'json');
        if (!saved || !saved.subscription) continue;
        const res = await sendPush(env, saved.subscription);
        if (res.ok) sent += 1;
        else {
          failed += 1;
          failures.push({ status: res.status, text: await res.text().catch(() => '') });
          if (res.status === 404 || res.status === 410) await env.SUBSCRIPTIONS.delete(key.name);
        }
      }
      return json({ ok: true, sent, failed, failures: failures.slice(0, 5) });
    }

    return json({ error: 'not_found' }, 404);
  }
};
