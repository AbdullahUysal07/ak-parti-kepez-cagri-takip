const encoder = new TextEncoder();

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
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


// ---------------------------------------------------------------------------
// Depolama anahtarları (Cloudflare KV - SUBSCRIPTIONS)
// Kişisel veriler (üyeler, başkanlar, kullanıcılar) artık sayfada değil, burada
// tutulur ve yalnızca giriş yapmış ve yetkili kullanıcıya gönderilir.
// ---------------------------------------------------------------------------
const DEFAULT_PASSWORD = 'kepez2026.';
const ADMIN_USERNAME = 'hasan_demir';
// Tam yetkili kullanıcılar (Hasan Demir paneliyle aynı yetkiler)
const ADMIN_USERNAMES = ['hasan_demir', 'ilkaygunesss'];
const USER_TITLES = { hasan_demir: 'İlçe Başkanı', ilkaygunesss: 'İlçe Teşkilat Başkanı' };
const ANALYSIS_USERS = ['ilkaygunesss', 'huseyin_ilkay_gunes'];
const REF_SHARDS = 64;
const MAX_VISIT_IMAGES = 5;
const sandikKey = hood => `__sandik__:${hood}`;
const SANDIK_ROLES = ['asil', 'yedek', 'musahitAsil', 'musahitYedek'];
const TOKEN_DAYS = 120;
const K = {
  secret: '__server_secret__',
  users: '__users__',
  overrides: '__access_overrides__',
  leaders: '__leaders__',
  org: '__org__',
  requests: '__requests__',
  memberIndex: '__members_index__',
  memberEdits: '__member_edits__',
  logs: '__call_logs__',
  locations: '__user_locations__',
  announcements: '__announcements__',
  latest: '__latest_notification__'
};
const memberHoodKey = (version, hood) => `__members__:${version}:${hood}`;
const memberRefKey = (version, shard) => `__members_ref__:${version}:${shard}`;
const memberNameKey = (version, shard) => `__members_name__:${version}:${shard}`;
// Doğum günü dizini: yılın haftasına göre 53 parça; içinde { "MM-GG": [[mahalle, id, ad, telefon, [referans anahtarları]]] }
const memberBdKey = (version, week) => `__members_bd__:${version}:${week}`;
function bdWeek(mmdd) {
  const [m, d] = String(mmdd).split('-').map(Number);
  const doy = Math.floor((Date.UTC(2001, (m || 1) - 1, Math.min(d || 1, m === 2 ? 28 : 31)) - Date.UTC(2001, 0, 1)) / 864e5);
  return Math.min(52, Math.floor(doy / 7));
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function textResponse(text, status = 200) {
  return new Response(text, { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders() } });
}

// Türkçe karakterleri sadeleştirip kullanıcı adı biçimine çevirir (istemcideki normalizeUser ile aynı).
function normalizeUser(v) {
  return String(v || '').trim().toLocaleLowerCase('tr-TR')
    .replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/[ıi]/g, 'i').replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u')
    .replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}
// Referans isim eşleştirmesi için ad normalleştirme (istemcideki refKey ile aynı).
function refKey(v) {
  return normalizeUser(v).replace(/_/g, ' ');
}
// FNV-1a: referans adını parçaya (shard) dağıtmak için (istemcideki refShard ile aynı).
function refShard(name) {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) { h ^= name.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h % REF_SHARDS;
}

async function getJson(env, key, fallback) {
  const v = await env.SUBSCRIPTIONS.get(key, 'json');
  return v == null ? fallback : v;
}
async function putJson(env, key, value) {
  await env.SUBSCRIPTIONS.put(key, JSON.stringify(value));
}

// Sunucu gizli anahtarı: ilk kullanımda rastgele üretilir, sadece KV'de durur.
async function getSecret(env) {
  let s = await env.SUBSCRIPTIONS.get(K.secret);
  if (!s) {
    s = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    await env.SUBSCRIPTIONS.put(K.secret, s);
  }
  return s;
}
async function hmacHex(secretHex, text) {
  const key = await crypto.subtle.importKey('raw', hexToBytes(secretHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return bytesToHex(await crypto.subtle.sign('HMAC', key, encoder.encode(text)));
}
// TC kimlik numarasından geri çevrilemeyen üye kimliği üretir.
async function memberIdFromTc(secretHex, tc) {
  return (await hmacHex(secretHex, 'member:' + String(tc).trim())).slice(0, 20);
}

// --------------------------- Kullanıcılar ---------------------------------
// Teşkilat grupları:
//  yurutme  → Yürütme Kurulu, tüm mahalleler
//  il_koord → İl Koordinatörü, tüm mahalleler
//  yonetim  → Yönetim Kurulu, yalnızca sorumlu olduğu mahalleler
//  mahalle  → Mahalle Başkanı, kendi mahallesi
const GROUP_LABELS = { yurutme: 'Yürütme Kurulu', il_koord: 'İl Koordinatörü', yonetim: 'Yönetim Kurulu', mahalle: 'Mahalle Başkanı' };
async function loadUsers(env) {
  const [base, overrides, org] = await Promise.all([getJson(env, K.users, []), getJson(env, K.overrides, {}), getJson(env, K.org, null)]);
  return base.map(u => effectiveUser(u, overrides[u.username], org));
}
function effectiveUser(u, o, org) {
  o = o || {};
  const baseRole = (o.role || u.role) === 'neighborhood' ? 'neighborhood' : 'management';
  let group = o.group || (org && org.groups && org.groups[u.username]) || (baseRole === 'neighborhood' ? 'mahalle' : 'yonetim');
  if (!GROUP_LABELS[group]) group = baseRole === 'neighborhood' ? 'mahalle' : 'yonetim';
  const role = group === 'mahalle' ? 'neighborhood' : 'management';
  const admin = ADMIN_USERNAMES.includes(u.username);
  // Tüm mahalleler: yöneticiler, teşkilat listesinde "allHoods" olanlar (İlçe Başkanı, Kadın/Gençlik Kolları Başkanı)
  // ve panelden "tüm mahalleler" verilenler. Diğer herkes yalnızca sorumlu olduğu mahalleleri görür.
  const orgAll = org && Array.isArray(org.allHoods) ? org.allHoods.includes(u.username) : null;
  const allHoods = admin || o.allHoods === true
    || (o.allHoods !== false && (orgAll === true || (orgAll === null && (group === 'yurutme' || group === 'il_koord'))))
    || (role === 'management' && !org && !o.group);
  const assigned = o.neighborhoods && o.neighborhoods.length ? o.neighborhoods
    : role === 'management' ? ((org && org.access && org.access[u.username]) || []) : (u.neighborhoods || []);
  return {
    username: u.username,
    loginUsername: normalizeUser(o.loginUsername || u.username) || u.username,
    name: (o.name || u.name || u.username).trim(),
    refName: (o.refName || '').trim(),
    role,
    group,
    allHoods,
    neighborhoods: allHoods ? [] : assigned,
    disabled: !!o.disabled,
    password: String(o.password || DEFAULT_PASSWORD)
  };
}
function publicUser(u) {
  return {
    username: u.username,
    loginUsername: u.loginUsername,
    name: u.name,
    refName: u.refName,
    role: u.role,
    group: u.group,
    groupLabel: GROUP_LABELS[u.group] || '',
    allHoods: u.allHoods,
    neighborhoods: u.neighborhoods,
    isAdmin: ADMIN_USERNAMES.includes(u.username),
    title: USER_TITLES[u.username] || '',
    canAnalysis: true,
    mustChangePassword: u.password === DEFAULT_PASSWORD
  };
}
function userCanSeeHood(u, hood) { return u.allHoods || u.neighborhoods.includes(hood); }

// --------------------------- Oturum (token) --------------------------------
async function passwordVersion(secret, u) {
  return (await hmacHex(secret, 'pw:' + u.username + ':' + u.password)).slice(0, 12);
}
async function createToken(env, u) {
  const secret = await getSecret(env);
  const payload = { u: u.username, pv: await passwordVersion(secret, u), exp: Date.now() + TOKEN_DAYS * 864e5 };
  const body = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
  return body + '.' + (await hmacHex(secret, 'tok:' + body));
}
async function authUser(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const secret = await getSecret(env);
  if ((await hmacHex(secret, 'tok:' + body)) !== sig) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(body))); } catch (e) { return null; }
  if (!payload || payload.exp < Date.now()) return null;
  const users = await loadUsers(env);
  const u = users.find(x => x.username === payload.u);
  if (!u || u.disabled) return null;
  if ((await passwordVersion(secret, u)) !== payload.pv) return null;
  return u;
}
const isAdminUser = u => !!u && ADMIN_USERNAMES.includes(u.username);

// --------------------------- Üyeler ---------------------------------------
// Üye satırı biçimi (yer tasarrufu için dizi): [id, ad soyad, telefon, adres, üyelik tarihi, referanslar(dizi)]
function rowToMember(row, hood) {
  return { id: row[0], name: row[1], phone: row[2], address: row[3], joined: row[4], refs: row[5] || [], bd: row[6] || '', sandik: row[7] || '', neighborhood: hood };
}

async function membersResponse(env, user, have) {
  const index = await getJson(env, K.memberIndex, null);
  const edits = await env.SUBSCRIPTIONS.get(K.memberEdits) || '{}';
  if (!index) return textResponse(`{"ok":true,"version":null,"hoods":[],"data":{},"edits":${edits}}`);
  const allowed = index.hoods.map(h => h.name).filter(h => userCanSeeHood(user, h));
  const hoods = index.hoods.filter(h => allowed.includes(h.name));
  // Cihazda aynı sürüm varsa listeyi tekrar gönderme; sadece düzenlemeleri gönder.
  if (have && have === index.version) return textResponse(`{"ok":true,"unchanged":true,"nameIndex":${index.nameIndex ? 'true' : 'false'},"version":${JSON.stringify(index.version)},"updatedAt":${JSON.stringify(index.updatedAt || '')},"hoods":${JSON.stringify(hoods)},"edits":${edits}}`);
  // Mahalle verileri KV'den bayt akışı olarak doğrudan yanıta aktarılır; büyük listeyi
  // sunucuda çözüp yeniden üretmeye gerek kalmaz (işlemci süresi düşük kalır).
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  (async () => {
    try {
      await writer.write(encoder.encode(`{"ok":true,"nameIndex":${index.nameIndex ? 'true' : 'false'},"version":${JSON.stringify(index.version)},"updatedAt":${JSON.stringify(index.updatedAt || '')},"hoods":${JSON.stringify(hoods)},"edits":${edits},"data":{`));
      let first = true;
      // Tüm mahalleleri aynı anda iste, sırayla yanıta yaz
      const streams = allowed.map(hood => env.SUBSCRIPTIONS.get(memberHoodKey(index.version, hood), 'stream'));
      for (let i = 0; i < allowed.length; i++) {
        const hood = allowed[i];
        const stream = await streams[i];
        if (!stream) continue;
        await writer.write(encoder.encode((first ? '' : ',') + JSON.stringify(hood) + ':'));
        first = false;
        const reader = stream.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          await writer.write(value);
        }
      }
      await writer.write(encoder.encode('}}'));
      await writer.close();
    } catch (error) {
      await writer.abort(error);
    }
  })();
  return new Response(readable, { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders() } });
}

async function myMembers(env, user) {
  const index = await getJson(env, K.memberIndex, null);
  if (!index) return [];
  const names = [user.name, user.refName].map(refKey).filter(Boolean);
  const uniqueNames = [...new Set(names)];
  const edits = await getJson(env, K.memberEdits, {});
  const out = new Map();
  for (const name of uniqueNames) {
    const shard = await getJson(env, memberRefKey(index.version, refShard(name)), {});
    for (const [hood, row] of (shard[name] || [])) {
      const m = rowToMember(row, hood);
      if (edits[m.id]) Object.assign(m, edits[m.id]);
      if (!m.deleted) out.set(m.id, m);
    }
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name, 'tr'));
}

async function deleteByPrefix(env, prefix, keepPrefix) {
  let cursor;
  let deleted = 0;
  do {
    const page = await env.SUBSCRIPTIONS.list({ prefix, cursor });
    for (const key of page.keys) {
      if (keepPrefix && key.name.startsWith(keepPrefix)) continue;
      await env.SUBSCRIPTIONS.delete(key.name);
      deleted += 1;
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return deleted;
}

// Eski loglarda üye kimliği TC numarasıydı; bunları yeni kimliğe çevirir.
async function migrateLogs(env, logs) {
  if (!logs.some(l => /^\d{11}$/.test(String(l.memberId || '')))) return logs;
  const secret = await getSecret(env);
  for (const l of logs) {
    if (/^\d{11}$/.test(String(l.memberId || ''))) l.memberId = await memberIdFromTc(secret, l.memberId);
  }
  await putJson(env, K.logs, logs.slice(0, 10000));
  return logs;
}


// --------------------------- Üye sorgulama --------------------------------
// Ad soyad (+ telefon) ile Kepez üyeliği kontrolü. Yalnızca karar ve en az bilgi döner.
function nameTokens(v) { return refKey(v).split(' ').filter(Boolean); }
function phoneTail(v) { const d = String(v || '').replace(/\D/g, ''); return d.length >= 10 ? d.slice(-10) : ''; }
function maskPhone(v) { const d = cleanPhone(v); return d.length >= 10 ? d.slice(0, 4) + '***' + d.slice(-2) : ''; }
function nameMatches(queryTokens, recordName) {
  const rec = nameTokens(recordName);
  if (!rec.length || rec[rec.length - 1] !== queryTokens[queryTokens.length - 1]) return false;
  const first = queryTokens.slice(0, -1);
  const recFirst = rec.slice(0, -1);
  return first.every(t => recFirst.includes(t));
}
async function checkMember(env, b) {
  const tokens = nameTokens(b.name);
  if (tokens.length < 2) return json({ error: 'name_surname_required' }, 400);
  const tail = phoneTail(b.phone);
  const index = await getJson(env, K.memberIndex, null);
  if (!index) return json({ error: 'no_member_list' }, 503);
  const edits = await getJson(env, K.memberEdits, {});
  let candidates = [];
  if (index.nameIndex) {
    const surname = tokens[tokens.length - 1];
    const shard = await getJson(env, memberNameKey(index.version, refShard(surname)), {});
    candidates = (shard[surname] || []).map(([hood, row]) => rowToMember(row, hood));
  } else {
    for (const h of index.hoods) {
      const rows = await getJson(env, memberHoodKey(index.version, h.name), []);
      for (const row of rows) if (nameTokens(row[1]).slice(-1)[0] === tokens[tokens.length - 1]) candidates.push(rowToMember(row, h.name));
    }
  }
  // Panelden düzenlenen bilgiler (ör. telefon, ad) sorguda da geçerli
  const all = candidates.map(m => edits[m.id] ? { ...m, ...edits[m.id] } : m);
  // Ad düzenlenip soyadı değişmiş kayıtları da yakala
  for (const [id, e] of Object.entries(edits)) if (e.name && !all.some(m => m.id === id) && nameMatches(tokens, e.name)) all.push({ id, ...e });
  const byName = all.filter(m => nameMatches(tokens, m.name));
  const brief = m => ({ name: m.name, neighborhood: m.neighborhood || '', joined: m.joined || '', phone: maskPhone(m.phone) });
  if (!byName.length) return json({ ok: true, result: 'not_member', nameMatches: 0 });
  if (byName.length === 1) {
    const m = byName[0];
    const phoneMismatch = !!tail && !!phoneTail(m.phone) && phoneTail(m.phone) !== tail;
    return json({ ok: true, result: 'active', nameMatches: 1, member: brief(m), phoneMismatch });
  }
  if (!tail) return json({ ok: true, result: 'need_phone', nameMatches: byName.length });
  const byPhone = byName.filter(m => phoneTail(m.phone) === tail);
  if (byPhone.length === 1) return json({ ok: true, result: 'active', nameMatches: byName.length, member: brief(byPhone[0]), byPhone: true });
  return json({ ok: true, result: 'uncertain', nameMatches: byName.length, phoneMatches: byPhone.length });
}

// --------------------------- Duyurular ------------------------------------
function upsertPerson(list, user) {
  const next = (list || []).filter(item => item.username !== user.username);
  next.push({ username: user.username, name: user.name, at: new Date().toISOString() });
  return next;
}
function normalizeTarget(value) {
  return value === 'management' || value === 'neighborhood' ? value : 'all';
}
function matchesTarget(saved, target) {
  const wanted = normalizeTarget(target);
  if (wanted === 'all') return true;
  if (!saved) return false;
  if (saved.role === wanted) return true;
  if (wanted === 'management' && !saved.role) return true;
  return false;
}

async function forEachSubscription(env, fn) {
  let cursor;
  do {
    const page = await env.SUBSCRIPTIONS.list({ cursor });
    for (const key of page.keys) {
      if (key.name.startsWith('__')) continue;
      const saved = await env.SUBSCRIPTIONS.get(key.name, 'json');
      if (saved && saved.subscription) await fn(key.name, saved);
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
}
async function pushToTarget(env, target) {
  let sent = 0;
  let failed = 0;
  const failures = [];
  await forEachSubscription(env, async (name, saved) => {
    if (!matchesTarget(saved, target)) return;
    const res = await sendPush(env, saved.subscription);
    if (res.ok) sent += 1;
    else {
      failed += 1;
      failures.push({ status: res.status });
      if (res.status === 404 || res.status === 410) await env.SUBSCRIPTIONS.delete(name);
    }
  });
  return { sent, failed, failures: failures.slice(0, 5) };
}

// Belirli kişilere bildirim: her cihazın kendi gelen kutusuna (__inbox__:<abonelik>) yazılır,
// servis çalışanı /latest?ep=... ile kendi bildirimini alır (genel duyuruları etkilemez).
const inboxKey = id => `__inbox__:${id}`;
async function pushToUsers(env, usernames, payload) {
  const want = new Set(usernames);
  let sent = 0, devices = 0;
  const item = { title: clean(payload.title, 120), body: clean(payload.body, 400), url: payload.url || './', sentAt: new Date().toISOString() };
  await forEachSubscription(env, async (name, saved) => {
    if (!want.has(saved.username)) return;
    devices += 1;
    const box = (await getJson(env, inboxKey(name), [])).filter(x => Date.now() - Date.parse(x.sentAt) < 864e5);
    box.push(item);
    await env.SUBSCRIPTIONS.put(inboxKey(name), JSON.stringify(box.slice(-10)), { expirationTtl: 86400 * 2 });
    let res;
    try { res = await sendPush(env, saved.subscription); } catch (e) { return; }
    if (res.ok) sent += 1;
    else if (res.status === 404 || res.status === 410) { await env.SUBSCRIPTIONS.delete(name); await env.SUBSCRIPTIONS.delete(inboxKey(name)); }
  });
  return { sent, devices };
}
const shortText = (t, n = 140) => { t = String(t || '').replace(/\s+/g, ' ').trim(); return t.length > n ? t.slice(0, n - 1) + '…' : t; };

// Türkiye saatine göre bugünün "AA-GG" değeri
function trToday() {
  const d = new Date(Date.now() + 3 * 3600e3);
  const y = d.getUTCFullYear(), mm = String(d.getUTCMonth() + 1).padStart(2, '0'), dd = String(d.getUTCDate()).padStart(2, '0');
  return { y, mmdd: `${mm}-${dd}`, date: `${y}-${mm}-${dd}` };
}
function bdDaysFor(t) {
  const leap = (t.y % 4 === 0 && t.y % 100 !== 0) || t.y % 400 === 0;
  return t.mmdd === '02-28' && !leap ? ['02-28', '02-29'] : [t.mmdd];
}
// Her sabah 10.00: kişinin sorumlu olduğu mahallelerde veya referansıyla yapılan üyelerde doğum günü varsa bildirim
async function birthdayPush(env, opts = {}) {
  const t = trToday();
  const sentKey = `__bd_sent__:${t.date}`;
  if (!opts.force && await env.SUBSCRIPTIONS.get(sentKey)) return { skipped: 'already_sent' };
  const index = await getJson(env, K.memberIndex, null);
  if (!index || !index.bdIndex) return { skipped: 'no_birthday_data' };
  const days = bdDaysFor(t);
  const week = await getJson(env, memberBdKey(index.version, bdWeek(days[0])), {});
  const rows = days.flatMap(d => week[d] || []);
  if (!opts.force) await env.SUBSCRIPTIONS.put(sentKey, '1', { expirationTtl: 86400 * 3 });
  if (!rows.length) return { birthdays: 0, sent: 0 };
  const users = new Map((await loadUsers(env)).map(u => [u.username, u]));
  const counts = new Map();
  const countFor = u => {
    if (counts.has(u.username)) return counts.get(u.username);
    const keys = [u.name, u.refName].map(refKey).filter(Boolean);
    let hood = 0, mine = 0;
    for (const r of rows) {
      if (userCanSeeHood(u, r[0])) hood++;
      if (keys.some(k => (r[4] || []).includes(k))) mine++;
    }
    const c = { hood, mine };
    counts.set(u.username, c);
    return c;
  };
  let sent = 0, devices = 0;
  await forEachSubscription(env, async (name, saved) => {
    const u = users.get(saved.username);
    if (!u || u.disabled || (opts.onlyUser && u.username !== opts.onlyUser)) return;
    const c = countFor(u);
    if (!c.hood && !c.mine) return;
    const parts = [];
    if (c.hood) parts.push(u.allHoods ? `Kepez'de ${c.hood} üyemizin` : `mahallenizde ${c.hood} üyemizin`);
    if (c.mine) parts.push(`üyelerinizden ${c.mine} kişinin`);
    const item = { title: '🎂 Bugün doğum günü olanlar var', body: `Bugün ${parts.join(', ')} doğum günü. Kutlama mesajı göndermek için dokunun.`, url: './?ac=dogum', sentAt: new Date().toISOString() };
    devices++;
    const box = (await getJson(env, inboxKey(name), [])).filter(x => Date.now() - Date.parse(x.sentAt) < 864e5);
    box.push(item);
    await env.SUBSCRIPTIONS.put(inboxKey(name), JSON.stringify(box.slice(-10)), { expirationTtl: 86400 * 2 });
    let res;
    try { res = await sendPush(env, saved.subscription); } catch (e) { return; }
    if (res.ok) sent++;
    else if (res.status === 404 || res.status === 410) { await env.SUBSCRIPTIONS.delete(name); await env.SUBSCRIPTIONS.delete(inboxKey(name)); }
  });
  return { birthdays: rows.length, devices, sent };
}

function clean(v, max = 500) {
  return String(v == null ? '' : v).trim().slice(0, max);
}
// Her biçimi (0532…, 532…, +90 532…, 0090…) 0 ile başlayan 11 haneye çevirir
function cleanPhone(v) {
  let d = String(v || '').replace(/\D/g, '');
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length >= 12 && d.startsWith('90')) d = d.slice(2);
  const n = d.replace(/^0+/, '');
  return n.length === 10 ? '0' + n : d.slice(0, 15);
}


// --------------------------- Harita konumları -----------------------------
// Sokak konumu OpenStreetMap (Nominatim) ile, bina konumları ArcGIS ile bulunur ve
// KV'de saklanır; bir sokak bir kez bulununca herkes için anında açılır.
const GEO_UA = 'ak-parti-kepez-cagri-takip/1.0 (+https://abdullahuysal07.github.io/ak-parti-kepez-cagri-takip/)';
function hoodBase(hood) { return String(hood || '').replace(/\s*MAH\.?$/i, '').trim(); }
function trLower(v) { return String(v || '').toLocaleLowerCase('tr-TR'); }
function streetForOsm(street) {
  return String(street || '').toLocaleLowerCase('tr-TR')
    .replace(/\bsok(ak|\.)?\b/g, 'Sokak').replace(/\bcad(desi|\.)?\b/g, 'Caddesi').replace(/\bbulvar(ı)?\b/g, 'Bulvarı')
    .replace(/(^|\s)(\p{L})/gu, (m, a, b) => a + b.toLocaleUpperCase('tr-TR'));
}
function flattenLine(geojson) {
  if (!geojson) return null;
  if (geojson.type === 'LineString') return geojson.coordinates.map(([lng, lat]) => [lat, lng]);
  if (geojson.type === 'MultiLineString') return geojson.coordinates.flat().map(([lng, lat]) => [lat, lng]);
  return null;
}
async function nominatim(params) {
  const u = new URL('https://nominatim.openstreetmap.org/search');
  Object.entries({ format: 'jsonv2', countrycodes: 'tr', 'accept-language': 'tr', limit: '5', ...params }).forEach(([k, v]) => u.searchParams.set(k, v));
  try {
    const res = await fetch(u.toString(), { headers: { 'User-Agent': GEO_UA, Accept: 'application/json' } });
    if (!res.ok) return [];
    return await res.json();
  } catch (e) { return []; }
}
async function arcgis(text) {
  try {
    const res = await fetch('https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates?f=json&maxLocations=1&outFields=Score&SingleLine=' + encodeURIComponent(text));
    const data = await res.json();
    const c = data.candidates && data.candidates[0];
    return c && c.location ? { lat: c.location.y, lng: c.location.x, score: c.score || 0 } : null;
  } catch (e) { return null; }
}
function distM(a, b) {
  const R = 6371000, r = x => x * Math.PI / 180;
  const h = Math.sin(r(b.lat - a.lat) / 2) ** 2 + Math.cos(r(a.lat)) * Math.cos(r(b.lat)) * Math.sin(r(b.lng - a.lng) / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
const KEPEZ_CENTER = { lat: 36.95, lng: 30.69 };
function inKepez(p) { return p && distM(p, KEPEZ_CENTER) < 25000; }
async function locateStreet(street, hood) {
  const hb = trLower(hoodBase(hood));
  const pick = list => {
    const ok = (list || []).filter(r => inKepez({ lat: +r.lat, lng: +r.lon }));
    return ok.find(r => trLower(r.display_name).includes(hb)) || ok[0] || null;
  };
  const osmStreet = streetForOsm(street);
  let r = pick(await nominatim({ street: osmStreet, county: 'Kepez', state: 'Antalya', polygon_geojson: '1' }));
  if (!r) r = pick(await nominatim({ q: `${osmStreet}, ${hoodBase(hood)}, Kepez, Antalya`, polygon_geojson: '1' }));
  if (r) return { point: { lat: +r.lat, lng: +r.lon }, line: flattenLine(r.geojson), source: 'osm' };
  const a = await arcgis(`${street} ${hood} Kepez Antalya Türkiye`);
  if (a && a.score >= 85 && inKepez(a)) return { point: { lat: a.lat, lng: a.lng }, line: null, source: 'arcgis' };
  const h = pick(await nominatim({ q: `${hoodBase(hood)} Mahallesi, Kepez, Antalya` }));
  if (h) return { point: { lat: +h.lat, lng: +h.lon }, line: null, source: 'hood' };
  return { point: { lat: 36.9300, lng: 30.6900 }, line: null, source: 'kepez' };
}
async function locateHood(hood) {
  const hb = hoodBase(hood);
  const list = await nominatim({ q: `${hb} Mahallesi, Kepez, Antalya`, polygon_geojson: '1' });
  const ok = (list || []).filter(r => inKepez({ lat: +r.lat, lng: +r.lon }));
  const r = ok.find(x => /polygon/i.test((x.geojson || {}).type || '')) || ok[0];
  if (!r) return { point: { lat: 36.93, lng: 30.69 }, line: null, source: 'kepez' };
  let ring = null;
  const g = r.geojson || {};
  if (g.type === 'Polygon') ring = g.coordinates[0];
  else if (g.type === 'MultiPolygon') ring = g.coordinates.map(p => p[0]).sort((a, b) => b.length - a.length)[0];
  // Çok noktalı sınırları sadeleştir (yanıt boyutu için)
  if (ring && ring.length > 400) { const step = Math.ceil(ring.length / 400); ring = ring.filter((_, i) => i % step === 0); }
  return { point: { lat: +r.lat, lng: +r.lon }, line: ring ? ring.map(([lng, lat]) => [+lat.toFixed(6), +lng.toFixed(6)]) : null, source: 'hood_area' };
}
async function geoForStreet(env, body) {
  const street = clean(body.street, 120);
  const hood = clean(body.hood, 80);
  if (!street && !hood) return json({ error: 'street_required' }, 400);
  if (!street) {
    const key = '__geo__:hood:' + (await sha256Hex(trLower(hood))).slice(0, 32);
    let rec = await getJson(env, key, null);
    if (!rec || (rec.source === 'kepez' && Date.now() - (rec.at || 0) > 864e5)) { rec = { hood, ...(await locateHood(hood)), at: Date.now() }; await putJson(env, key, rec); }
    return json({ ok: true, point: rec.point, line: rec.line, source: rec.source, doors: {}, pending: 0 });
  }
  const key = '__geo__:' + (await sha256Hex(trLower(hood) + '|' + trLower(street))).slice(0, 32);
  let rec = await getJson(env, key, null);
  let changed = false;
  if (!rec || (rec.source === 'kepez' && Date.now() - (rec.at || 0) > 864e5) || (rec.source === 'hood' && Date.now() - (rec.at || 0) > 7 * 864e5)) {
    rec = { street, hood, ...(await locateStreet(street, hood)), doors: {}, at: Date.now() };
    changed = true;
  }
  const doors = [...new Set((Array.isArray(body.doors) ? body.doors : []).map(d => clean(d, 12)).filter(Boolean))];
  const missing = rec.source === 'kepez' ? [] : doors.filter(d => !(d in rec.doors)).slice(0, 36);
  const queue = missing.slice();
  const work = async () => {
    while (queue.length) {
      const d = queue.shift();
      const p = await arcgis(`${street} No:${d} ${hood} Kepez Antalya Türkiye`);
      rec.doors[d] = p && p.score >= 80 && distM(p, rec.point) < (rec.line ? 900 : 600) ? [+p.lat.toFixed(6), +p.lng.toFixed(6)] : 0;
    }
  };
  await Promise.all(Array.from({ length: 6 }, work));
  if (missing.length) changed = true;
  if (changed) await putJson(env, key, rec);
  const pending = rec.source === 'kepez' ? 0 : doors.filter(d => !(d in rec.doors)).length;
  return json({ ok: true, point: rec.point, line: rec.line, source: rec.source, doors: rec.doors, pending });
}


// --------------------------- Kullanım takibi ------------------------------
// Kimin giriş yaptığı, uygulamayı kurup kurmadığı ve bildirim durumu (kullanıcı başına bir kayıt).
const actKey = username => `__act__:${username}`;
async function touchActivity(env, user, patch = {}, force = false) {
  const key = actKey(user.username);
  const rec = (await getJson(env, key, null)) || { username: user.username, logins: 0, devices: {} };
  const now = Date.now();
  let changed = force;
  if (patch.login) { rec.lastLogin = new Date(now).toISOString(); rec.logins = (rec.logins || 0) + 1; changed = true; }
  if (patch.device && patch.device.id) {
    const d = patch.device; const prev = rec.devices[d.id] || {};
    const next = { platform: clean(d.platform, 20), standalone: !!d.standalone, permission: clean(d.permission, 20), pushSubscribed: !!d.pushSubscribed, at: new Date(now).toISOString() };
    if (prev.platform !== next.platform || prev.standalone !== next.standalone || prev.permission !== next.permission || prev.pushSubscribed !== next.pushSubscribed) changed = true;
    rec.devices[clean(d.id, 40)] = next;
    const ids = Object.keys(rec.devices).sort((a, b) => String(rec.devices[b].at).localeCompare(String(rec.devices[a].at)));
    ids.slice(4).forEach(id => delete rec.devices[id]);
  }
  // Yazma sayısını düşük tutmak için "son görülme" en fazla 20 dakikada bir güncellenir
  if (!rec.lastSeen || now - new Date(rec.lastSeen).getTime() > 20 * 60000) changed = true;
  if (changed) { rec.lastSeen = new Date(now).toISOString(); await putJson(env, key, rec); }
  return rec;
}
async function usageReport(env) {
  const [users, org] = [await loadUsers(env), await getJson(env, K.org, null)];
  const acts = {}; const subs = {};
  let cursor;
  do {
    const page = await env.SUBSCRIPTIONS.list({ prefix: '__act__:', cursor });
    await Promise.all(page.keys.map(async k => { const r = await env.SUBSCRIPTIONS.get(k.name, 'json'); if (r) acts[r.username] = r; }));
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  await forEachSubscription(env, async (name, saved) => { const u = saved.username || ''; if (!subs[u]) subs[u] = 0; subs[u] += 1; });
  const rows = users.map(u => {
    const a = acts[u.username] || null;
    const devices = a ? Object.values(a.devices || {}) : [];
    return {
      username: u.username, loginUsername: u.loginUsername, name: u.name, group: u.group, groupLabel: GROUP_LABELS[u.group] || '',
      neighborhoods: u.neighborhoods, allHoods: u.allHoods, disabled: u.disabled,
      passwordChanged: u.password !== DEFAULT_PASSWORD,
      lastLogin: a && a.lastLogin || '', lastSeen: a && a.lastSeen || '', logins: a && a.logins || 0,
      devices, pushSubscriptions: subs[u.username] || 0,
      installed: devices.some(d => d.standalone), permission: devices.length ? (devices.find(d => d.permission === 'granted') ? 'granted' : devices.find(d => d.permission === 'denied') ? 'denied' : devices[0].permission) : ''
    };
  });
  return { ok: true, generatedAt: new Date().toISOString(), rows, anonymousSubscriptions: subs[''] || 0 };
}

// --------------------------- İstek yönlendirme ----------------------------
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(birthdayPush(env).catch(() => {}));
  },
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
    try {
      return await handle(request, env);
    } catch (error) {
      return json({ error: 'server_error', message: String(error && error.message || error) }, 500);
    }
  }
};

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method;
  const body = async () => { try { return await request.json(); } catch (e) { return {}; } };

  if (path === '/health') return json({ ok: true });
  // Kısa kurulum bağlantısı: WhatsApp mesajlarında uzun site adresi yerine kullanılır
  if (path === '/kur' || path === '/k') return Response.redirect('https://abdullahuysal07.github.io/ak-parti-kepez-cagri-takip/kurulum.html', 302);
  if (path === '/latest') {
    const ep = url.searchParams.get('ep');
    if (ep) {
      const key = inboxKey(await sha256Hex(ep));
      const box = await getJson(env, key, []);
      if (box.length) {
        const next = box.shift();
        if (box.length) await env.SUBSCRIPTIONS.put(key, JSON.stringify(box), { expirationTtl: 86400 * 2 }); else await env.SUBSCRIPTIONS.delete(key);
        return json(next);
      }
    }
    const latest = await env.SUBSCRIPTIONS.get(K.latest, 'json');
    return json(latest || { title: 'AK Parti Kepez', body: 'Yeni bildirim var.', url: './' });
  }

  // ---- Giriş ----
  if (path === '/auth/login' && method === 'POST') {
    const b = await body();
    const wanted = normalizeUser(b.username);
    const users = await loadUsers(env);
    const u = users.find(x => x.loginUsername === wanted || x.username === wanted);
    if (!u || u.disabled || String(b.password || '') !== u.password) return json({ error: 'login_failed' }, 401);
    await touchActivity(env, u, { login: true });
    return json({ ok: true, token: await createToken(env, u), user: publicUser(u) });
  }

  const user = await authUser(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401);
  const admin = isAdminUser(user);
  const requireAdmin = () => admin ? null : json({ error: 'forbidden' }, 403);

  if (path === '/auth/me' && method === 'GET') return json({ ok: true, user: publicUser(user) });
  if (path === '/activity' && method === 'POST') { const b = await body(); await touchActivity(env, user, { device: b }); return json({ ok: true }); }
  if (path === '/admin/usage' && method === 'GET') { const denied = requireAdmin(); if (denied) return denied; return json(await usageReport(env)); }

  if (path === '/auth/password' && method === 'POST') {
    const b = await body();
    const next = String(b.newPassword || '').trim();
    if (String(b.currentPassword || '') !== user.password) return json({ error: 'wrong_password' }, 400);
    if (next.length < 6 || next === DEFAULT_PASSWORD) return json({ error: 'weak_password' }, 400);
    const overrides = await getJson(env, K.overrides, {});
    overrides[user.username] = { ...(overrides[user.username] || {}), password: next };
    await putJson(env, K.overrides, overrides);
    const updated = { ...user, password: next };
    return json({ ok: true, token: await createToken(env, updated), user: publicUser(updated) });
  }

  // ---- Üyeler ----
  if (path === '/members' && method === 'GET') return membersResponse(env, user, url.searchParams.get('have') || '');
  if (path === '/members/check' && method === 'POST') return checkMember(env, await body());
  if (path === '/members/mine' && method === 'GET') return json({ ok: true, members: await myMembers(env, user) });
  if (path.startsWith('/members/') && method === 'PUT') {
    const denied = requireAdmin(); if (denied) return denied;
    const id = decodeURIComponent(path.slice('/members/'.length));
    const b = await body();
    const edits = await getJson(env, K.memberEdits, {});
    const e = { ...(edits[id] || {}) };
    if ('name' in b) e.name = clean(b.name, 120).toLocaleUpperCase('tr-TR');
    if ('phone' in b) e.phone = cleanPhone(b.phone);
    if ('address' in b) e.address = clean(b.address, 300);
    if ('neighborhood' in b && clean(b.neighborhood)) e.neighborhood = clean(b.neighborhood, 80);
    e.updatedAt = new Date().toISOString();
    e.updatedBy = user.name;
    edits[id] = e;
    await putJson(env, K.memberEdits, edits);
    return json({ ok: true, edit: e });
  }

  // ---- Üye listesi içe aktarma (sadece admin) ----
  if (path === '/admin/id-secret' && method === 'GET') {
    const denied = requireAdmin(); if (denied) return denied;
    return json({ ok: true, secret: await getSecret(env) });
  }
  if (path === '/admin/import/start' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    return json({ ok: true, version: 'v' + Date.now().toString(36) });
  }
  if (path === '/admin/import/part' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const version = url.searchParams.get('version') || '';
    const kind = url.searchParams.get('kind');
    const key = url.searchParams.get('key') || '';
    if (!/^v[a-z0-9]+$/.test(version) || !key) return json({ error: 'bad_request' }, 400);
    const text = await request.text();
    if (kind === 'hood') await env.SUBSCRIPTIONS.put(memberHoodKey(version, key), text);
    else if (kind === 'ref') await env.SUBSCRIPTIONS.put(memberRefKey(version, Number(key) % REF_SHARDS), text);
    else if (kind === 'name') await env.SUBSCRIPTIONS.put(memberNameKey(version, Number(key) % REF_SHARDS), text);
    else if (kind === 'bd') await env.SUBSCRIPTIONS.put(memberBdKey(version, Math.min(52, Math.max(0, Number(key) || 0))), text);
    else return json({ error: 'bad_kind' }, 400);
    return json({ ok: true });
  }
  if (path === '/admin/import/finish' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    if (!/^v[a-z0-9]+$/.test(b.version || '') || !Array.isArray(b.hoods)) return json({ error: 'bad_request' }, 400);
    const previous = await getJson(env, K.memberIndex, null);
    const index = { version: b.version, nameIndex: !!b.nameIndex, bdIndex: !!b.bdIndex, updatedAt: new Date().toISOString(), updatedBy: user.name, total: Number(b.total) || 0, hoods: b.hoods.map(h => ({ name: clean(h.name, 80), count: Number(h.count) || 0 })) };
    await putJson(env, K.memberIndex, index);
    // Sandık → mahalle eşleşmesi (tüm liste üzerinden, yükleyen yöneticinin tarayıcısında hesaplanır)
    if (b.sandikHoods && typeof b.sandikHoods === 'object') {
      const map = {};
      for (const [no, h] of Object.entries(b.sandikHoods)) { const n = String(no).replace(/\D/g, '').slice(0, 6); if (n) map[n] = [clean(h && h[0], 80), Number(h && h[1]) || 0]; }
      await putJson(env, '__sandik_map__', map);
    }
    let removed = 0;
    if (previous && previous.version && previous.version !== b.version) {
      removed += await deleteByPrefix(env, `__members__:${previous.version}:`);
      removed += await deleteByPrefix(env, `__members_ref__:${previous.version}:`);
      removed += await deleteByPrefix(env, `__members_name__:${previous.version}:`);
      if (previous.bdIndex) removed += await deleteByPrefix(env, `__members_bd__:${previous.version}:`);
    }
    // Listeden çıkarılan üyelerin düzenleme kayıtlarını temizle
    if (Array.isArray(b.ids)) {
      const keep = new Set(b.ids);
      const edits = await getJson(env, K.memberEdits, {});
      let changed = false;
      for (const id of Object.keys(edits)) if (!keep.has(id)) { delete edits[id]; changed = true; }
      if (changed) await putJson(env, K.memberEdits, edits);
    }
    return json({ ok: true, index, removedKeys: removed });
  }

  // Doğum günü bildirimini elle tetikleme (deneme için, yalnızca admin)
  if (path === '/admin/birthday-push' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    return json({ ok: true, ...(await birthdayPush(env, { force: true, onlyUser: url.searchParams.get('me') ? user.username : '' })) });
  }

  // ---- Sandık kurulları (mahalle bazında: __sandik__:<mahalle>) ----
  if (path === '/sandik' && method === 'GET') {
    const hood = clean(url.searchParams.get('hood'), 80);
    if (!hood || !userCanSeeHood(user, hood)) return json({ error: 'forbidden' }, 403);
    const map = await getJson(env, '__sandik_map__', null);
    const nos = map ? Object.entries(map).filter(([, v]) => v[0] === hood).map(([no, v]) => [no, v[1]]) : null;
    return json({ ok: true, hood, data: await getJson(env, sandikKey(hood), {}), nos });
  }
  if (path === '/sandik' && method === 'PUT') {
    const b = await body();
    const hood = clean(b.hood, 80);
    const no = String(b.sandik || '').replace(/\D/g, '').slice(0, 6);
    if (!hood || !no) return json({ error: 'bad_request' }, 400);
    if (!userCanSeeHood(user, hood)) return json({ error: 'forbidden' }, 403);
    const data = await getJson(env, sandikKey(hood), {});
    const person = p => p && (p.name || p.phone) ? { name: clean(p.name, 120).toLocaleUpperCase('tr-TR'), phone: cleanPhone(p.phone), memberId: clean(p.memberId, 40), memberHood: clean(p.memberHood, 80) } : null;
    const roles = {};
    for (const r of SANDIK_ROLES) { const v = person(b.roles && b.roles[r]); if (v) roles[r] = v; }
    // Sandık kuruluna yalnızca üyeler yazılabilir: kişi güncel üye listesinde (kendi mahallesinin kaydında) bulunmalı
    const index = await getJson(env, K.memberIndex, null);
    if (index) {
      const shardCache = new Map();
      const notMember = [];
      for (const [r, v] of Object.entries(roles)) {
        const h = v.memberHood || hood;
        if (!shardCache.has(h)) shardCache.set(h, new Map((await getJson(env, memberHoodKey(index.version, h), [])).map(x => [x[0], x[1]])));
        const official = v.memberId && shardCache.get(h).get(v.memberId);
        if (!official) notMember.push(r);
        else v.name = clean(official, 120); // adı üye kaydındaki haliyle yaz
      }
      if (notMember.length) return json({ error: 'not_member', roles: notMember }, 400);
    }
    const entry = { roles, bina: clean(b.bina, 160), note: clean(b.note, 500), updatedAt: new Date().toISOString(), updatedBy: user.name };
    if (!Object.keys(roles).length && !entry.bina && !entry.note) delete data[no]; else data[no] = entry;
    await putJson(env, sandikKey(hood), data);
    return json({ ok: true, hood, data });
  }
  // Okul/bina görevlileri: okul sorumlusu ve kat sorumluları (mahalle kaydında "_okullar" altında)
  if (path === '/sandik/okul' && method === 'PUT') {
    const b = await body();
    const hood = clean(b.hood, 80);
    const okul = clean(b.okul, 160).toLocaleUpperCase('tr-TR');
    if (!hood || !okul) return json({ error: 'bad_request' }, 400);
    if (!userCanSeeHood(user, hood)) return json({ error: 'forbidden' }, 403);
    const data = await getJson(env, sandikKey(hood), {});
    const okullar = data._okullar || {};
    const person = p => p && (p.name || p.phone) ? { name: clean(p.name, 120).toLocaleUpperCase('tr-TR'), phone: cleanPhone(p.phone), memberId: clean(p.memberId, 40) } : null;
    const oldName = clean(b.oldOkul, 160).toLocaleUpperCase('tr-TR');
    if (oldName && oldName !== okul) delete okullar[oldName];
    if (b.remove) delete okullar[okul];
    else okullar[okul] = { sorumlu: person(b.sorumlu), katlar: (Array.isArray(b.katlar) ? b.katlar : []).map(person).filter(Boolean).slice(0, 20), updatedAt: new Date().toISOString(), updatedBy: user.name };
    data._okullar = okullar;
    await putJson(env, sandikKey(hood), data);
    return json({ ok: true, hood, data });
  }
  if (path === '/sandik/summary' && method === 'GET') {
    const index = await getJson(env, K.memberIndex, null);
    const hoods = ((index && index.hoods) || []).map(h => h.name).filter(h => userCanSeeHood(user, h));
    const all = url.searchParams.get('full') === '1' && admin;
    const out = {};
    await Promise.all(hoods.map(async h => { const d = await getJson(env, sandikKey(h), {}); out[h] = all ? d : Object.fromEntries(Object.entries(d).filter(([k]) => k !== '_okullar').map(([k, v]) => [k, Object.keys(v.roles || {})])); }));
    const fullMap = await getJson(env, '__sandik_map__', {});
    const totals = {};
    for (const [, v] of Object.entries(fullMap)) if (v && out[v[0]] !== undefined) totals[v[0]] = (totals[v[0]] || 0) + 1;
    return json({ ok: true, hoods: out, map: all ? fullMap : undefined, totals });
  }

  // ---- Harita ----
  if (path === '/geo' && method === 'POST') return geoForStreet(env, await body());

  if (path === '/admin/import/name-done' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    const index = await getJson(env, K.memberIndex, null);
    if (!index || index.version !== b.version) return json({ error: 'version_mismatch' }, 409);
    index.nameIndex = true;
    await putJson(env, K.memberIndex, index);
    return json({ ok: true });
  }

  if (path === '/org' && method === 'GET') return json({ ok: true, org: await getJson(env, K.org, null) });

  // ---- Başkanlar / Yönetim ----
  if (path === '/leaders' && method === 'GET') return json({ ok: true, leaders: await getJson(env, K.leaders, []) });
  if (path === '/leaders' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    const leaders = await getJson(env, K.leaders, []);
    const item = { id: 'l-' + crypto.randomUUID().slice(0, 8), name: clean(b.name, 120).toLocaleUpperCase('tr-TR'), role: clean(b.role, 120), branch: clean(b.branch, 60) || 'Ana Kademe', phone: cleanPhone(b.phone), address: clean(b.address, 300), neighborhood: clean(b.neighborhood, 80) };
    if (!item.name) return json({ error: 'name_required' }, 400);
    leaders.push(item);
    await putJson(env, K.leaders, leaders);
    // Mahalle başkanı eklenince otomatik kullanıcı hesabı (mahalle grubu, kendi mahallesi)
    let account = null;
    if (b.createAccount && item.neighborhood) {
      const base = await getJson(env, K.users, []);
      const current = await loadUsers(env);
      const nk = s2 => normalizeUser(s2).replace(/_/g, '');
      const existing = current.find(u => nk(u.name) === nk(item.name));
      if (existing) account = { existing: true, username: existing.username, loginUsername: existing.loginUsername };
      else {
        const stem = normalizeUser(item.name) || 'kullanici';
        let username = stem, n = 2;
        const taken = u2 => base.some(u => u.username === u2) || current.some(u => u.loginUsername === u2);
        while (taken(username)) username = `${stem}_${n++}`;
        base.push({ username, name: item.name, role: 'neighborhood', neighborhoods: [item.neighborhood], createdAt: new Date().toISOString(), createdBy: user.username, leaderId: item.id });
        await putJson(env, K.users, base);
        const overrides = await getJson(env, K.overrides, {});
        overrides[username] = { role: 'neighborhood', group: 'mahalle', neighborhoods: [item.neighborhood], disabled: false, loginUsername: username, name: item.name, refName: item.name, password: DEFAULT_PASSWORD };
        await putJson(env, K.overrides, overrides);
        account = { created: true, username, loginUsername: username, password: DEFAULT_PASSWORD };
      }
    }
    return json({ ok: true, leader: item, leaders, account, users: account ? await loadUsers(env) : undefined });
  }
  if (path.startsWith('/leaders/') && (method === 'PUT' || method === 'DELETE')) {
    const denied = requireAdmin(); if (denied) return denied;
    const id = decodeURIComponent(path.slice('/leaders/'.length));
    const leaders = await getJson(env, K.leaders, []);
    const i = leaders.findIndex(l => l.id === id);
    if (i === -1) return json({ error: 'not_found' }, 404);
    if (method === 'DELETE') leaders.splice(i, 1);
    else {
      const b = await body();
      const l = leaders[i];
      if ('name' in b) l.name = clean(b.name, 120).toLocaleUpperCase('tr-TR');
      if ('role' in b) l.role = clean(b.role, 120);
      if ('branch' in b) l.branch = clean(b.branch, 60);
      if ('phone' in b) l.phone = cleanPhone(b.phone);
      if ('address' in b) l.address = clean(b.address, 300);
      if ('neighborhood' in b) l.neighborhood = clean(b.neighborhood, 80);
    }
    await putJson(env, K.leaders, leaders);
    return json({ ok: true, leaders });
  }

  // ---- Talep ve öneriler ----
  if (path === '/requests' && method === 'GET') {
    const requests = await getJson(env, K.requests, []);
    return json({ ok: true, requests: admin ? requests : requests.filter(r => r.username === user.username) });
  }
  if (path === '/requests' && method === 'POST') {
    const b = await body();
    const text = clean(b.text, 3000);
    if (!text) return json({ error: 'text_required' }, 400);
    const item = { id: crypto.randomUUID(), text, category: clean(b.category, 40) || 'Talep', username: user.username, name: user.name, role: user.role, neighborhood: user.neighborhoods[0] || '', status: 'new', time: new Date().toISOString() };
    if (b.visit && typeof b.visit === 'object') {
      item.visit = { neighborhood: clean(b.visit.neighborhood, 80), date: /^\d{4}-\d{2}-\d{2}$/.test(String(b.visit.date || '')) ? b.visit.date : '' };
      if (item.visit.neighborhood) item.neighborhood = item.visit.neighborhood;
    }
    // Ziyaret fotoğrafları: ana veriden ve GitHub deposundan ayrı, kendi KV deposunda (VISIT_IMAGES) tutulur
    if (Array.isArray(b.images) && b.images.length > MAX_VISIT_IMAGES) return json({ error: 'too_many_images' }, 400);
    const images = Array.isArray(b.images) ? b.images : [];
    if (images.length) {
      if (!env.VISIT_IMAGES) return json({ error: 'image_storage_missing' }, 503);
      const decoded = [];
      for (const d of images) {
        const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(d || ''));
        if (!m) return json({ error: 'bad_image' }, 400);
        const bytes = base64UrlToBytes(m[2].replace(/=+$/, ''));
        if (bytes.length > 2.5 * 1024 * 1024) return json({ error: 'image_too_large' }, 413);
        decoded.push({ type: 'image/' + m[1], bytes });
      }
      item.images = [];
      for (let n = 0; n < decoded.length; n++) {
        await env.VISIT_IMAGES.put(`img:${item.id}:${n}`, decoded[n].bytes, { metadata: { type: decoded[n].type, username: user.username } });
        item.images.push({ n, size: decoded[n].bytes.length });
      }
    }
    const requests = await getJson(env, K.requests, []);
    requests.unshift(item);
    await putJson(env, K.requests, requests.slice(0, 2000));
    const isVisit = item.category === 'Mahalle Ziyareti';
    const notifyAdmins = ADMIN_USERNAMES.filter(u => u !== user.username);
    let notified = 0;
    if (notifyAdmins.length) {
      try {
        notified = await pushToUsers(env, notifyAdmins, {
          title: isVisit ? `Yeni ziyaret raporu: ${user.name}` : `Yeni ${item.category.toLocaleLowerCase('tr-TR')}: ${user.name}`,
          body: (isVisit && item.visit && item.visit.neighborhood ? item.visit.neighborhood + ' • ' : '') + shortText(text) + (item.images && item.images.length ? ` (📷 ${item.images.length} fotoğraf)` : ''),
          url: './?ac=talepler'
        });
      } catch (e) {}
    }
    return json({ ok: true, request: item, notified });
  }
  if (path.startsWith('/requests/img/') && method === 'GET') {
    const [rid, nStr] = decodeURIComponent(path.slice('/requests/img/'.length)).split('/');
    const requests = await getJson(env, K.requests, []);
    const r = requests.find(x => x.id === rid);
    if (!r || !(admin || r.username === user.username)) return json({ error: 'not_found' }, 404);
    if (!env.VISIT_IMAGES) return json({ error: 'image_storage_missing' }, 503);
    const got = await env.VISIT_IMAGES.getWithMetadata(`img:${rid}:${Number(nStr) || 0}`, 'arrayBuffer');
    if (!got || !got.value) return json({ error: 'not_found' }, 404);
    return new Response(got.value, { headers: { 'Content-Type': (got.metadata && got.metadata.type) || 'image/jpeg', 'Cache-Control': 'private, max-age=86400', ...corsHeaders() } });
  }
  if (path.startsWith('/requests/') && (method === 'PUT' || method === 'DELETE')) {
    const denied = requireAdmin(); if (denied) return denied;
    const id = decodeURIComponent(path.slice('/requests/'.length));
    const requests = await getJson(env, K.requests, []);
    const i = requests.findIndex(r => r.id === id);
    if (i === -1) return json({ error: 'not_found' }, 404);
    if (method === 'DELETE') {
      const [removed] = requests.splice(i, 1);
      if (env.VISIT_IMAGES && removed.images) await Promise.all(removed.images.map(im => env.VISIT_IMAGES.delete(`img:${removed.id}:${im.n}`)));
    } else {
      const b = await body();
      const r = requests[i];
      const prevStatus = r.status, prevReply = r.reply || '';
      if (['new', 'reviewed', 'done'].includes(b.status)) r.status = b.status;
      if ('reply' in b) { r.reply = clean(b.reply, 2000); if (r.reply !== prevReply) { r.repliedAt = new Date().toISOString(); r.repliedBy = user.name; } }
      r.updatedAt = new Date().toISOString();
      await putJson(env, K.requests, requests);
      // Talep sahibine bildirim: yanıt yazıldığında veya durum değiştiğinde
      const replied = r.reply && r.reply !== prevReply;
      const statusChanged = r.status !== prevStatus && r.status !== 'new';
      let notified = null;
      if ((replied || statusChanged) && r.username && r.username !== user.username) {
        const label = { reviewed: 'İnceleniyor', done: 'Tamamlandı' }[r.status] || '';
        try {
          notified = await pushToUsers(env, [r.username], {
            title: replied ? `${r.category || 'Talep'} yanıtlandı` : `${r.category || 'Talep'} durumu: ${label}`,
            body: replied ? `${user.name}: ${shortText(r.reply)}` : shortText(r.text, 120),
            url: './?ac=talepler'
          });
        } catch (e) {}
      }
      return json({ ok: true, notified });
    }
    await putJson(env, K.requests, requests);
    return json({ ok: true });
  }

  // ---- Kullanıcı yetkileri (admin) ----
  if (path === '/access' && method === 'GET') {
    const denied = requireAdmin(); if (denied) return denied;
    return json({ ok: true, users: await loadUsers(env) });
  }
  if (path === '/access' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    let username = clean(b.username, 80);
    const base = await getJson(env, K.users, []);
    if (b.create) {
      // Yeni kullanıcı: kullanıcı adı benzersiz olmalı (hem kayıtlı ad hem giriş adı)
      username = normalizeUser(b.loginUsername || b.username);
      const name = clean(b.name, 120);
      if (!username || username.length < 3) return json({ error: 'username_required' }, 400);
      if (!name) return json({ error: 'name_required' }, 400);
      const current = await loadUsers(env);
      if (base.some(u => u.username === username) || current.some(u => u.loginUsername === username)) return json({ error: 'username_taken' }, 409);
      base.push({ username, name, role: b.group === 'mahalle' ? 'neighborhood' : 'management', neighborhoods: [], createdAt: new Date().toISOString(), createdBy: user.username });
      await putJson(env, K.users, base);
    } else if (!base.some(u => u.username === username)) return json({ error: 'user_not_found' }, 404);
    else {
      // Giriş adı başka bir kullanıcıyla çakışmasın
      const wantedLogin = normalizeUser(b.loginUsername || username);
      const current = await loadUsers(env);
      if (current.some(u => u.username !== username && (u.loginUsername === wantedLogin || u.username === wantedLogin))) return json({ error: 'username_taken' }, 409);
    }
    const group = GROUP_LABELS[b.group] ? b.group : (b.role === 'neighborhood' ? 'mahalle' : 'yonetim');
    const role = group === 'mahalle' ? 'neighborhood' : 'management';
    const hoodsIn = Array.isArray(b.neighborhoods) ? b.neighborhoods : [b.neighborhood];
    const wantedHoods = [...new Set(hoodsIn.map(h => clean(h, 80)).filter(Boolean))].slice(0, 80);
    const orgNow = await getJson(env, K.org, null);
    const orgHoods = (orgNow && orgNow.access && orgNow.access[username]) || [];
    // Teşkilat listesindeki sorumluluklarla aynıysa ayrıca kaydetme (liste güncellenince kendiliğinden değişsin)
    const sameAsOrg = role === 'management' && wantedHoods.length === orgHoods.length && wantedHoods.every(h => orgHoods.includes(h));
    const orgAll = !!(orgNow && Array.isArray(orgNow.allHoods) && orgNow.allHoods.includes(username));
    const overrides = await getJson(env, K.overrides, {});
    overrides[username] = {
      role,
      group,
      neighborhoods: sameAsOrg ? [] : wantedHoods,
      allHoods: b.allHoods === true ? true : (b.allHoods === false && orgAll ? false : undefined),
      disabled: !!b.disabled,
      loginUsername: normalizeUser(b.loginUsername || username) || username,
      name: clean(b.name, 120),
      refName: clean(b.refName, 120),
      password: clean(b.password, 80) || DEFAULT_PASSWORD
    };
    await putJson(env, K.overrides, overrides);
    return json({ ok: true, users: await loadUsers(env) });
  }

  // ---- Arama logları ----
  if (path === '/logs/delete' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    const ids = new Set((Array.isArray(b.ids) ? b.ids : []).map(x => String(x)));
    if (!ids.size) return json({ error: 'ids_required' }, 400);
    const logs = await getJson(env, K.logs, []);
    const kept = logs.filter(l => !ids.has(String(l.id)));
    await putJson(env, K.logs, kept);
    return json({ ok: true, deleted: logs.length - kept.length });
  }
  if (path === '/logs' && method === 'GET') {
    const denied = requireAdmin(); if (denied) return denied;
    return json({ ok: true, logs: await migrateLogs(env, await getJson(env, K.logs, [])) });
  }
  // Kendi kapsamındaki arama durumları (mahalle başkanı: kendi mahallesi; yönetim: tümü)
  if (path === '/logs/scope' && method === 'GET') {
    const logs = await getJson(env, K.logs, []);
    const scoped = logs.filter(l => userCanSeeHood(user, l.neighborhood));
    return json({ ok: true, logs: scoped.map(l => ({ id: l.id, memberId: l.memberId, memberName: l.memberName, neighborhood: l.neighborhood, status: l.status, note: l.note, agent: l.agent, username: l.username, time: l.time })) });
  }
  if (path === '/logs' && method === 'POST') {
    const b = await body();
    if (!b.memberId) return json({ error: 'member_required' }, 400);
    const logs = await getJson(env, K.logs, []);
    const item = {
      id: clean(b.id, 80) || crypto.randomUUID(),
      memberId: clean(b.memberId, 40),
      memberName: clean(b.memberName, 120),
      memberPhone: clean(b.memberPhone, 20),
      neighborhood: clean(b.neighborhood, 80),
      status: clean(b.status, 20) || 'called',
      note: clean(b.note, 2000),
      agent: clean(b.agent, 120) || user.name,
      username: user.username,
      time: b.time || new Date().toISOString()
    };
    const existing = logs.findIndex(l => l.id === item.id);
    if (existing !== -1) logs.splice(existing, 1);
    logs.unshift(item);
    await putJson(env, K.logs, logs.slice(0, 10000));
    return json({ ok: true, log: item });
  }

  // ---- Canlı konum ----
  if (path === '/locations' && method === 'GET') {
    const denied = requireAdmin(); if (denied) return denied;
    const locations = await getJson(env, K.locations, {});
    return json({ ok: true, locations: Object.values(locations).sort((a, b) => String(b.time).localeCompare(String(a.time))) });
  }
  if (path === '/locations' && method === 'POST') {
    const b = await body();
    const lat = Number(b.lat);
    const lng = Number(b.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json({ error: 'location_required' }, 400);
    const locations = await getJson(env, K.locations, {});
    locations[user.username] = { username: user.username, name: user.name, role: user.role, neighborhood: user.neighborhoods[0] || '', lat, lng, accuracy: Number(b.accuracy || 0), time: new Date().toISOString() };
    await putJson(env, K.locations, locations);
    return json({ ok: true });
  }

  // ---- Duyurular ----
  if (path === '/announcements' && method === 'GET') {
    const announcements = await getJson(env, K.announcements, []);
    return json({ ok: true, announcements: admin ? announcements : announcements.filter(a => matchesTarget({ role: user.role }, a.target || 'all')) });
  }
  if (path === '/announcements' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    const text = clean(b.body, 5000);
    if (!text) return json({ error: 'body_required' }, 400);
    const announcements = await getJson(env, K.announcements, []);
    const announcement = { id: crypto.randomUUID(), body: text, target: normalizeTarget(b.target), authorName: b.authorName || 'Hasan Demir', createdAt: new Date().toISOString(), reads: [], likes: [], popup: !!b.popup, action: b.action === 'sandik' ? 'sandik' : '' };
    announcements.unshift(announcement);
    await putJson(env, K.announcements, announcements.slice(0, 100));
    await putJson(env, K.latest, { title: announcement.authorName, body: text, url: b.url || './', sentAt: new Date().toISOString() });
    const result = await pushToTarget(env, announcement.target);
    return json({ ok: true, announcement, ...result });
  }
  if ((path === '/announcements/read' || path === '/announcements/like') && method === 'POST') {
    const b = await body();
    const announcements = await getJson(env, K.announcements, []);
    const item = announcements.find(a => a.id === b.announcementId);
    if (!item) return json({ error: 'not_found' }, 404);
    if (path.endsWith('/like')) item.likes = upsertPerson(item.likes, user);
    item.reads = upsertPerson(item.reads, user);
    await putJson(env, K.announcements, announcements);
    return json({ ok: true });
  }
  if (path.startsWith('/announcements/') && (method === 'PUT' || method === 'DELETE')) {
    const denied = requireAdmin(); if (denied) return denied;
    const id = decodeURIComponent(path.slice('/announcements/'.length));
    const announcements = await getJson(env, K.announcements, []);
    if (method === 'DELETE') {
      await putJson(env, K.announcements, announcements.filter(a => a.id !== id));
      return json({ ok: true });
    }
    const b = await body();
    const item = announcements.find(a => a.id === id);
    if (!item) return json({ error: 'not_found' }, 404);
    const text = clean(b.body, 5000);
    if (!text) return json({ error: 'body_required' }, 400);
    item.body = text;
    if ('popup' in b) item.popup = !!b.popup;
    if ('action' in b) item.action = b.action === 'sandik' ? 'sandik' : '';
    item.updatedAt = new Date().toISOString();
    await putJson(env, K.announcements, announcements);
    return json({ ok: true, announcement: item });
  }

  // ---- Bildirimler ----
  if (path === '/subscribe' && method === 'POST') {
    const b = await body();
    if (!b.subscription || !b.subscription.endpoint) return json({ error: 'subscription_missing' }, 400);
    const id = await sha256Hex(b.subscription.endpoint);
    await env.SUBSCRIPTIONS.put(id, JSON.stringify({ subscription: b.subscription, username: user.username, role: user.role, createdAt: new Date().toISOString() }));
    return json({ ok: true, id });
  }
  if (path === '/send' && method === 'POST') {
    const denied = requireAdmin(); if (denied) return denied;
    const b = await body();
    const payload = { title: clean(b.title, 120) || 'AK Parti Kepez', body: clean(b.body, 2000) || 'Yeni bildirim var.', url: b.url || './', target: normalizeTarget(b.target) };
    await putJson(env, K.latest, { ...payload, sentAt: new Date().toISOString() });
    return json({ ok: true, ...(await pushToTarget(env, payload.target)) });
  }

  return json({ error: 'not_found' }, 404);
}

