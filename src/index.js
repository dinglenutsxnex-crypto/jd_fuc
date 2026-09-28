function hexEncode(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
  return new Uint8Array(sig);
}
async function sha256Hex(dataBytes) {
  const d = await crypto.subtle.digest('SHA-256', dataBytes);
  return hexEncode(new Uint8Array(d));
}

async function handleChallenge() {
  const rb = crypto.getRandomValues(new Uint8Array(32));
  const challenge = hexEncode(rb);
  return Response.json({
    ok: true,
    challenge,
    activation_challenge: challenge,
    expires_at: new Date(Date.now() + 120 * 1000).toISOString(),
    expires_in_s: 120
  });
}

async function handleActivate(request) {
  try { await request.json(); } catch {}
  const session_id = crypto.randomUUID();
  const session_token = hexEncode(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  return Response.json({
    ok: true,
    status: 'ACTIVE',
    session_id,
    session_token,
    expires_at: new Date(now + 180 * 1000).toISOString(),
    license_expiry: new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString(),
    capabilities: 255,
    next_heartbeat_s: 60
  });
}

async function handleHeartbeat(request) {
  let body = {};
  try { body = await request.json(); } catch {}
  return Response.json({
    ok: true,
    session_token: body.session_token || '',
    expires_at: new Date(Date.now() + 180 * 1000).toISOString()
  });
}

async function handlePayload(request) {
  let body = {};
  try { body = await request.json(); } catch {
    return Response.json({ ok: false, error: 'bad json' }, { status: 400 });
  }
  const session_id = body.session_id || '';
  const session_token = body.session_token || '';
  const public_key = body.public_key || '';
  const client_nonce = body.client_nonce || '';
  const target_app = body.target_app || 'com.nekki.shadowfightarena';
  const hwid = public_key;

  const payload_server_nonce = hexEncode(crypto.getRandomValues(new Uint8Array(32)));

  // fetch plaintext payload from this repo (raw github). Cache via Cloudflare cache.
  let payloadText;
  try {
    const r = await fetch('https://raw.githubusercontent.com/dinglenutsxnex-crypto/jd_fuc/main/payload.lua', { cf: { cacheTtl: 3600 } });
    if (!r.ok) throw new Error('payload fetch ' + r.status);
    payloadText = await r.text();
  } catch (e) {
    return Response.json({ ok: false, error: 'payload missing: ' + String(e) }, { status: 500 });
  }
  const enc = new TextEncoder();
  const payloadBytes = enc.encode(payloadText);
  const payload_size = String(payloadBytes.length);
  const payload_sha256 = await sha256Hex(payloadBytes);

  const saltBytes = enc.encode(payload_server_nonce);
  const ikmBytes = enc.encode(session_token);
  const prk = await hmacSha256(saltBytes, ikmBytes);
  const infoBytes = enc.encode(`SF4_FEATURE_PAYLOAD_AEAD_KEY_V2|${session_id}|${hwid}|1.0.0|ALL`);
  const infoWithCounter = new Uint8Array(infoBytes.length + 1);
  infoWithCounter.set(infoBytes, 0);
  infoWithCounter[infoBytes.length] = 0x01;
  const aesKeyBytes = (await hmacSha256(prk, infoWithCounter)).slice(0, 32);

  const expiresAtMillis = String(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const expiresIso = new Date(Number(expiresAtMillis)).toISOString();
  const aadPrefixBytes = enc.encode(`${session_id}|1.0.0|ALL|1|${expiresAtMillis}|`);
  const hwidHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(hwid)));
  const aad = new Uint8Array(aadPrefixBytes.length + hwidHash.length);
  aad.set(aadPrefixBytes, 0);
  aad.set(hwidHash, aadPrefixBytes.length);

  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const ctAndTag = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes, additionalData: aad, tagLength: 128 }, aesKey, payloadBytes));
  const ciphertext = hexEncode(ctAndTag.slice(0, ctAndTag.length - 16));
  const tag = hexEncode(ctAndTag.slice(ctAndTag.length - 16));

  return Response.json({
    ok: true,
    protocol: 'v3',
    session_id,
    key_id: 'SF4-PENTEST-01',
    hwid,
    target_app,
    payload_id: 'com.izf.sf4.v3.1_main',
    payload_version: '2.5.0',
    expires: expiresIso,
    client_nonce,
    payload_server_nonce,
    payload_sha256,
    payload_size,
    signature: '00'.repeat(256),
    game_version: '1.0.0',
    payload_generation: 1,
    expires_at: expiresAtMillis,
    iv: hexEncode(ivBytes),
    ciphertext,
    tag
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (request.method === 'POST' && p === '/api/android/v3/challenge') return handleChallenge();
    if (request.method === 'POST' && p === '/api/android/v3/activate') return handleActivate(request);
    if (request.method === 'POST' && p === '/api/android/v3/payload') return handlePayload(request);
    if (request.method === 'POST' && p === '/api/android/v3/heartbeat') return handleHeartbeat(request);
    if ((p === '/' || p === '') && request.method === 'GET') return new Response('doc\n', { headers: { 'content-type': 'text/html' } });
    return new Response('Not Found', { status: 404 });
  }
};
