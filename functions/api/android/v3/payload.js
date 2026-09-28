function hexEncode(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
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

export async function onRequestPost(context) {
  let body = {};
  try { body = await context.request.json(); } catch (e) {
    return Response.json({ ok: false, error: 'bad json' }, { status: 400 });
  }
  const session_id = body.session_id || '';
  const session_token = body.session_token || '';
  const public_key = body.public_key || '';
  const client_nonce = body.client_nonce || '';
  const game_version = body.game_version || '1.0.0';
  const target_app = body.target_app || 'com.nekki.shadowfightarena';
  const hwid = public_key;

  // server nonce (salt): fresh 32 random bytes hex (64 hex chars)
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const payload_server_nonce = hexEncode(nonceBytes);

  // fetch plaintext payload (static file deployed alongside)
  let payloadText;
  try {
    const url = new URL('/payload.lua', context.request.url);
    const r = await fetch(url);
    if (!r.ok) throw new Error('payload fetch ' + r.status);
    payloadText = await r.text();
  } catch (e) {
    return Response.json({ ok: false, error: 'payload missing: ' + String(e) }, { status: 500 });
  }
  const enc = new TextEncoder();
  const payloadBytes = enc.encode(payloadText);
  const payload_size = String(payloadBytes.length);
  const payload_sha256 = await sha256Hex(payloadBytes);

  // HKDF: salt = server_nonce UTF8, IKM = session_token UTF8
  // PRK = HMAC(salt, IKM)
  // info = "SF4_FEATURE_PAYLOAD_AEAD_KEY_V2|<session_id>|<hwid>|1.0.0|ALL" + 0x01
  // key = HMAC(PRK, info)[:32]
  const saltBytes = enc.encode(payload_server_nonce);
  const ikmBytes = enc.encode(session_token);
  const prk = await hmacSha256(saltBytes, ikmBytes);
  const infoStr = `SF4_FEATURE_PAYLOAD_AEAD_KEY_V2|${session_id}|${hwid}|1.0.0|ALL`;
  const infoBytes = enc.encode(infoStr);
  const infoWithCounter = new Uint8Array(infoBytes.length + 1);
  infoWithCounter.set(infoBytes, 0);
  infoWithCounter[infoBytes.length] = 0x01;
  const okmFull = await hmacSha256(prk, infoWithCounter);
  const aesKeyBytes = okmFull.slice(0, 32);

  // AAD = "<session_id>|1.0.0|ALL|1|<expires_at>|" UTF8 + SHA256(hwid UTF8) raw
  const expiresAtMillis = String(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const expiresIso = new Date(Number(expiresAtMillis)).toISOString();
  const aadPrefixStr = `${session_id}|1.0.0|ALL|1|${expiresAtMillis}|`;
  const aadPrefixBytes = enc.encode(aadPrefixStr);
  const hwidHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(hwid)));
  const aad = new Uint8Array(aadPrefixBytes.length + hwidHash.length);
  aad.set(aadPrefixBytes, 0);
  aad.set(hwidHash, aadPrefixBytes.length);

  // AES-GCM encrypt
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const ctAndTagBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes, additionalData: aad, tagLength: 128 }, aesKey, payloadBytes);
  const ctAndTag = new Uint8Array(ctAndTagBuf);
  const ciphertextBytes = ctAndTag.slice(0, ctAndTag.length - 16);
  const tagBytes = ctAndTag.slice(ctAndTag.length - 16);

  const iv = hexEncode(ivBytes);
  const ciphertext = hexEncode(ciphertextBytes);
  const tag = hexEncode(tagBytes);
  // RSA signature bypassed on client (patched to always verify). Return 512 zeros (256 bytes).
  const signature = '00'.repeat(256);

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
    signature,
    game_version: '1.0.0',
    payload_generation: 1,
    expires_at: expiresAtMillis,
    iv,
    ciphertext,
    tag
  });
}
