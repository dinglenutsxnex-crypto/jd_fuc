export async function onRequestPost(context) {
  try {
    await context.request.json();
  } catch {}
  const session_id = crypto.randomUUID();
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const session_token = [...tokenBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const now = Date.now();
  const expires_at = new Date(now + 180 * 1000).toISOString();
  const license_expiry = new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
  return Response.json({
    ok: true,
    status: 'ACTIVE',
    session_id,
    session_token,
    expires_at,
    license_expiry,
    capabilities: 255,
    next_heartbeat_s: 60
  });
}
