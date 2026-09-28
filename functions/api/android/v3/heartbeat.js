export async function onRequestPost(context) {
  let body = {};
  try { body = await context.request.json(); } catch {}
  const session_token = body.session_token || '';
  const session_id = body.session_id || '';
  const hwid = body.hwid || '';
  const expires_at = new Date(Date.now() + 180 * 1000).toISOString();
  return Response.json({
    ok: true,
    session_token,
    expires_at
  });
}
