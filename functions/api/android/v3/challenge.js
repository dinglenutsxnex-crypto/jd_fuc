export async function onRequestPost(context) {
  const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
  const challenge = [...challengeBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const expires_at = new Date(Date.now() + 120 * 1000).toISOString();
  return Response.json({
    ok: true,
    challenge,
    activation_challenge: challenge,
    expires_at,
    expires_in_s: 120
  });
}
