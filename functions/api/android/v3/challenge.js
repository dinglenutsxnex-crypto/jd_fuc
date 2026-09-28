export async function onRequestPost(context) {
  const challenge = '17b4b8f1ec2f7235c60f27e869fe48872a7944668f04e31cca1489ccc145ce69'; // static known-good
  
  const expires_at = new Date(Date.now() + 120 * 1000).toISOString();
  return Response.json({
    ok: true,
    challenge,
    activation_challenge: challenge,
    expires_at,
    expires_in_s: 120
  });
}
