const COOKIE_NAME = 'auth_token';

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  try {
    // Expire cookie immediately
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT` + (process.env.COOKIE_SECURE ? '; Secure' : ''));
    return res.status(200).json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'Server Error', details: String(e) });
  }
};