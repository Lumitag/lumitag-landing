import { createPrivateKey, sign, randomInt } from 'node:crypto';

export default async (req) => {
  // Only allow with a secret query param (so it's not publicly exploitable)
  const url = new URL(req.url);
  if (url.searchParams.get('secret') !== process.env.PADDLE_WEBHOOK_SECRET?.substring(0, 10)) {
    return new Response('Unauthorized', { status: 401 });
  }

  console.log('[TEST] === Testing key generation ===');

  const rawPem = process.env.ED25519_PRIVATE_KEY || '';
  console.log('[TEST] Raw PEM length:', rawPem.length);
  console.log('[TEST] Raw PEM first 30:', rawPem.substring(0, 30));

  let pem = rawPem.replace(/\\n/g, '\n').trim();
  console.log('[TEST] After replace length:', pem.length);
  console.log('[TEST] Has headers:', pem.includes('-----BEGIN'));

  if (!pem.includes('-----BEGIN')) {
    pem = `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
    console.log('[TEST] Added headers, new length:', pem.length);
  }

  try {
    const key = createPrivateKey(pem);
    console.log('[TEST] ✓ createPrivateKey succeeded');

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let payload = '';
    for (let i = 0; i < 8; i++) {
      payload += chars[randomInt(chars.length)];
    }

    const signature = sign(null, Buffer.from(payload), key);
    const sig64 = signature.toString('base64url');
    const licenseKey = `LT-${payload}.${sig64}`;

    console.log('[TEST] ✓ License key generated:', licenseKey.substring(0, 15) + '...');
    return new Response(JSON.stringify({ ok: true, key: licenseKey }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (e) {
    console.error('[TEST] ✗ FAIL:', e.message);
    return new Response(JSON.stringify({ ok: false, error: e.message, pemLength: pem.length }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

export const config = { path: '/api/test-keygen' };
