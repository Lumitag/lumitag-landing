import { createHmac, createPrivateKey, sign, randomInt, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';

export default async (req) => {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const rawBody = await req.text();

  // --- Verify Paddle webhook signature ---
  const sigHeader = req.headers.get('paddle-signature') || '';
  const parts = Object.fromEntries(
    sigHeader.split(';').map((p) => p.split('=', 2))
  );
  const ts = parts.ts;
  const h1 = parts.h1;
  if (!ts || !h1) {
    return new Response('Missing signature', { status: 401 });
  }

  // Replay protection: reject if timestamp > 60s old
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 60) {
    return new Response('Timestamp too old', { status: 401 });
  }

  const expected = createHmac('sha256', process.env.PADDLE_WEBHOOK_SECRET)
    .update(`${ts}:${rawBody}`)
    .digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(h1, 'hex');
  if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
    return new Response('Invalid signature', { status: 401 });
  }

  // --- Parse event ---
  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }
  if (event.event_type !== 'transaction.completed') {
    return new Response('Ignored', { status: 200 });
  }

  const txnId = event.data?.id;
  const customerId = event.data?.customer_id;
  if (!txnId || !customerId) {
    return new Response('Missing txn/customer id', { status: 400 });
  }

  // --- Idempotency: check Blobs first ---
  const store = getStore({ name: 'licenses', consistency: 'strong' });
  const existing = await store.get(txnId);
  let licenseKey;

  if (existing) {
    licenseKey = existing;
  } else {
    // Generate Ed25519 license key
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let payload = '';
    for (let i = 0; i < 8; i++) {
      payload += chars[randomInt(chars.length)];
    }

    const pem = process.env.ED25519_PRIVATE_KEY.replace(/\\n/g, '\n');
    const key = createPrivateKey(pem);
    const signature = sign(null, Buffer.from(payload), key);
    const sig64 = signature.toString('base64url'); // no padding by default

    licenseKey = `LT-${payload}.${sig64}`;
    await store.set(txnId, licenseKey);
  }

  // --- Get customer email from Paddle API ---
  let email = '';
  try {
    const customerRes = await fetch(
      `https://api.paddle.com/customers/${customerId}`,
      { headers: { Authorization: `Bearer ${process.env.PADDLE_API_KEY}` } }
    );
    if (customerRes.ok) {
      const customerData = await customerRes.json();
      email = customerData.data?.email || '';
    } else {
      console.error('Paddle customer API error:', customerRes.status);
    }
  } catch (e) {
    console.error('Paddle customer API fetch failed:', e.message);
  }

  if (!email) {
    console.warn(`No email for ${txnId} — key available via polling only`);
    return new Response('OK', { status: 200 });
  }

  // --- Send email via Resend ---
  const html = `
<!DOCTYPE html>
<html><body style="margin:0;padding:0;font-family:system-ui,-apple-system,sans-serif;background:#f5f5f0">
<div style="max-width:520px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden">
  <div style="background:#7c9a82;padding:32px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:24px">🏷️ LumiTag Pro</h1>
  </div>
  <div style="padding:32px">
    <p style="color:#333;font-size:16px;line-height:1.5">Thank you for your purchase! Here is your license key:</p>
    <div style="background:#f0f4f1;border:2px solid #7c9a82;border-radius:8px;padding:16px;text-align:center;margin:24px 0">
      <code style="font-size:18px;color:#2d3b30;letter-spacing:1px;word-break:break-all">${licenseKey}</code>
    </div>
    <p style="color:#333;font-size:14px;line-height:1.6"><strong>To activate:</strong></p>
    <ol style="color:#555;font-size:14px;line-height:1.8">
      <li>Open LumiTag</li>
      <li>Go to <strong>Settings → License</strong></li>
      <li>Paste the key above and click <strong>Activate</strong></li>
    </ol>
    <p style="color:#999;font-size:12px;margin-top:32px;text-align:center">
      Keep this email — you'll need the key if you reinstall.
    </p>
  </div>
</div>
</body></html>`;

  const emailRes = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'LumiTag <onboarding@resend.dev>',
      to: [email],
      subject: 'Your LumiTag Pro License Key',
      html,
    }),
  });
  if (!emailRes.ok) {
    console.error('Resend API error:', emailRes.status, await emailRes.text());
    // Key is already in Blobs — user can still get it via polling
  }

  return new Response('OK', { status: 200 });
};

export const config = { path: '/api/paddle-webhook' };
