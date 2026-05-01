import { createHmac, createPrivateKey, sign, randomInt, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import nodemailer from 'nodemailer';

export default async (req) => {
  console.log('[WEBHOOK] === Paddle webhook invoked ===');
  console.log('[WEBHOOK] Method:', req.method);

  if (req.method !== 'POST') {
    console.log('[WEBHOOK] Rejected: not POST');
    return new Response('Method not allowed', { status: 405 });
  }

  const rawBody = await req.text();
  console.log('[WEBHOOK] Body length:', rawBody.length);

  // --- Verify Paddle webhook signature ---
  const sigHeader = req.headers.get('paddle-signature') || '';
  console.log('[WEBHOOK] Signature header:', sigHeader.substring(0, 80) + '...');

  const parts = Object.fromEntries(
    sigHeader.split(';').map((p) => p.split('=', 2))
  );
  const ts = parts.ts;
  const h1 = parts.h1;

  if (!ts || !h1) {
    console.error('[WEBHOOK] FAIL: Missing ts or h1 in signature header');
    return new Response('Missing signature', { status: 401 });
  }

  console.log('[WEBHOOK] ts:', ts, '| h1 length:', h1?.length);
  console.log('[WEBHOOK] Time diff (s):', Math.abs(Date.now() / 1000 - Number(ts)));

  // Replay protection: reject if timestamp > 5 min old
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    console.error('[WEBHOOK] FAIL: Timestamp too old');
    return new Response('Timestamp too old', { status: 401 });
  }

  const secret = process.env.PADDLE_WEBHOOK_SECRET || '';
  console.log('[WEBHOOK] Secret present:', !!secret, '| length:', secret.length, '| starts:', secret.substring(0, 8));

  const signedPayload = `${ts}:${rawBody}`;
  const expected = createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');

  console.log('[WEBHOOK] Expected (first 16):', expected.substring(0, 16));
  console.log('[WEBHOOK] Actual h1 (first 16):', h1.substring(0, 16));
  console.log('[WEBHOOK] Expected length:', expected.length, '| h1 length:', h1.length);

  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(h1, 'hex');

  if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
    console.error('[WEBHOOK] FAIL: Signature mismatch!');
    console.error('[WEBHOOK] signedPayload (first 100):', signedPayload.substring(0, 100));
    return new Response('Invalid signature', { status: 401 });
  }

  console.log('[WEBHOOK] ✓ Signature valid');

  // --- Parse event ---
  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (e) {
    console.error('[WEBHOOK] FAIL: Invalid JSON:', e.message);
    return new Response('Invalid JSON', { status: 400 });
  }

  console.log('[WEBHOOK] Event type:', event.event_type);

  if (event.event_type !== 'transaction.completed') {
    console.log('[WEBHOOK] Ignored (not transaction.completed)');
    return new Response('Ignored', { status: 200 });
  }

  const txnId = event.data?.id;
  const customerId = event.data?.customer_id;
  console.log('[WEBHOOK] txnId:', txnId, '| customerId:', customerId);

  if (!txnId || !customerId) {
    console.error('[WEBHOOK] FAIL: Missing txn/customer id');
    return new Response('Missing txn/customer id', { status: 400 });
  }

  // --- Idempotency: check Blobs first ---
  let licenseKey;
  try {
    const store = getStore({ name: 'licenses', consistency: 'strong' });
    const existing = await store.get(txnId);
    console.log('[WEBHOOK] Blob lookup:', existing ? 'FOUND (reuse)' : 'NOT FOUND (generate new)');

    if (existing) {
      licenseKey = existing;
    } else {
      // Generate Ed25519 license key
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let payload = '';
      for (let i = 0; i < 8; i++) {
        payload += chars[randomInt(chars.length)];
      }

      const rawPem = process.env.ED25519_PRIVATE_KEY || '';
      // Handle both literal \n and real newlines, and missing headers
      let pem = rawPem.replace(/\\n/g, '\n').trim();
      if (!pem.includes('-----BEGIN')) {
        pem = `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
      }
      console.log('[WEBHOOK] ED25519 key present:', !!rawPem, '| length:', rawPem.length, '| has headers:', pem.includes('-----BEGIN'));

      const key = createPrivateKey(pem);
      const signature = sign(null, Buffer.from(payload), key);
      const sig64 = signature.toString('base64url');

      licenseKey = `LT-${payload}.${sig64}`;
      await store.set(txnId, licenseKey);
      console.log('[WEBHOOK] ✓ License key generated and stored');
    }
  } catch (e) {
    console.error('[WEBHOOK] FAIL: Key generation/blob error:', e.message);
    return new Response('Internal error', { status: 500 });
  }

  // --- Get customer email from Paddle API ---
  let email = '';
  try {
    const apiKey = process.env.PADDLE_API_KEY || '';
    console.log('[WEBHOOK] PADDLE_API_KEY present:', !!apiKey, '| length:', apiKey.length);

    const url = `https://api.paddle.com/customers/${customerId}`;
    console.log('[WEBHOOK] Fetching:', url);

    const customerRes = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });

    console.log('[WEBHOOK] Customer API status:', customerRes.status);

    if (customerRes.ok) {
      const customerData = await customerRes.json();
      email = customerData.data?.email || '';
      console.log('[WEBHOOK] Email resolved:', email ? email : 'EMPTY');
    } else {
      const errBody = await customerRes.text();
      console.error('[WEBHOOK] Customer API error body:', errBody.substring(0, 200));
    }
  } catch (e) {
    console.error('[WEBHOOK] Customer API fetch failed:', e.message);
  }

  if (!email) {
    console.warn('[WEBHOOK] No email — key available via polling only. Key:', licenseKey.substring(0, 10) + '...');
    return new Response('OK', { status: 200 });
  }

  // --- Send email via Gmail SMTP ---
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

  try {
    console.log('[WEBHOOK] GMAIL_USER:', process.env.GMAIL_USER || 'NOT SET');
    console.log('[WEBHOOK] GMAIL_APP_PASSWORD present:', !!process.env.GMAIL_APP_PASSWORD);

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: 'LumiTag <lumitag.support@gmail.com>',
      to: email,
      subject: 'Your LumiTag Pro License Key',
      html,
    });

    console.log('[WEBHOOK] ✓ Email sent to:', email);
  } catch (e) {
    console.error('[WEBHOOK] SMTP send failed:', e.message);
  }

  console.log('[WEBHOOK] === Done ===');
  return new Response('OK', { status: 200 });
};

export const config = { path: '/api/paddle-webhook' };
