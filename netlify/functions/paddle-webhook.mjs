import { createHmac, createPrivateKey, sign, randomInt, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import nodemailer from 'nodemailer';

// ---------------------------------------------------------------------------
// Email templates
// ---------------------------------------------------------------------------

const LOGO_URL = 'https://lumitag.netlify.app/screenshots/icon.png';
const SUPPORT_EMAIL = 'lumitag.support@gmail.com';
const SITE_URL = 'https://lumitag.netlify.app';

function emailHtml(licenseKey, lang) {
  const t = lang === 'pl' ? {
    title: 'Twój klucz licencyjny',
    thanks: 'Dziękujemy za zakup! Oto Twój klucz licencyjny:',
    activate: 'Jak aktywować:',
    step1: 'Otwórz LumiTag',
    step2: 'Przejdź do <strong>Ustawienia → Licencja</strong>',
    step3: 'Wklej powyższy klucz i kliknij <strong>Aktywuj</strong>',
    keep: 'Zachowaj tego maila — klucz będzie potrzebny przy reinstalacji.<br>Nie udostępniaj tego klucza innym osobom.',
    help: 'Problemy? Napisz do nas:',
  } : {
    title: 'Your License Key',
    thanks: 'Thank you for your purchase! Here is your license key:',
    activate: 'To activate:',
    step1: 'Open LumiTag',
    step2: 'Go to <strong>Settings → License</strong>',
    step3: 'Paste the key above and click <strong>Activate</strong>',
    keep: 'Keep this email — you\'ll need the key if you reinstall.<br>Do not share this license key with others.',
    help: 'Need help? Contact us:',
  };

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#f5f4f0;">
<div style="max-width:540px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">

  <!-- Header -->
  <div style="background:#4a6b50;padding:28px 32px;text-align:center;">
    <img src="${LOGO_URL}" alt="LumiTag" width="48" height="48" style="display:block;margin:0 auto 12px;">
    <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:600;">LumiTag Pro</h1>
  </div>

  <!-- Body -->
  <div style="padding:32px;">
    <h2 style="margin:0 0 8px;color:#2d3b30;font-size:18px;font-weight:600;">${t.title}</h2>
    <p style="color:#555;font-size:15px;line-height:1.5;margin:0 0 24px;">${t.thanks}</p>

    <!-- License key block -->
    <div style="background:#f0f4f1;border:2px solid #7c9a82;border-radius:8px;padding:20px;text-align:center;margin:0 0 28px;">
      <code style="font-family:'SF Mono','Cascadia Code','Consolas',monospace;font-size:15px;color:#2d3b30;letter-spacing:0.5px;word-break:break-all;line-height:1.6;-webkit-user-select:all;user-select:all;cursor:pointer;">${licenseKey}</code>
    </div>

    <!-- Activation steps -->
    <p style="color:#2d3b30;font-size:14px;font-weight:600;margin:0 0 8px;">${t.activate}</p>
    <ol style="color:#555;font-size:14px;line-height:2;margin:0 0 28px;padding-left:20px;">
      <li>${t.step1}</li>
      <li>${t.step2}</li>
      <li>${t.step3}</li>
    </ol>

    <p style="color:#888;font-size:12px;margin:0;text-align:center;">${t.keep}</p>
  </div>

  <!-- Footer -->
  <div style="background:#f9f8f6;padding:20px 32px;border-top:1px solid #eee;text-align:center;">
    <p style="margin:0;color:#999;font-size:12px;">
      ${t.help} <a href="mailto:${SUPPORT_EMAIL}" style="color:#4a6b50;text-decoration:none;">${SUPPORT_EMAIL}</a>
    </p>
    <p style="margin:8px 0 0;color:#bbb;font-size:11px;">
      <a href="${SITE_URL}" style="color:#bbb;text-decoration:none;">lumitag.app</a>
    </p>
  </div>

</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------

export default async (req) => {
  console.log('[WEBHOOK] === Paddle webhook invoked ===');

  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const rawBody = await req.text();
  console.log('[WEBHOOK] Body length:', rawBody.length);

  // --- Verify Paddle webhook signature ---
  const sigHeader = req.headers.get('paddle-signature') || '';
  const parts = Object.fromEntries(
    sigHeader.split(';').map((p) => p.split('=', 2))
  );
  const ts = parts.ts;
  const h1 = parts.h1;

  if (!ts || !h1) {
    console.error('[WEBHOOK] FAIL: Missing ts or h1');
    return new Response('Missing signature', { status: 401 });
  }

  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    console.error('[WEBHOOK] FAIL: Timestamp too old');
    return new Response('Timestamp too old', { status: 401 });
  }

  const secret = process.env.PADDLE_WEBHOOK_SECRET || '';
  const expected = createHmac('sha256', secret)
    .update(`${ts}:${rawBody}`)
    .digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(h1, 'hex');

  if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
    console.error('[WEBHOOK] FAIL: Signature mismatch');
    return new Response('Invalid signature', { status: 401 });
  }

  console.log('[WEBHOOK] ✓ Signature valid');

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
  const currencyCode = event.data?.currency_code || 'USD';
  console.log('[WEBHOOK] txnId:', txnId, '| customerId:', customerId, '| currency:', currencyCode);

  if (!txnId || !customerId) {
    return new Response('Missing txn/customer id', { status: 400 });
  }

  // --- Idempotency: check Blobs first ---
  let licenseKey;
  try {
    const store = getStore({ name: 'licenses', consistency: 'strong' });
    const existing = await store.get(txnId);

    if (existing) {
      licenseKey = existing;
      console.log('[WEBHOOK] Reusing existing key');
    } else {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let payload = '';
      for (let i = 0; i < 8; i++) {
        payload += chars[randomInt(chars.length)];
      }

      const rawPem = process.env.ED25519_PRIVATE_KEY || '';
      let pem = rawPem.replace(/\\n/g, '\n').trim();
      if (!pem.includes('-----BEGIN')) {
        pem = `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
      }

      const key = createPrivateKey(pem);
      const signature = sign(null, Buffer.from(payload), key);
      const sig64 = signature.toString('base64url');

      licenseKey = `LT-${payload}.${sig64}`;
      await store.set(txnId, licenseKey);
      console.log('[WEBHOOK] ✓ Key generated');
    }
  } catch (e) {
    console.error('[WEBHOOK] FAIL: Key generation:', e.message);
    return new Response('Internal error', { status: 500 });
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
      console.error('[WEBHOOK] Customer API error:', customerRes.status);
    }
  } catch (e) {
    console.error('[WEBHOOK] Customer API failed:', e.message);
  }

  if (!email) {
    console.warn('[WEBHOOK] No email — key in Blobs only');
    return new Response('OK', { status: 200 });
  }

  console.log('[WEBHOOK] Email:', email, '| Currency:', currencyCode);

  // --- Send email ---
  const lang = currencyCode === 'PLN' ? 'pl' : 'en';
  const subject = lang === 'pl'
    ? 'Twój klucz licencyjny LumiTag Pro'
    : 'Your LumiTag Pro License Key';
  const html = emailHtml(licenseKey, lang);

  try {
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
      from: `LumiTag <${process.env.GMAIL_USER}>`,
      to: email,
      subject,
      html,
    });

    console.log('[WEBHOOK] ✓ Email sent (' + lang + ')');
  } catch (e) {
    console.error('[WEBHOOK] SMTP failed:', e.message);
  }

  return new Response('OK', { status: 200 });
};

export const config = { path: '/api/paddle-webhook' };
