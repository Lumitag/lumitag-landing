import { getStore } from '@netlify/blobs';

export default async (req, context) => {
  if (req.method === 'OPTIONS') {
    return new Response('', { status: 204 });
  }
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  // --- Rate limit: 5 reports/hour per IP (check only, increment after success) ---
  const ip = req.headers.get('x-nf-client-connection-ip') || 'unknown';
  const store = getStore({ name: 'rate-limits', consistency: 'strong' });
  const rateKey = `report:${ip}`;
  let rateData = null;
  try {
    const raw = await store.get(rateKey);
    const oneHourAgo = Date.now() - 3_600_000;
    if (raw) {
      rateData = JSON.parse(raw);
      rateData.timestamps = rateData.timestamps.filter((t) => t > oneHourAgo);
      if (rateData.timestamps.length >= 5) {
        return Response.json({ error: 'rate_limited' }, { status: 429 });
      }
    }
  } catch (e) {
    console.warn('Rate limit check failed, allowing request:', e.message);
  }

  // --- Parse + validate ---
  let body;
  try {
    body = JSON.parse(await req.text());
  } catch {
    return Response.json({ error: 'invalid_json' }, { status: 400 });
  }

  const { version, os, python, gpu_tier, models, log_tail } = body;
  if (!version || typeof version !== 'string') {
    return Response.json({ error: 'missing_version' }, { status: 400 });
  }

  // --- Sanitize ---
  const safe = (v, max) => String(v ?? 'unknown').slice(0, max);
  const safeTail = (Array.isArray(log_tail) ? log_tail.join('\n') : String(log_tail ?? '')).slice(0, 60_000);
  const safeModels = (Array.isArray(models) ? models.join(', ') : String(models ?? 'unknown')).slice(0, 200);

  // --- Build GitHub Issue ---
  const issueBody = [
    `**Version**: ${safe(version, 30)}`,
    `**OS**: ${safe(os, 100)}`,
    `**Python**: ${safe(python, 20)}`,
    `**GPU tier**: ${safe(gpu_tier, 10)}`,
    `**Models**: ${safeModels}`,
    '',
    '<details><summary>Log tail</summary>',
    '',
    '```',
    safeTail,
    '```',
    '</details>',
  ].join('\n');

  // Return early — acknowledge receipt, create issue in background
  const backgroundWork = (async () => {
    try {
      const ghRes = await fetch(
        'https://api.github.com/repos/Lumitag/lumitag/issues',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.GITHUB_ISSUES_TOKEN}`,
            Accept: 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'lumitag-netlify-function',
          },
          body: JSON.stringify({
            title: `[user-report] Lumitag ${safe(version, 30)}`,
            body: issueBody,
            labels: ['user-report'],
          }),
        }
      );

      if (!ghRes.ok) {
        console.error('GitHub API error:', ghRes.status, await ghRes.text());
        return;
      }

      // Increment rate limit after success
      try {
        if (rateData) {
          rateData.timestamps.push(Date.now());
        } else {
          rateData = { timestamps: [Date.now()] };
        }
        await store.set(rateKey, JSON.stringify(rateData));
      } catch (e) {
        console.warn('Rate limit update failed:', e.message);
      }
    } catch (e) {
      console.error('Background issue creation failed:', e.message);
    }
  })();

  // Use waitUntil to keep function alive for background work
  context.waitUntil(backgroundWork);

  return Response.json({ ok: true, accepted: true });
};

export const config = { path: '/api/report-bug' };
