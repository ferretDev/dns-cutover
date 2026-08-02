import { requireEnv } from './env.js';

/**
 * AI insights via the Claude API (claude-opus-5, raw HTTP — this project is
 * zero-dependency by design; every API client here is plain fetch).
 * Thinking is on by default on Opus 5 (adaptive); server-side refusal
 * fallbacks are enabled so a safety-classifier decline re-runs on a fallback
 * model instead of failing the request.
 */

const SYSTEM = `You are the analyst built into "dns-cutover", a local DNS operations desk an agency operator uses to migrate ~130 client domains from a source registrar (Enom/GoDaddy/Namecheap/Porkbun) to Cloudflare and manage them afterwards.

You receive the desk's current state as a report: fleet KPIs, per-domain sections (record sync status, nameservers, mail checklists, redirects, uptime probes, diagnostics), and a triage section grouping failures by class.

Failure classes and their fixes in this tool:
- "no-dns": apex doesn't resolve — the Tools drawer has a "Missing @ / www" mirror-fixer; some domains are intentionally mail-only shells.
- "tls-error": origin serves a self-signed/invalid cert — proxy the record (orange-cloud) or install a cert on the origin.
- "origin-error" (CF 52x): origin has no vhost/cert for the hostname — fix on the hosting box (SpinupWP drawer shows zones with no site).
- "dead": origin not answering at all.
- Mail gaps: per-provider checklists (M365/Google) — missing DKIM usually means DKIM was never enabled at the mail tenant; misplaced "dmarc." records have a one-click mirror; SPF over 10 lookups needs include-pruning.
- Record drift: the diff table + record search & bulk edit tool (fleet-wide replace).

Write an insight brief in plain Markdown:
1. One-paragraph headline read of fleet health (call out trend vs. what the data shows, not generic caution).
2. Top risks, ranked, each with WHY it matters and the concrete next action naming the tool/button in this desk.
3. Anomalies or patterns the operator may not have noticed (correlate across sections — shared IPs, common providers, repeated plugins/tenants).
4. A short "do today" list, ordered by leverage.

Be specific to the data given. Never pad with generic best-practice advice the data doesn't support. Keep it tight — the operator is expert and busy.`;

export async function generateInsights(context, focus) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': requireEnv('ANTHROPIC_API_KEY'),
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'server-side-fallback-2026-07-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-opus-5',
      max_tokens: 16000,
      fallbacks: 'default',
      system: SYSTEM,
      messages: [{
        role: 'user',
        content: `${focus ? `Operator focus: ${focus}\n\n` : ''}${context}`,
      }],
    }),
    signal: AbortSignal.timeout(240_000),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Claude API: HTTP ${res.status}${j.error?.message ? ` — ${j.error.message}` : ''}`);
  if (j.stop_reason === 'refusal') throw new Error('Claude declined this request (safety classifiers) — even via fallback.');
  const text = (j.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n');
  if (!text) throw new Error('Empty response from Claude.');
  return { text, model: j.model, usage: j.usage };
}
