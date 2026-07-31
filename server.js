#!/usr/bin/env node
/**
 * dns-cutover UI server — localhost only, zero dependencies.
 *   node server.js   ->   http://127.0.0.1:8787
 */
import { createServer } from 'node:http';
import { promises as dnsp } from 'node:dns';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as enom from './lib/enom.js';
import * as cloudflare from './lib/cloudflare.js';
import { loadConfig, saveConfig, maskedConfig } from './lib/config.js';
import {
  fromEnom, fromEnomSrv, fromCloudflare, buildRows, toCloudflarePayload, toEnomHost, ENOM_WRITABLE,
} from './lib/records.js';
import { analyzeMail } from './lib/mailcheck.js';
import { getRollbacks, saveRollback, markRolledBack } from './lib/rollback.js';
import { getPlaybooks, savePlaybook, deletePlaybook } from './lib/playbooks.js';
import { getTransfers, recordTransfer } from './lib/transfers.js';

const root = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8899);
loadConfig();

/* ---------- helpers ---------- */

function json(res, status, body) {
  const buf = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(buf) });
  res.end(buf);
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

/** Run tasks with bounded concurrency. */
async function pooled(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i).catch((err) => ({ error: err.message }));
    }
  }));
  return results;
}

/**
 * Identity guards — every write is checked against the domain it claims to
 * belong to, so stale or cross-domain data can never land in the wrong zone.
 */
function assertBelongs(name, domain) {
  const n = (name || '').toLowerCase();
  if (n !== domain && !n.endsWith(`.${domain}`)) {
    throw new Error(`identity guard: record "${name}" does not belong to ${domain} — write refused`);
  }
}
function assertZone(zone, domain) {
  if (zone && zone.name && zone.name.toLowerCase() !== domain) {
    throw new Error(`identity guard: Cloudflare returned zone "${zone.name}" for ${domain} — aborting`);
  }
  return zone;
}

/** Full state for one domain: both zones, NS, aligned rows. */
async function domainState(domain) {
  const [hostsR, srvR, nsR, zoneR] = await Promise.allSettled([
    enom.getHosts(domain),
    enom.getSrvHosts(domain),
    enom.getNameservers(domain),
    cloudflare.getZone(domain),
  ]);
  const errors = [];
  const hosts = hostsR.status === 'fulfilled' ? hostsR.value : (errors.push(`Enom records: ${hostsR.reason.message}`), []);
  const srvHosts = srvR.status === 'fulfilled' ? srvR.value : (errors.push(`Enom SRV records: ${srvR.reason.message}`), []);
  const enomNs = nsR.status === 'fulfilled' ? nsR.value : (errors.push(`Enom NS: ${nsR.reason.message}`), { nameservers: [] });
  const zone = zoneR.status === 'fulfilled' ? assertZone(zoneR.value, domain) : (errors.push(`Cloudflare: ${zoneR.reason.message}`), null);

  const { records: enomRecords, warnings, redirects: enomRedirects } = fromEnom(hosts, domain);
  const srv = fromEnomSrv(srvHosts, domain);
  enomRecords.push(...srv.records);
  warnings.push(...srv.warnings);
  let cfRecords = [];
  let cfRedirects = [];
  if (zone) {
    const [recsR, rulesR] = await Promise.allSettled([
      cloudflare.listRecords(zone.id),
      cloudflare.getRedirectRules(zone.id),
    ]);
    if (recsR.status === 'fulfilled') cfRecords = fromCloudflare(recsR.value, domain);
    else errors.push(`Cloudflare records: ${recsR.reason.message}`);
    if (rulesR.status === 'fulfilled') {
      cfRedirects = rulesR.value.map((r) => ({
        expression: r.expression,
        status: r.action_parameters?.from_value?.status_code,
        target: r.action_parameters?.from_value?.target_url?.value
          ?? r.action_parameters?.from_value?.target_url?.expression,
        description: r.description,
        enabled: r.enabled !== false,
      }));
    } else {
      errors.push(`Cloudflare redirect rules: ${rulesR.reason.message} (token may need "Dynamic URL Redirects" permission)`);
    }
  }
  const redirects = enomRedirects.map((r) => ({
    ...r,
    covered: cfRedirects.some((c) => c.expression?.includes(`"${r.name}"`) && c.target === r.target),
  }));
  const cfNs = (zone?.name_servers || []).map((n) => n.toLowerCase());
  const pointedAtCf = cfNs.length > 0
    && cfNs.every((n) => enomNs.nameservers.includes(n))
    && enomNs.nameservers.length === cfNs.length;

  return {
    domain,
    rows: buildRows(enomRecords, cfRecords),
    mail: analyzeMail(enomRecords, cfRecords, domain),
    rollback: getRollbacks()[domain] || null,
    redirects,
    cfRedirects,
    enomNs: enomNs.nameservers,
    cfNs,
    zone: zone ? { id: zone.id, status: zone.status } : null,
    pointedAtCf,
    warnings,
    errors,
  };
}

/** Sync a set of rows in one direction. Returns per-record results. */
async function syncRecords(domain, direction, keys) {
  const state = await domainState(domain);
  const wanted = new Set(keys || []);
  const all = !keys;
  const results = [];

  if (direction === 'to-cf') {
    let zone = state.zone;
    if (!zone) {
      const created = assertZone(await cloudflare.createZone(domain), domain);
      zone = { id: created.id, status: created.status };
      results.push({ key: '_zone', ok: true, message: `Created Cloudflare zone (NS: ${(created.name_servers || []).join(', ')})` });
    }
    const targets = state.rows.filter((r) => r.status === 'enom-only' && (all || wanted.has(r.key)));
    for (const row of targets) {
      try {
        assertBelongs(row.enom.name, domain);
        await cloudflare.createRecord(zone.id, toCloudflarePayload(row.enom));
        results.push({ key: row.key, ok: true });
      } catch (err) {
        results.push({ key: row.key, ok: false, message: err.message });
      }
    }
  } else if (direction === 'to-enom') {
    const targets = state.rows.filter((r) => r.status === 'cf-only' && (all || wanted.has(r.key)));
    const writable = targets.filter((r) => ENOM_WRITABLE.has(r.cf.type));
    for (const r of targets.filter((t) => !ENOM_WRITABLE.has(t.cf.type))) {
      results.push({ key: r.key, ok: false, message: `Enom SetHosts does not support ${r.cf.type} records` });
    }
    if (writable.length) {
      // SetHosts replaces the whole zone — resubmit current hosts + additions in one call.
      writable.forEach((r) => assertBelongs(r.cf.name, domain));
      const current = await enom.getHosts(domain);
      const additions = writable.map((r) => toEnomHost(r.cf, domain));
      try {
        await enom.setHosts(domain, [...current, ...additions]);
        for (const r of writable) results.push({ key: r.key, ok: true });
      } catch (err) {
        for (const r of writable) results.push({ key: r.key, ok: false, message: err.message });
      }
    }
  } else {
    throw new Error(`Unknown direction "${direction}"`);
  }
  return results;
}

/**
 * Probe one hostname over HTTPS (manual redirects, 10s timeout) and classify.
 * Falls back to plain HTTP to distinguish cert-only failures.
 */
const PROBE_ORDER = { dead: 0, 'origin-error': 1, 'tls-error': 2, 'server-error': 3, 'client-error': 4, 'no-dns': 5, 'pending-zone': 6, live: 7 };

async function probeHost(hostname) {
  const out = {};
  const started = Date.now();
  try {
    const res = await fetch(`https://${hostname}/`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: { 'user-agent': 'dns-cutover-health/1.0' },
    });
    out.ms = Date.now() - started;
    out.status = res.status;
    if (res.status >= 300 && res.status < 400) {
      out.class = 'live';
      out.detail = `→ ${res.headers.get('location') || '(redirect)'}`;
    } else if (res.status >= 200 && res.status < 300) {
      out.class = 'live';
    } else if (res.status >= 520 && res.status <= 526) {
      out.class = 'origin-error';
      out.detail = `Cloudflare ${res.status} — origin refused/misconfigured for this hostname`;
    } else if (res.status >= 500) {
      out.class = 'server-error';
      out.detail = `HTTP ${res.status}`;
    } else {
      out.class = 'client-error';
      out.detail = `HTTP ${res.status}`;
    }
  } catch (e) {
    out.ms = Date.now() - started;
    const reason = String(e.cause?.code || e.name || e.message);
    if (reason === 'ENOTFOUND') {
      out.class = 'no-dns';
      out.detail = 'name does not resolve — no A/AAAA/CNAME in effect, or NS moved away';
      return out;
    }
    if (reason.includes('SELF_SIGNED') || reason.includes('CERT_')) {
      out.class = 'tls-error';
      out.detail = `origin certificate invalid (${reason}) — record is DNS-only; proxy it or install a real cert`;
      return out;
    }
    out.class = 'dead';
    out.detail = reason;
    try {
      const r2 = await fetch(`http://${hostname}/`, { redirect: 'manual', signal: AbortSignal.timeout(8_000) });
      out.class = 'tls-error';
      out.detail = `HTTPS fails (${reason}) but HTTP answers ${r2.status} — certificate problem`;
    } catch { /* both dead — keep 'dead' */ }
  }
  return out;
}

/* ---------- registrar transfers ---------- */

/**
 * RDAP is the truth for transfer progress: registrar of record + status codes
 * (pendingTransfer) straight from the registry, no auth, gaining-registrar agnostic.
 */
async function rdapLookup(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(12_000),
      headers: { accept: 'application/rdap+json' },
    });
    if (!res.ok) return { registrar: null, statuses: [], note: `RDAP ${res.status}` };
    const j = await res.json();
    let registrar = null;
    for (const e of j.entities || []) {
      if ((e.roles || []).includes('registrar')) {
        const fn = (e.vcardArray?.[1] || []).find((v) => v[0] === 'fn');
        registrar = fn?.[3] || e.handle || null;
      }
    }
    return { registrar, statuses: j.status || [] };
  } catch (e) {
    return { registrar: null, statuses: [], note: String(e.cause?.code || e.name) };
  }
}

async function transferRow(domain) {
  const [lockR, wppsR, rdapR] = await Promise.allSettled([
    enom.getRegLock(domain),
    enom.getWppsInfo(domain),
    rdapLookup(domain),
  ]);
  const rdap = rdapR.status === 'fulfilled' ? rdapR.value : { registrar: null, statuses: [] };
  const saved = getTransfers()[domain] || {};
  const statuses = rdap.statuses || [];
  return {
    domain,
    locked: lockR.status === 'fulfilled' ? lockR.value : null,
    lockNote: lockR.status === 'rejected' ? lockR.reason.message : '',
    privacy: wppsR.status === 'fulfilled' ? wppsR.value.exists : null,
    privacyNote: wppsR.status === 'rejected' ? wppsR.reason.message : '',
    registrar: rdap.registrar,
    rdapNote: rdap.note || '',
    pendingTransfer: statuses.some((s) => /pending ?transfer/i.test(s)),
    transferProhibited: statuses.some((s) => /transfer ?prohibited/i.test(s)),
    transferredAway: !!(rdap.registrar && !/enom|tucows/i.test(rdap.registrar)),
    eppSentAt: saved.eppSentAt || null,
    unlockedAt: saved.unlockedAt || null,
    privacyOffAt: saved.privacyOffAt || null,
  };
}

/* ---------- site diagnostics: deep on-demand sweep of a live site ---------- */

const DIAG_UA = 'dns-cutover-diag/1.0';
const diagFetch = (url, timeout = 12_000) =>
  fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(timeout), headers: { 'user-agent': DIAG_UA } });

async function followChain(startUrl, timeout = 12_000, maxHops = 6) {
  let url = startUrl;
  const chain = [];
  let res = null;
  for (let i = 0; i < maxHops; i++) {
    res = await diagFetch(url, timeout);
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      const next = new URL(res.headers.get('location'), url).href;
      if (chain.includes(next)) return { res, url, chain, loop: true };
      chain.push(next);
      url = next;
      continue;
    }
    break;
  }
  return { res, url, chain, loop: false };
}

async function diagnoseSite(domain) {
  const checks = [];
  const add = (label, status, detail = '') => checks.push({ label, status, detail });
  const summary = () => ({
    domain,
    checks,
    fails: checks.filter((c) => c.status === 'fail').length,
    warns: checks.filter((c) => c.status === 'warn').length,
  });

  let res, finalUrl, chain;
  const t0 = Date.now();
  try {
    const out = await followChain(`https://${domain}/`);
    if (out.loop) { add('Redirect loop', 'fail', out.chain.join(' → ')); return summary(); }
    ({ res, url: finalUrl, chain } = out);
  } catch (e) {
    add('Site reachable', 'fail', String(e.cause?.code || e.name || e.message));
    return summary();
  }
  const ms = Date.now() - t0;

  if (res.status >= 200 && res.status < 300) add('Site reachable', 'pass', `${res.status} at ${finalUrl} (${ms}ms)`);
  else add('Site reachable', 'fail', `final status ${res.status} at ${finalUrl}`);
  if (chain.length >= 3) add('Redirect chain', 'warn', `${chain.length} hops: ${chain.join(' → ')}`);
  else if (chain.length) add('Redirect chain', 'pass', chain.join(' → '));
  const finalHost = new URL(finalUrl).hostname;
  if (!finalHost.endsWith(domain)) add('Lands off-domain', 'info', `final host ${finalHost}`);

  const h = res.headers;
  add('Cloudflare proxied', h.get('cf-ray') ? 'pass' : 'info', h.get('cf-ray') ? '' : 'no cf-ray header — served direct (DNS-only)');
  add('HSTS', h.get('strict-transport-security') ? 'pass' : 'warn', h.get('strict-transport-security') ? '' : 'no Strict-Transport-Security header');
  add('X-Content-Type-Options', h.get('x-content-type-options') ? 'pass' : 'warn', h.get('x-content-type-options') ? '' : 'nosniff missing');
  const hasFrameGuard = h.get('content-security-policy') || h.get('x-frame-options');
  add('Clickjacking protection', hasFrameGuard ? 'pass' : 'warn', hasFrameGuard ? '' : 'no CSP or X-Frame-Options');

  let body = '';
  try { body = (await res.text()).slice(0, 400_000); } catch { /* body unavailable */ }
  const lower = body.toLowerCase();

  const noindex = /<meta[^>]+name=["']robots["'][^>]*noindex/i.test(body) || /noindex/i.test(h.get('x-robots-tag') || '');
  add('Indexable (no noindex)', noindex ? 'fail' : 'pass', noindex ? 'noindex present — search engines are excluded!' : '');

  const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim();
  add('Page <title>', title ? 'pass' : 'warn', title ? title.slice(0, 80) : 'missing');
  add('Meta description', /<meta[^>]+name=["']description["']/i.test(body) ? 'pass' : 'warn', '');
  add('<h1> present', /<h1[\s>]/i.test(body) ? 'pass' : 'warn', '');

  const parked = ['welcome to nginx', 'apache2 ubuntu default', 'index of /', 'wp-admin/install.php',
    'this domain is parked', 'account suspended', 'default web site page'].find((s) => lower.includes(s));
  if (parked) add('Placeholder/parked page', 'fail', `page contains "${parked}"`);

  if (finalUrl.startsWith('https://')) {
    const mixed = (body.match(/(?:src|href)=["']http:\/\//gi) || []).length;
    add('Mixed content', mixed ? 'warn' : 'pass', mixed ? `${mixed} http:// reference(s) in HTML` : '');
  }

  try {
    const r = await diagFetch(`http://${domain}/`, 8_000);
    if (r.status >= 300 && r.status < 400 && (r.headers.get('location') || '').startsWith('https://')) add('HTTP → HTTPS redirect', 'pass', '');
    else if (r.status >= 200 && r.status < 300) add('HTTP → HTTPS redirect', 'warn', `plain HTTP serves ${r.status} without redirecting`);
    else add('HTTP → HTTPS redirect', 'info', `HTTP answers ${r.status}`);
  } catch { add('HTTP → HTTPS redirect', 'info', 'plain HTTP not answering'); }

  try {
    const w = await followChain(`https://www.${domain}/`, 8_000);
    if (w.res.status >= 200 && w.res.status < 300) {
      const same = new URL(w.url).hostname.replace(/^www\./, '') === finalHost.replace(/^www\./, '');
      add('www variant', same ? 'pass' : 'warn', same ? '' : `www lands at ${w.url}`);
    } else {
      add('www variant', 'warn', `www final status ${w.res.status}`);
    }
  } catch (e) {
    add('www variant', 'warn', `www unreachable (${String(e.cause?.code || e.name)})`);
  }

  try {
    const rb = await diagFetch(`https://${domain}/robots.txt`, 8_000);
    if (rb.status === 200) {
      const rtxt = (await rb.text()).slice(0, 10_000);
      const blockAll = /user-agent:\s*\*/i.test(rtxt) && /^\s*disallow:\s*\/\s*$/im.test(rtxt);
      add('robots.txt', blockAll ? 'fail' : 'pass', blockAll ? 'Disallow: / for all agents — blocks all crawling!' : '');
    } else {
      add('robots.txt', 'info', `status ${rb.status}`);
    }
  } catch { add('robots.txt', 'info', 'unreachable'); }

  return summary();
}

/* ---------- playbook: the full migration pipeline for one domain ---------- */

// Hostnames that must never be proxied — pure-DNS mail infrastructure.
const NOPROXY_PATTERNS = ['pm-bounces', '_domainkey', 'dkim'];

async function runPlaybook(domain, config = {}) {
  const cfg = {
    zone: true, records: true, apex: true, redirects: true, dmarc: true, unproxy: true, verify: true, cutover: true,
    ...(config.steps || {}),
  };
  const patterns = config.unproxyPatterns?.length ? config.unproxyPatterns : NOPROXY_PATTERNS;
  const steps = [];
  const add = (step, status, detail = '') => steps.push({ step, status, detail });
  let s;
  try {
    // 1. zone
    s = await domainState(domain);
    let zoneId = s.zone?.id;
    if (!cfg.zone) {
      add('zone', 'skip', 'disabled by playbook');
    } else if (zoneId) {
      add('zone', 'skip', `exists (${s.zone.status})`);
    } else {
      const z = assertZone(await cloudflare.createZone(domain), domain);
      zoneId = z.id;
      add('zone', 'ok', `created — NS: ${(z.name_servers || []).join(', ')}`);
    }

    // 2. records
    const missingBefore = s.rows.filter((r) => r.status === 'enom-only').length;
    if (!cfg.records) {
      add('records', 'skip', 'disabled by playbook');
    } else if (!missingBefore && s.zone) {
      add('records', 'skip', 'nothing missing');
    } else {
      const results = await syncRecords(domain, 'to-cf', null);
      const created = results.filter((r) => r.ok && r.key !== '_zone').length;
      const failed = results.filter((r) => r.ok === false);
      add('records', failed.length ? 'warn' : 'ok',
        `${created} created${failed.length ? `, ${failed.length} FAILED (${failed[0].message})` : ''}`);
    }

    // refresh once for the fix steps
    s = await domainState(domain);
    zoneId = s.zone?.id;

    // 3. core address records — a * wildcard does NOT cover the apex
    if (!cfg.apex) {
      add('apex', 'skip', 'disabled by playbook');
    } else if (!zoneId) {
      add('apex', 'skip', 'no zone');
    } else {
      const rawA = await cloudflare.listRecords(zoneId);
      const addr = rawA.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type));
      const apexRec = addr.find((r) => r.name.toLowerCase() === domain);
      const wildcard = addr.find((r) => r.name.toLowerCase() === `*.${domain}`);
      const wwwRec = addr.find((r) => r.name.toLowerCase() === `www.${domain}`);
      const made = [];
      let apexSrc = apexRec;
      if (!apexRec) {
        const src = wildcard || wwwRec;
        if (src) {
          await cloudflare.createRecord(zoneId, { type: src.type, name: domain, content: src.content, ttl: 1, proxied: !!src.proxied });
          made.push(`@ ← ${wildcard ? '*' : 'www'} (${src.type} ${src.content})`);
          apexSrc = src;
        } else {
          const cands = [...new Set(addr.map((r) => r.content))].slice(0, 3);
          add('apex', 'warn', `no @ address record and no */www to mirror${cands.length ? ` — clone candidates: ${cands.join(', ')}` : ' (no address records at all)'}`);
        }
      }
      if (!wwwRec && !wildcard && apexSrc) {
        await cloudflare.createRecord(zoneId, { type: apexSrc.type, name: `www.${domain}`, content: apexSrc.content, ttl: 1, proxied: !!apexSrc.proxied });
        made.push(`www ← @ (${apexSrc.type} ${apexSrc.content})`);
      }
      if (made.length) add('apex', 'ok', made.join('; '));
      else if (apexRec && (wwwRec || wildcard)) add('apex', 'skip', '@ and www covered');
    }

    // 4. redirects
    const uncovered = (s.redirects || []).filter((r) => !r.covered);
    if (!cfg.redirects) {
      add('redirects', 'skip', 'disabled by playbook');
    } else if (!zoneId) {
      add('redirects', 'skip', 'no zone');
    } else if (!uncovered.length) {
      add('redirects', 'skip', s.redirects?.length ? 'all covered' : 'none needed');
    } else {
      const raw = await cloudflare.listRecords(zoneId);
      let made = 0;
      const errs = [];
      for (const r of uncovered) {
        try {
          const hostRecs = raw.filter((x) => x.name.toLowerCase() === r.name && ['A', 'AAAA', 'CNAME'].includes(x.type));
          if (!hostRecs.length) {
            await cloudflare.createRecord(zoneId, { type: 'A', name: r.name, content: '192.0.2.1', ttl: 1, proxied: true });
          } else {
            for (const x of hostRecs.filter((x) => !x.proxied)) await cloudflare.updateRecord(zoneId, x.id, { proxied: true });
          }
          await cloudflare.addRedirectRule(zoneId, { hostname: r.name, target: r.target, status: r.status });
          made++;
        } catch (e) { errs.push(`${r.name}: ${e.message}`); }
      }
      add('redirects', errs.length ? 'warn' : 'ok', `${made}/${uncovered.length} rules created${errs.length ? `; ${errs[0]}` : ''}`);
    }

    // 4. misplaced DMARC
    if (!cfg.dmarc) {
      add('dmarc', 'skip', 'disabled by playbook');
    } else if (!zoneId) {
      add('dmarc', 'skip', 'no zone');
    } else if (s.mail?.misplacedDmarc) {
      await cloudflare.createRecord(zoneId, toCloudflarePayload({
        type: 'TXT', name: `_dmarc.${domain}`, content: s.mail.misplacedDmarc.content,
      }));
      add('dmarc', 'ok', 'mirrored dmarc → _dmarc');
    } else {
      add('dmarc', 'skip', 'no misplaced policy');
    }

    // 5. un-proxy mail hostnames
    if (!cfg.unproxy) {
      add('unproxy', 'skip', 'disabled by playbook');
    } else if (!zoneId) {
      add('unproxy', 'skip', 'no zone');
    } else {
      const rawRecs = await cloudflare.listRecords(zoneId);
      const badProxy = rawRecs.filter((r) => r.proxied && patterns.some((p) => r.name.toLowerCase().includes(p)));
      if (!badProxy.length) {
        add('unproxy', 'skip', 'no proxied mail hostnames');
      } else {
        for (const r of badProxy) await cloudflare.updateRecord(zoneId, r.id, { proxied: false });
        add('unproxy', 'ok', `${badProxy.length} flipped to DNS-only (${badProxy.map((b) => b.name).join(', ')})`);
      }
    }

    // 6. verify (forced whenever cutover is enabled — cutover requires it)
    const wantVerify = cfg.verify || cfg.cutover;
    s = await domainState(domain);
    const missing = s.rows.filter((r) => r.status === 'enom-only').length;
    const matched = s.rows.filter((r) => r.status === 'same').length;
    const cfCount = s.rows.filter((r) => r.cf).length;
    const srvWarn = s.warnings.filter((w) => w.includes('SRV')).length;
    let verified;
    if (!wantVerify) {
      verified = false;
      add('verify', 'skip', 'disabled by playbook');
    } else if (missing > 0) {
      verified = false;
      add('verify', 'fail', `${missing} record(s) still missing in Cloudflare`);
    } else if (s.rows.length === 0) {
      verified = false;
      add('verify', 'fail', 'Enom has zero records and the CF zone is empty — source of truth unclear, cut over manually if intended');
    } else if (matched === 0 && cfCount > 0) {
      verified = true;
      add('verify', 'warn', `Enom empty; CF zone has ${cfCount} manually-curated record(s)`);
    } else {
      verified = true;
      add('verify', srvWarn ? 'warn' : 'ok', `all ${matched} records match${srvWarn ? ` (${srvWarn} broken SRV skipped — see warnings)` : ''}`);
    }
    for (const c of (wantVerify && s.mail?.contamination) || []) {
      if (c.inEnom) {
        add('verify', 'warn', `pre-existing at source: ${c.msg}`);
      } else {
        verified = false;
        add('verify', 'fail', `cross-domain data in Cloudflare only: ${c.msg}`);
      }
    }

    // 7. cutover
    if (!cfg.cutover) add('cutover', 'skip', 'disabled by playbook');
    else if (s.pointedAtCf) add('cutover', 'skip', 'already pointed at Cloudflare');
    else if (!verified) add('cutover', 'blocked', 'verification failed');
    else if (!s.cfNs.length) add('cutover', 'blocked', 'Cloudflare has not assigned nameservers yet');
    else {
      await enom.setNameservers(domain, s.cfNs);
      saveRollback(domain, { previousNs: s.enomNs, newNs: s.cfNs, at: new Date().toISOString() });
      add('cutover', 'ok', `NS → ${s.cfNs.join(', ')} (rollback saved)`);
      s = await domainState(domain);
    }
  } catch (err) {
    add('error', 'fail', err.message);
    s = s || null;
  }
  return { domain, steps, state: s };
}

/* ---------- routes ---------- */

const routes = {
  'GET /api/config': async () => maskedConfig(),

  'POST /api/config': async (req) => {
    saveConfig(await readBody(req));
    return maskedConfig();
  },

  'POST /api/test': async () => {
    const out = {};
    try {
      const domains = await enom.listDomains();
      out.enom = { ok: true, message: `${domains.length} domain(s) visible` };
    } catch (err) {
      out.enom = { ok: false, message: err.message };
    }
    try {
      const zones = await cloudflare.listZones();
      out.cloudflare = { ok: true, message: `${zones.length} zone(s) visible` };
    } catch (err) {
      out.cloudflare = { ok: false, message: err.message };
    }
    return out;
  },

  'GET /api/domains': async () => {
    const [domains, zones] = await Promise.all([enom.listDomains(), cloudflare.listZones()]);
    const zoneByName = new Map(zones.map((z) => [z.name.toLowerCase(), z]));
    return domains.map((d) => {
      const z = zoneByName.get(d);
      return { domain: d, zoneStatus: z ? z.status : null };
    });
  },

  'GET /api/domain': async (req, res, domain) => domainState(domain),

  'POST /api/email-report': async (req) => {
    const { subject, markdown, to } = await readBody(req);
    if (!subject || !markdown) throw new Error('subject and markdown are required');
    if (!process.env.POSTMARK_TOKEN) throw new Error('POSTMARK_TOKEN not set — add it in ⚙ API Keys');
    const from = process.env.REPORT_FROM;
    if (!from) throw new Error('REPORT_FROM not set — must be a verified Postmark sender signature');
    const recipient = (to || process.env.REPORT_TO || '').trim();
    if (!recipient) throw new Error('No recipient — pass one or set REPORT_TO in ⚙ API Keys');
    const escHtml = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const res = await fetch('https://api.postmarkapp.com/email', {
      method: 'POST',
      headers: {
        'X-Postmark-Server-Token': process.env.POSTMARK_TOKEN,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        From: from,
        To: recipient,
        Subject: subject,
        TextBody: markdown,
        HtmlBody: `<pre style="font-family:ui-monospace,Menlo,monospace;font-size:13px;white-space:pre-wrap">${escHtml(markdown)}</pre>`,
        MessageStream: 'outbound',
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`Postmark: ${j.Message || `HTTP ${res.status}`}`);
    return { ok: true, to: recipient, messageId: j.MessageID };
  },

  'GET /api/pending-status': async () => {
    const zones = await cloudflare.listZones();
    const pendingZones = zones.filter((z) => z.status !== 'active');
    return { pending: pendingZones.length, names: pendingZones.map((z) => z.name) };
  },

  'POST /api/activation-check': async () => {
    const zones = await cloudflare.listZones();
    const pending = zones.filter((z) => z.status !== 'active');
    const results = await pooled(pending, 4, async (z) => {
      try {
        await cloudflare.activationCheck(z.id);
        return { name: z.name, ok: true };
      } catch (e) {
        return { name: z.name, ok: false, message: e.message }; // rate-limited checks are fine to skip
      }
    });
    return { checked: results.filter((r) => r?.ok).length, pending: pending.length };
  },

  'GET /api/playbooks': async () => ({ playbooks: getPlaybooks() }),

  'POST /api/playbooks': async (req) => {
    const { name, config } = await readBody(req);
    if (!name?.trim()) throw new Error('Playbook name required');
    savePlaybook(name.trim(), config || {});
    return { playbooks: getPlaybooks() };
  },

  'POST /api/playbooks/delete': async (req) => {
    const { name } = await readBody(req);
    deletePlaybook(name);
    return { playbooks: getPlaybooks() };
  },

  'POST /api/domain/playbook': async (req, res, domain) => {
    const body = await readBody(req);
    let config = body.config;
    if (!config && body.playbook) {
      config = getPlaybooks()[body.playbook];
      if (!config) throw new Error(`Unknown playbook "${body.playbook}"`);
    }
    if (!config) config = { steps: { cutover: body.cutover !== false } }; // legacy shape
    return runPlaybook(domain, config);
  },

  'POST /api/domain/create-zone': async (req, res, domain) => {
    const existing = await cloudflare.getZone(domain);
    if (existing) throw new Error(`Zone already exists (status: ${existing.status}).`);
    const zone = await cloudflare.createZone(domain);
    return {
      ok: true,
      nameServers: zone.name_servers || [],
      plan: zone.plan?.name || 'Free',
      status: zone.status,
      state: await domainState(domain),
    };
  },

  'POST /api/domain/sync': async (req, res, domain) => {
    const { direction = 'to-cf', keys } = await readBody(req);
    return { results: await syncRecords(domain, direction, keys), state: await domainState(domain) };
  },

  'POST /api/domain/cutover': async (req, res, domain) => {
    const state = await domainState(domain);
    if (!state.zone) throw new Error('No Cloudflare zone — sync first.');
    if (!state.cfNs.length) throw new Error('Cloudflare has not assigned nameservers yet.');
    const missing = state.rows.filter((r) => r.status === 'enom-only').length;
    const { force } = await readBody(req);
    if (missing && !force) throw new Error(`${missing} record(s) missing in Cloudflare — sync first or force.`);
    const previous = state.enomNs;
    await enom.setNameservers(domain, state.cfNs);
    saveRollback(domain, { previousNs: previous, newNs: state.cfNs, at: new Date().toISOString() });
    return { ok: true, previousNs: previous, newNs: state.cfNs, state: await domainState(domain) };
  },

  'POST /api/domain/rollback': async (req, res, domain) => {
    const entry = getRollbacks()[domain];
    if (!entry) throw new Error('No rollback snapshot stored for this domain.');
    if (!entry.previousNs?.length) throw new Error('Rollback snapshot has no nameservers — restore manually.');
    await enom.setNameservers(domain, entry.previousNs);
    markRolledBack(domain);
    return { ok: true, restoredNs: entry.previousNs, state: await domainState(domain) };
  },

  'POST /api/domain/redirect': async (req, res, domain) => {
    const { name, target, status = 301 } = await readBody(req);
    if (!name || !target) throw new Error('name and target are required');
    assertBelongs(name, domain);
    const zone = assertZone(await cloudflare.getZone(domain), domain);
    if (!zone) throw new Error('No Cloudflare zone — sync first.');
    const steps = [];

    // A redirect only fires if the host routes through Cloudflare — ensure a proxied record exists.
    const raw = await cloudflare.listRecords(zone.id);
    const hostRecs = raw.filter((r) => r.name.toLowerCase() === name && ['A', 'AAAA', 'CNAME'].includes(r.type));
    if (!hostRecs.length) {
      await cloudflare.createRecord(zone.id, { type: 'A', name, content: '192.0.2.1', ttl: 1, proxied: true });
      steps.push({ ok: true, message: `Created proxied placeholder A record for ${name}` });
    } else {
      for (const r of hostRecs.filter((r) => !r.proxied)) {
        await cloudflare.updateRecord(zone.id, r.id, { proxied: true });
        steps.push({ ok: true, message: `Flipped ${r.type} ${r.name} to proxied` });
      }
    }

    await cloudflare.addRedirectRule(zone.id, { hostname: name, target, status });
    steps.push({ ok: true, message: `Redirect rule created: ${name} → ${target} (${status})` });
    return { steps, state: await domainState(domain) };
  },

  'POST /api/domain/record-update': async (req, res, domain) => {
    const { recordId, type, content, priority, proxied } = await readBody(req);
    if (!recordId) throw new Error('recordId required');
    const zone = assertZone(await cloudflare.getZone(domain), domain);
    if (!zone) throw new Error('No Cloudflare zone.');
    const fields = {};
    if (content !== undefined && content !== '') {
      if (type === 'TXT' && !/^".*"$/.test(content)) {
        fields.content = `"${content}"`;
      } else if (type === 'SRV') {
        const [weight, port, ...target] = content.trim().split(/\s+/);
        fields.data = { weight: Number(weight) || 0, port: Number(port) || 0, target: target.join(''), priority: Number(priority) || 0 };
      } else {
        fields.content = content;
      }
    }
    if (priority !== undefined && type === 'MX') fields.priority = Number(priority);
    if (proxied !== undefined && ['A', 'AAAA', 'CNAME'].includes(type)) fields.proxied = !!proxied;
    if (!Object.keys(fields).length) throw new Error('Nothing to update');
    const updated = await cloudflare.updateRecord(zone.id, recordId, fields);
    return { ok: true, record: { type: updated.type, name: updated.name, content: updated.content, proxied: updated.proxied, priority: updated.priority } };
  },

  'POST /api/domain/mirror-dmarc': async (req, res, domain) => {
    const state = await domainState(domain);
    if (!state.zone) throw new Error('No Cloudflare zone — sync first.');
    const mis = state.mail?.misplacedDmarc;
    if (!mis) throw new Error('No misplaced DMARC found (or _dmarc already exists).');
    await cloudflare.createRecord(state.zone.id, toCloudflarePayload({
      type: 'TXT',
      name: `_dmarc.${domain}`,
      content: mis.content,
    }));
    return {
      ok: true,
      message: `Created _dmarc.${domain} TXT mirroring dmarc.${domain} — DMARC is now actually deployed.`,
      state: await domainState(domain),
    };
  },

  'POST /api/domain/epp': async (req, res, domain) => {
    const { unlock } = await readBody(req);
    const steps = [];
    if (unlock) {
      try {
        await enom.setRegLock(domain, false);
        recordTransfer(domain, { unlockedAt: new Date().toISOString() });
        steps.push({ step: 'unlock', ok: true, message: 'Registrar lock removed' });
      } catch (err) {
        steps.push({ step: 'unlock', ok: false, message: err.message });
      }
    }
    try {
      await enom.emailEppKey(domain);
      recordTransfer(domain, { eppSentAt: new Date().toISOString() });
      steps.push({ step: 'epp', ok: true, message: 'EPP/auth code emailed to the registrant contact' });
    } catch (err) {
      steps.push({ step: 'epp', ok: false, message: err.message });
    }
    return { steps };
  },

  'POST /api/transfer/board': async (req) => {
    const { domains = [] } = await readBody(req);
    const rows = await pooled(domains, 4, transferRow);
    return { rows: rows.filter(Boolean) };
  },

  'POST /api/transfer/action': async (req, res, domain) => {
    if (!domain) throw new Error('Missing ?domain=');
    const { action } = await readBody(req);
    if (action === 'unlock') {
      await enom.setRegLock(domain, false);
      recordTransfer(domain, { unlockedAt: new Date().toISOString() });
      return { ok: true, message: 'Registrar lock removed' };
    }
    if (action === 'privacy-off') {
      await enom.disableWpps(domain);
      recordTransfer(domain, { privacyOffAt: new Date().toISOString() });
      return { ok: true, message: 'WHOIS privacy disabled' };
    }
    if (action === 'epp') {
      await enom.emailEppKey(domain);
      recordTransfer(domain, { eppSentAt: new Date().toISOString() });
      return { ok: true, message: 'EPP/auth code emailed to registrant' };
    }
    throw new Error(`Unknown action "${action}"`);
  },

  'POST /api/transfer/prep': async (req) => {
    const { domains = [] } = await readBody(req);
    const results = [];
    for (const domain of domains) {
      const steps = [];
      try {
        const locked = await enom.getRegLock(domain).catch(() => null);
        if (locked) {
          await enom.setRegLock(domain, false);
          recordTransfer(domain, { unlockedAt: new Date().toISOString() });
          steps.push('unlocked');
        } else {
          steps.push(locked === false ? 'already unlocked' : 'lock state unknown');
        }
      } catch (e) { steps.push(`unlock failed: ${e.message}`); }
      try {
        const wpps = await enom.getWppsInfo(domain).catch(() => null);
        if (wpps?.exists) {
          await enom.disableWpps(domain);
          recordTransfer(domain, { privacyOffAt: new Date().toISOString() });
          steps.push('privacy off');
        } else {
          steps.push('no privacy service');
        }
      } catch (e) { steps.push(`privacy-off failed: ${e.message}`); }
      try {
        await enom.emailEppKey(domain);
        recordTransfer(domain, { eppSentAt: new Date().toISOString() });
        steps.push('EPP emailed');
      } catch (e) { steps.push(`EPP failed: ${e.message}`); }
      results.push({ domain, steps });
    }
    return { results };
  },

  'POST /api/scan': async (req) => {
    const { domains = [] } = await readBody(req);
    const results = await pooled(domains, 4, async (d) => {
      const s = await domainState(d);
      return {
        domain: d,
        missing: s.rows.filter((r) => r.status === 'enom-only').length,
        extra: s.rows.filter((r) => r.status === 'cf-only').length,
        same: s.rows.filter((r) => r.status === 'same').length,
        zoneStatus: s.zone?.status ?? null,
        pointedAtCf: s.pointedAtCf,
        mailProvider: s.mail.provider,
        mailGaps: s.mail.gaps || 0,
        redirectsPending: (s.redirects || []).filter((r) => !r.covered).length,
        errors: s.errors.length,
      };
    });
    return { results };
  },

  /* ---- bulk corrective tools: operate across ALL Cloudflare zones ---- */

  'POST /api/tools/find-missing-apex': async () => {
    const zones = await cloudflare.listZones();
    const fixable = [];
    const unfixable = [];
    await pooled(zones, 6, async (z) => {
      const recs = await cloudflare.listRecords(z.id);
      const addr = recs.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type));
      const apexRec = addr.find((r) => r.name.toLowerCase() === z.name);
      const wildcard = addr.find((r) => r.name.toLowerCase() === `*.${z.name}`);
      const wwwRec = addr.find((r) => r.name.toLowerCase() === `www.${z.name}`);

      if (!apexRec) {
        const src = wildcard || wwwRec; // wildcard does NOT cover apex — that's the bug
        if (src) {
          // Probe www: it's served by the explicit www record or covered by the wildcard,
          // so it exercises exactly the value we'd mirror to @.
          const live = await probeHost(`www.${z.name}`).catch(() => ({ class: 'dead' }));
          fixable.push({
            domain: z.name, zoneId: z.id, target: '@', from: wildcard ? '*' : 'www',
            type: src.type, content: src.content, proxied: !!src.proxied,
            sourceLive: `${live.class}${live.status ? ' ' + live.status : ''}`,
          });
        } else {
          const cands = [...new Set(addr.map((r) => `${r.content} (${r.name.toLowerCase().replace(`.${z.name}`, '')})`))].slice(0, 4);
          unfixable.push({
            domain: z.name,
            note: cands.length ? `no @ / * / www — clone candidates: ${cands.join(', ')}` : 'no address records at all (mail-only/parked?)',
          });
        }
      }

      // www only counts as missing when no wildcard covers it
      if (!wwwRec && !wildcard && apexRec) {
        const live = await probeHost(z.name).catch(() => ({ class: 'dead' }));
        fixable.push({
          domain: z.name, zoneId: z.id, target: 'www', from: '@',
          type: apexRec.type, content: apexRec.content, proxied: !!apexRec.proxied,
          sourceLive: `${live.class}${live.status ? ' ' + live.status : ''}`,
        });
      }
    });
    fixable.sort((a, b) => a.domain.localeCompare(b.domain) || a.target.localeCompare(b.target));
    unfixable.sort((a, b) => a.domain.localeCompare(b.domain));
    return { fixable, unfixable, zonesScanned: zones.length };
  },

  'POST /api/tools/fix-apex': async (req) => {
    const { items = [] } = await readBody(req);
    const results = await pooled(items, 5, async (it) => {
      const name = it.target === 'www' ? `www.${it.domain}` : it.domain;
      assertBelongs(name, it.domain);
      await cloudflare.createRecord(it.zoneId, {
        type: it.type, name, content: it.content, ttl: 1, proxied: !!it.proxied,
      });
      return { domain: it.domain, target: it.target, ok: true };
    });
    return { results };
  },

  'POST /api/tools/find-proxied': async (req) => {
    const { pattern } = await readBody(req);
    if (!pattern || pattern.trim().length < 2) throw new Error('Pattern must be at least 2 characters.');
    const p = pattern.trim().toLowerCase();
    const zones = await cloudflare.listZones();
    const found = [];
    await pooled(zones, 6, async (z) => {
      const recs = await cloudflare.listRecords(z.id);
      for (const r of recs) {
        if (r.proxied && r.name.toLowerCase().includes(p)) {
          found.push({ domain: z.name, zoneId: z.id, recordId: r.id, type: r.type, name: r.name, content: r.content });
        }
      }
    });
    found.sort((a, b) => a.name.localeCompare(b.name));
    return { found, zonesScanned: zones.length };
  },

  'POST /api/tools/unproxy': async (req) => {
    const { items = [] } = await readBody(req);
    const results = await pooled(items, 6, async (it) => {
      await cloudflare.updateRecord(it.zoneId, it.recordId, { proxied: false });
      return { name: it.name, ok: true };
    });
    return { results };
  },

  'POST /api/tools/find-misplaced-dmarc': async () => {
    const zones = await cloudflare.listZones();
    const found = [];
    await pooled(zones, 6, async (z) => {
      const recs = await cloudflare.listRecords(z.id);
      const mis = recs.find((r) => r.type === 'TXT' && r.name.toLowerCase() === `dmarc.${z.name}` && /v=dmarc1/i.test(r.content));
      const real = recs.some((r) => r.type === 'TXT' && r.name.toLowerCase() === `_dmarc.${z.name}`);
      if (mis && !real) {
        found.push({ domain: z.name, zoneId: z.id, content: mis.content.replace(/^"|"$/g, '') });
      }
    });
    found.sort((a, b) => a.domain.localeCompare(b.domain));
    return { found, zonesScanned: zones.length };
  },

  'POST /api/tools/diagnose': async (req) => {
    const { domains = [] } = await readBody(req);
    const results = await pooled(domains, 5, diagnoseSite);
    return { results: results.filter(Boolean) };
  },

  'POST /api/tools/health': async () => {
    const zones = await cloudflare.listZones();
    const results = await pooled(zones, 8, async (z) => {
      if (z.status !== 'active') {
        return { domain: z.name, class: 'pending-zone', detail: `zone ${z.status} — NS not confirmed, edge cert not issued` };
      }
      return { domain: z.name, ...(await probeHost(z.name)) };
    });
    const clean = results.filter(Boolean);
    clean.sort((a, b) => (PROBE_ORDER[a.class] ?? 9) - (PROBE_ORDER[b.class] ?? 9) || a.domain.localeCompare(b.domain));
    return { results: clean, probedAt: new Date().toISOString() };
  },

  'POST /api/domain/probe-hosts': async (req, res, domain) => {
    const zone = assertZone(await cloudflare.getZone(domain), domain);
    if (!zone) throw new Error('No Cloudflare zone.');
    const recs = await cloudflare.listRecords(zone.id);
    const allNames = [...new Set(recs
      .filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type) && !r.name.startsWith('_') && !r.name.includes('._') && !r.name.includes('*'))
      .map((r) => r.name.toLowerCase()))];
    // Service hostnames aren't websites — an HTTP error is their normal state.
    // The meaningful check for them (like MX) is: does the name resolve?
    const SERVICE_PREFIXES = ['autodiscover', 'sip', 'lyncdiscover', 'enterpriseregistration', 'enterpriseenrollment', 'pm-bounces', 'msoid'];
    const isService = (n) => SERVICE_PREFIXES.includes(n.split('.')[0]);
    const webNames = allNames.filter((n) => !isService(n));
    const serviceNames = allNames.filter(isService);
    const results = await pooled(webNames, 6, async (name) => ({ host: name, ...(await probeHost(name)) }));
    const serviceResults = await pooled(serviceNames, 6, async (name) => {
      try {
        const addr = await dnsp.lookup(name);
        return { host: name, class: 'live', detail: `service host — resolves (${addr.address})` };
      } catch {
        return { host: name, class: 'no-dns', detail: 'service host does not resolve' };
      }
    });
    results.push(...serviceResults);
    // MX targets get a resolution check, not an HTTP probe — mail hosts aren't websites.
    const mxTargets = [...new Set(recs.filter((r) => r.type === 'MX').map((r) => r.content.toLowerCase().replace(/\.$/, '')))];
    const mxResults = await pooled(mxTargets, 6, async (t) => {
      try {
        const addr = await dnsp.lookup(t);
        return { host: `MX → ${t}`, class: 'live', detail: `resolves (${addr.address})` };
      } catch {
        return { host: `MX → ${t}`, class: 'no-dns', detail: 'MX target does not resolve — mail is undeliverable' };
      }
    });
    const clean = [...results, ...mxResults].filter(Boolean);
    clean.sort((a, b) => (PROBE_ORDER[a.class] ?? 9) - (PROBE_ORDER[b.class] ?? 9) || a.host.localeCompare(b.host));
    return { results: clean, probedAt: new Date().toISOString() };
  },

  'POST /api/tools/verify-source-ips': async () => {
    const [domains, zones] = await Promise.all([enom.listDomains(), cloudflare.listZones()]);
    const zoneByName = new Map(zones.map((z) => [z.name.toLowerCase(), z]));
    const targets = domains.filter((d) => zoneByName.has(d));
    const mismatches = [];
    await pooled(targets, 4, async (d) => {
      const [hosts, cfRaw] = await Promise.all([
        enom.getHosts(d),
        cloudflare.listRecords(zoneByName.get(d).id),
      ]);
      const { records: enomRecs } = fromEnom(hosts, d);
      const ipsByName = (recs) => {
        const m = new Map();
        for (const r of recs) {
          if (r.type !== 'A' && r.type !== 'AAAA') continue;
          if (r.content === '192.0.2.1') continue; // our redirect placeholders
          const k = `${r.type} ${r.name.toLowerCase()}`;
          if (!m.has(k)) m.set(k, new Set());
          m.get(k).add(r.content);
        }
        return m;
      };
      const enomIps = ipsByName(enomRecs);
      const cfIps = ipsByName(cfRaw.map((r) => ({ type: r.type, name: r.name, content: r.content })));
      for (const [k, eSet] of enomIps) {
        const cSet = cfIps.get(k);
        if (!cSet) continue; // absent in CF = normal diff territory, not drift
        const e = [...eSet].sort().join(', ');
        const c = [...cSet].sort().join(', ');
        if (e !== c) mismatches.push({ domain: d, record: k, enomIps: e, cfIps: c });
      }
    });
    mismatches.sort((a, b) => a.domain.localeCompare(b.domain));
    return { mismatches, domainsChecked: targets.length };
  },

  'POST /api/tools/shared-ips': async () => {
    const zones = await cloudflare.listZones();
    const byIp = new Map();
    await pooled(zones, 6, async (z) => {
      const recs = await cloudflare.listRecords(z.id);
      for (const r of recs) {
        if (r.type !== 'A' && r.type !== 'AAAA') continue;
        if (r.content === '192.0.2.1') continue; // our redirect placeholders
        if (!byIp.has(r.content)) byIp.set(r.content, new Map());
        byIp.get(r.content).set(z.name, [...(byIp.get(r.content).get(z.name) || []), r.name]);
      }
    });
    const shared = [...byIp.entries()]
      .filter(([, domains]) => domains.size >= 2)
      .map(([ip, domains]) => ({
        ip,
        domainCount: domains.size,
        domains: [...domains.keys()].sort(),
      }))
      .sort((a, b) => b.domainCount - a.domainCount);
    return { shared, zonesScanned: zones.length };
  },

  'POST /api/tools/mirror-dmarc-bulk': async (req) => {
    const { items = [] } = await readBody(req);
    const results = await pooled(items, 4, async (it) => {
      await cloudflare.createRecord(it.zoneId, toCloudflarePayload({
        type: 'TXT',
        name: `_dmarc.${it.domain}`,
        content: it.content,
      }));
      return { domain: it.domain, ok: true };
    });
    return { results };
  },

  'POST /api/batch/sync': async (req) => {
    const { domains = [], direction = 'to-cf' } = await readBody(req);
    const results = await pooled(domains, 3, async (domain) => {
      const recResults = await syncRecords(domain, direction, null);
      const failed = recResults.filter((r) => r.ok === false).length;
      return { domain, synced: recResults.filter((r) => r.ok).length, failed };
    });
    return { results };
  },
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
    const html = readFileSync(join(root, 'public', 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // Per-domain routes carry the domain as a query param to keep routing trivial.
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();
  const routeKey = `${req.method} ${path}`;
  const handler = routes[routeKey];
  if (!handler) return json(res, 404, { error: `No route ${routeKey}` });
  const needsDomain = path === '/api/domain' || path.startsWith('/api/domain/');
  if (needsDomain && !domain) return json(res, 400, { error: 'Missing ?domain=' });

  try {
    json(res, 200, await handler(req, res, domain));
  } catch (err) {
    json(res, 500, { error: err.message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`dns-cutover UI -> http://127.0.0.1:${PORT}`);
});
