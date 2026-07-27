#!/usr/bin/env node
/**
 * dns-cutover UI server — localhost only, zero dependencies.
 *   node server.js   ->   http://127.0.0.1:8787
 */
import { createServer } from 'node:http';
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
  const zone = zoneR.status === 'fulfilled' ? zoneR.value : (errors.push(`Cloudflare: ${zoneR.reason.message}`), null);

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
      const created = await cloudflare.createZone(domain);
      zone = { id: created.id, status: created.status };
      results.push({ key: '_zone', ok: true, message: `Created Cloudflare zone (NS: ${(created.name_servers || []).join(', ')})` });
    }
    const targets = state.rows.filter((r) => r.status === 'enom-only' && (all || wanted.has(r.key)));
    for (const row of targets) {
      try {
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
    const zone = await cloudflare.getZone(domain);
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

  'POST /api/domain/epp': async (req, res, domain) => {
    const { unlock } = await readBody(req);
    const steps = [];
    if (unlock) {
      try {
        await enom.setRegLock(domain, false);
        steps.push({ step: 'unlock', ok: true, message: 'Registrar lock removed' });
      } catch (err) {
        steps.push({ step: 'unlock', ok: false, message: err.message });
      }
    }
    try {
      await enom.emailEppKey(domain);
      steps.push({ step: 'epp', ok: true, message: 'EPP/auth code emailed to the registrant contact' });
    } catch (err) {
      steps.push({ step: 'epp', ok: false, message: err.message });
    }
    return { steps };
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
