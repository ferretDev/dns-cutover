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
import { getPlaybooks, savePlaybook, deletePlaybook } from './lib/playbooks.js';

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

/* ---------- playbook: the full migration pipeline for one domain ---------- */

// Hostnames that must never be proxied — pure-DNS mail infrastructure.
const NOPROXY_PATTERNS = ['pm-bounces', '_domainkey', 'dkim'];

async function runPlaybook(domain, config = {}) {
  const cfg = {
    zone: true, records: true, redirects: true, dmarc: true, unproxy: true, verify: true, cutover: true,
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

    // 3. redirects
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

  /* ---- bulk corrective tools: operate across ALL Cloudflare zones ---- */

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
