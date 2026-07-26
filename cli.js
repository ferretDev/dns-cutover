#!/usr/bin/env node
/**
 * dns-cutover — migrate DNS hosting from Enom to Cloudflare.
 *
 *   list                     List all domains in the Enom account
 *   status  <domain...>      Show Enom NS + Cloudflare zone state
 *   check   <domain...>      Diff Enom host records against the Cloudflare zone
 *   sync    <domain...>      Create missing records in Cloudflare (creates zone if needed)
 *   cutover <domain...>      Verify zones match, then point Enom NS at Cloudflare
 *
 * Flags:
 *   --yes         Skip the cutover confirmation prompt
 *   --force       Cut over even if records are missing in Cloudflare
 *   --proxy-web   Create A/AAAA/CNAME records proxied (orange cloud). Default: DNS-only.
 */

import { createInterface } from 'node:readline/promises';
import * as enom from './lib/enom.js';
import * as cloudflare from './lib/cloudflare.js';
import { fromEnom, fromCloudflare, diff, toCloudflarePayload, fmt } from './lib/records.js';

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const positional = args.filter((a) => !a.startsWith('--'));
const [command, ...domains] = positional;

const ENOM_DNS_SUFFIXES = ['name-services.com', 'enomdns.com', 'registrar-servers.com'];

function ok(msg) { console.log(`  \x1b[32m✓\x1b[0m ${msg}`); }
function warn(msg) { console.log(`  \x1b[33m!\x1b[0m ${msg}`); }
function bad(msg) { console.log(`  \x1b[31m✗\x1b[0m ${msg}`); }
function header(msg) { console.log(`\n\x1b[1m${msg}\x1b[0m`); }

async function confirm(question) {
  if (flags.has('--yes')) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question(`${question} [y/N] `)).trim().toLowerCase();
  rl.close();
  return answer === 'y' || answer === 'yes';
}

/** Load both sides for a domain. Cloudflare zone may be null. */
async function loadDomain(domain) {
  const [hosts, enomNs, zone] = await Promise.all([
    enom.getHosts(domain),
    enom.getNameservers(domain),
    cloudflare.getZone(domain),
  ]);
  const { records: enomRecords, warnings } = fromEnom(hosts, domain);
  const cfRecords = zone ? fromCloudflare(await cloudflare.listRecords(zone.id), domain) : [];
  return { domain, enomRecords, warnings, enomNs, zone, cfRecords };
}

function warnIfEnomNotAuthoritative(state) {
  const onEnomDns = state.enomNs.nameservers.some((ns) =>
    ENOM_DNS_SUFFIXES.some((suffix) => ns.endsWith(suffix)));
  if (!onEnomDns && state.enomNs.nameservers.length) {
    warn(`Registrar NS are NOT Enom's DNS hosting (${state.enomNs.nameservers.join(', ')}).`);
    warn(`Enom's stored host records may be stale — live DNS is served elsewhere. Verify before trusting this diff.`);
  }
}

function printDiff(state) {
  const d = diff(state.enomRecords, state.cfRecords);
  for (const w of state.warnings) warn(w);

  if (!state.zone) {
    bad(`No Cloudflare zone exists for ${state.domain} — run sync to create it.`);
  }
  ok(`Matched: ${d.matched.length} record(s)`);
  if (d.missing.length) {
    bad(`Missing in Cloudflare: ${d.missing.length}`);
    for (const r of d.missing) console.log(`      ${fmt(r)}`);
  }
  if (d.extra.length) {
    warn(`Extra in Cloudflare (not in Enom — left alone): ${d.extra.length}`);
    for (const r of d.extra) console.log(`      ${fmt(r)}`);
  }
  return d;
}

async function cmdList() {
  const list = await enom.listDomains();
  for (const d of list) console.log(d);
  console.error(`\n${list.length} domain(s)`);
}

async function cmdStatus(domain) {
  header(domain);
  const [enomNs, zone] = await Promise.all([
    enom.getNameservers(domain),
    cloudflare.getZone(domain),
  ]);
  console.log(`  Enom registrar NS : ${enomNs.nameservers.join(', ') || '(none)'}`);
  if (zone) {
    console.log(`  Cloudflare zone   : ${zone.status} (id ${zone.id})`);
    console.log(`  Cloudflare NS     : ${(zone.name_servers || []).join(', ')}`);
    const pointed = (zone.name_servers || []).every((ns) => enomNs.nameservers.includes(ns.toLowerCase()));
    if (pointed && zone.name_servers?.length) ok('Registrar NS already point at Cloudflare.');
  } else {
    console.log('  Cloudflare zone   : (does not exist)');
  }
}

async function cmdCheck(domain) {
  header(domain);
  const state = await loadDomain(domain);
  warnIfEnomNotAuthoritative(state);
  const d = printDiff(state);
  return d.missing.length === 0 && state.zone;
}

async function cmdSync(domain) {
  header(domain);
  const state = await loadDomain(domain);
  warnIfEnomNotAuthoritative(state);

  if (!state.enomRecords.length) {
    bad('Enom returned zero host records — refusing to sync an empty zone. Check the domain uses Enom DNS hosting.');
    return false;
  }

  let zone = state.zone;
  if (!zone) {
    zone = await cloudflare.createZone(domain);
    ok(`Created Cloudflare zone (status: ${zone.status})`);
    console.log(`      Assigned NS: ${(zone.name_servers || []).join(', ')}`);
    state.cfRecords = fromCloudflare(await cloudflare.listRecords(zone.id), domain);
  }

  const d = printDiff({ ...state, zone });
  if (!d.missing.length) {
    ok('Nothing to create — zones already match.');
    return true;
  }

  const proxyWeb = flags.has('--proxy-web');
  let created = 0;
  for (const rec of d.missing) {
    try {
      await cloudflare.createRecord(zone.id, toCloudflarePayload(rec, { proxyWeb }));
      ok(`Created ${fmt(rec)}`);
      created++;
    } catch (err) {
      bad(`Failed ${fmt(rec)} — ${err.message}`);
    }
  }
  console.log(`\n  Created ${created}/${d.missing.length}. Records are ${proxyWeb ? 'PROXIED (A/AAAA/CNAME)' : 'DNS-only'}.`);
  return created === d.missing.length;
}

async function cmdCutover(domain) {
  header(domain);
  const state = await loadDomain(domain);

  if (!state.zone) {
    bad('No Cloudflare zone — run sync first.');
    return false;
  }
  const cfNs = (state.zone.name_servers || []).map((ns) => ns.toLowerCase());
  if (!cfNs.length) {
    bad('Cloudflare has not assigned nameservers for this zone yet.');
    return false;
  }

  const d = diff(state.enomRecords, state.cfRecords);
  if (d.missing.length && !flags.has('--force')) {
    bad(`${d.missing.length} record(s) missing in Cloudflare — run sync first, or pass --force.`);
    for (const r of d.missing) console.log(`      ${fmt(r)}`);
    return false;
  }

  const already = cfNs.every((ns) => state.enomNs.nameservers.includes(ns));
  if (already && cfNs.length === state.enomNs.nameservers.length) {
    ok('Registrar NS already point at Cloudflare — nothing to do.');
    return true;
  }

  console.log(`  Current NS : ${state.enomNs.nameservers.join(', ') || '(none)'}`);
  console.log(`  New NS     : ${cfNs.join(', ')}`);
  console.log(`  (rollback: re-run ModifyNS with the current NS above)`);

  if (!(await confirm(`  Point ${domain} at Cloudflare?`))) {
    warn('Skipped.');
    return false;
  }

  await enom.setNameservers(domain, cfNs);
  ok(`NS updated at Enom. Cloudflare zone will activate once the registry change propagates (usually minutes, up to 24h).`);
  return true;
}

async function main() {
  const perDomain = { status: cmdStatus, check: cmdCheck, sync: cmdSync, cutover: cmdCutover };

  if (command === 'list') return cmdList();

  if (!perDomain[command] || !domains.length) {
    console.error('Usage: dns-cutover <list | status|check|sync|cutover <domain...>> [--yes] [--force] [--proxy-web]');
    process.exit(1);
  }

  let allGood = true;
  for (const domain of domains) {
    try {
      const result = await perDomain[command](domain);
      if (result === false) allGood = false;
    } catch (err) {
      bad(`${domain}: ${err.message}`);
      allGood = false;
    }
  }
  console.log('');
  process.exit(allGood ? 0 : 1);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
