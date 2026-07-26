import { requireEnv, env } from './env.js';

const BASES = {
  prod: 'https://reseller.enom.com/interface.asp',
  test: 'https://resellertest.enom.com/interface.asp',
};

function base() {
  const mode = env('ENOM_ENV', 'prod');
  if (!BASES[mode]) {
    console.error(`ENOM_ENV must be "prod" or "test", got "${mode}"`);
    process.exit(1);
  }
  return BASES[mode];
}

/**
 * Enom expects SLD/TLD split on the FIRST dot:
 *   example.com   -> sld=example, tld=com
 *   example.co.uk -> sld=example, tld=co.uk
 */
export function splitDomain(domain) {
  const clean = domain.trim().toLowerCase().replace(/\.$/, '');
  const idx = clean.indexOf('.');
  if (idx <= 0) throw new Error(`"${domain}" is not a valid domain`);
  return { sld: clean.slice(0, idx), tld: clean.slice(idx + 1) };
}

/**
 * Call the Enom reseller API (interface.asp) and parse its line-based
 * key=value text response into an object. Throws on ErrCount > 0.
 */
async function enomCall(command, params = {}) {
  const url = new URL(base());
  url.searchParams.set('command', command);
  url.searchParams.set('uid', requireEnv('ENOM_UID'));
  url.searchParams.set('pw', requireEnv('ENOM_PW'));
  url.searchParams.set('responsetype', 'text');
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));

  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`Enom ${command}: HTTP ${res.status}`);
  const text = await res.text();

  const out = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith(';')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }

  const errCount = parseInt(out.ErrCount || '0', 10);
  if (errCount > 0) {
    const errs = [];
    for (let i = 1; i <= errCount; i++) errs.push(out[`Err${i}`]);
    throw new Error(`Enom ${command} failed: ${errs.filter(Boolean).join('; ')}`);
  }
  if (out.Done !== 'true') {
    throw new Error(`Enom ${command}: response incomplete (Done != true) — possible auth or IP-whitelist problem`);
  }
  return out;
}

/**
 * Records stored in Enom's DNS hosting for a domain.
 * Returns [{ host, type, address, mxpref }]
 */
export async function getHosts(domain) {
  const { sld, tld } = splitDomain(domain);
  const out = await enomCall('GetHosts', { sld, tld });
  const records = [];
  for (let i = 1; out[`HostName${i}`] !== undefined || out[`RecordType${i}`] !== undefined; i++) {
    records.push({
      host: out[`HostName${i}`] ?? '@',
      type: (out[`RecordType${i}`] || '').toUpperCase(),
      address: out[`Address${i}`] ?? '',
      mxpref: out[`MXPref${i}`] !== undefined ? parseInt(out[`MXPref${i}`], 10) : undefined,
    });
  }
  return records;
}

/** Current nameservers registered for the domain at Enom. */
export async function getNameservers(domain) {
  const { sld, tld } = splitDomain(domain);
  const out = await enomCall('GetDNS', { sld, tld });
  const ns = [];
  for (let i = 1; out[`DNS${i}`] !== undefined; i++) {
    if (out[`DNS${i}`]) ns.push(out[`DNS${i}`].toLowerCase());
  }
  return { nameservers: ns, useDns: out.UseDNS };
}

/** Point the domain's registrar NS records at the given nameservers. */
export async function setNameservers(domain, nsList) {
  if (!nsList.length || nsList.length > 12) {
    throw new Error(`ModifyNS needs 1-12 nameservers, got ${nsList.length}`);
  }
  const { sld, tld } = splitDomain(domain);
  const params = { sld, tld };
  nsList.forEach((ns, i) => { params[`NS${i + 1}`] = ns; });
  await enomCall('ModifyNS', params);
}

/**
 * Replace the ENTIRE host record set for a domain (Enom SetHosts is all-or-nothing).
 * hosts: [{ host, type, address, mxpref? }]
 */
export async function setHosts(domain, hosts) {
  const { sld, tld } = splitDomain(domain);
  const params = { sld, tld };
  hosts.forEach((h, idx) => {
    const i = idx + 1;
    params[`HostName${i}`] = h.host;
    params[`RecordType${i}`] = h.type;
    params[`Address${i}`] = h.address;
    if (h.type === 'MX') params[`MXPref${i}`] = h.mxpref ?? 10;
  });
  await enomCall('SetHosts', params);
}

/** Registrar lock state. Returns true when locked. */
export async function getRegLock(domain) {
  const { sld, tld } = splitDomain(domain);
  const out = await enomCall('GetRegLock', { sld, tld });
  return out['reg-lock'] === '1' || out.RegLock === '1';
}

/** Lock/unlock the domain at the registrar (required before a transfer-out). */
export async function setRegLock(domain, locked) {
  const { sld, tld } = splitDomain(domain);
  await enomCall('SetRegLock', { sld, tld, UnlockRegistrar: locked ? '0' : '1' });
}

/**
 * Trigger Enom to EMAIL the EPP/auth code to the registrant contact.
 * Enom does not return EPP codes over the API — email is the only channel.
 */
export async function emailEppKey(domain) {
  const { sld, tld } = splitDomain(domain);
  await enomCall('SynchAuthInfo', { sld, tld, EmailEPP: 'True', RunSynchAutoInfo: 'True' });
}

/** All domains in the Enom account. Uses XML because GetAllDomains' text output is unreliable. */
export async function listDomains() {
  const url = new URL(base());
  url.searchParams.set('command', 'GetAllDomains');
  url.searchParams.set('uid', requireEnv('ENOM_UID'));
  url.searchParams.set('pw', requireEnv('ENOM_PW'));
  url.searchParams.set('responsetype', 'xml');

  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`Enom GetAllDomains: HTTP ${res.status}`);
  const xml = await res.text();

  const errs = [...xml.matchAll(/<Err\d+>([^<]+)<\/Err\d+>/g)].map((m) => m[1]);
  if (errs.length) throw new Error(`Enom GetAllDomains failed: ${errs.join('; ')}`);

  return [...xml.matchAll(/<DomainName>([^<]+)<\/DomainName>/gi)]
    .map((m) => m[1].trim().toLowerCase())
    .filter(Boolean);
}
