import { requireEnv, env } from '../env.js';
import { normRedirectTarget } from '../records.js';

const API = 'https://api.namecheap.com/xml.response';

async function nc(command, params = {}) {
  const url = new URL(API);
  const user = requireEnv('NAMECHEAP_USER');
  url.searchParams.set('ApiUser', user);
  url.searchParams.set('UserName', user);
  url.searchParams.set('ApiKey', requireEnv('NAMECHEAP_KEY'));
  url.searchParams.set('ClientIp', env('NAMECHEAP_CLIENT_IP', '127.0.0.1'));
  url.searchParams.set('Command', command);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  const xml = await res.text();
  const err = xml.match(/<Error[^>]*>([^<]+)<\/Error>/);
  if (err) throw new Error(`Namecheap ${command}: ${err[1]} (API access requires IP whitelisting — set NAMECHEAP_CLIENT_IP)`);
  return xml;
}

const split = (domain) => {
  const i = domain.indexOf('.');
  return { SLD: domain.slice(0, i), TLD: domain.slice(i + 1) };
};

const attrs = (tag) => {
  const out = {};
  for (const m of tag.matchAll(/(\w+)="([^"]*)"/g)) out[m[1]] = m[2];
  return out;
};

export const name = 'Namecheap';
export const caps = { syncBack: false, srv: false, transferBoard: false, epp: false, redirects: true };

export async function listDomains() {
  const domains = [];
  for (let page = 1; page <= 20; page++) {
    const xml = await nc('namecheap.domains.getList', { PageSize: 100, Page: page });
    const found = [...xml.matchAll(/<Domain\s+([^>]*?)\/?>/g)].map((m) => attrs(m[1]).Name).filter(Boolean);
    domains.push(...found.map((d) => d.toLowerCase()));
    if (found.length < 100) break;
  }
  return domains;
}

export async function getZone(domain) {
  const xml = await nc('namecheap.domains.dns.getHosts', split(domain));
  const records = [];
  const redirects = [];
  const warnings = [];
  for (const m of xml.matchAll(/<[Hh]ost\s+([^>]*?)\/?>/g)) {
    const a = attrs(m[1]);
    const type = (a.Type || '').toUpperCase();
    const host = a.Name || '@';
    const fqdn = host === '@' ? domain : `${host.toLowerCase()}.${domain}`;
    const address = a.Address || '';
    if (['URL', 'URL301', 'FRAME'].includes(type)) {
      redirects.push({ name: fqdn, target: normRedirectTarget(address), status: type === 'URL301' ? 301 : 302, enomType: type });
      if (type === 'FRAME') warnings.push(`FRAME on "${host}" is iframe masking — only a real redirect can be recreated.`);
      continue;
    }
    if (!['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA'].includes(type)) {
      warnings.push(`Skipping unsupported ${type} record on "${host}"`);
      continue;
    }
    const rec = { type, name: fqdn, content: type === 'TXT' ? address : address.toLowerCase().replace(/\.$/, '') };
    if (type === 'MX') rec.priority = Number(a.MXPref) || 10;
    records.push(rec);
  }
  return { records, redirects, warnings, errors: [] };
}

export async function getNameservers(domain) {
  const xml = await nc('namecheap.domains.dns.getList', split(domain));
  const ns = [...xml.matchAll(/<Nameserver>([^<]+)<\/Nameserver>/g)].map((m) => m[1].trim().toLowerCase());
  return { nameservers: ns };
}

export async function setNameservers(domain, ns) {
  await nc('namecheap.domains.dns.setCustom', { ...split(domain), Nameservers: ns.join(',') });
}

export async function test() {
  const d = await listDomains();
  return { ok: true, message: `${d.length} domain(s) visible` };
}
