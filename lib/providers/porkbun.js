import { requireEnv } from '../env.js';

const API = 'https://api.porkbun.com/api/json/v3';

async function pb(path, extra = {}) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apikey: requireEnv('PORKBUN_KEY'),
      secretapikey: requireEnv('PORKBUN_SECRET'),
      ...extra,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  const j = await res.json().catch(() => ({}));
  if (j.status !== 'SUCCESS') throw new Error(`Porkbun ${path}: ${j.message || `HTTP ${res.status}`}`);
  return j;
}

export const name = 'Porkbun';
export const caps = { syncBack: false, srv: true, transferBoard: false, epp: false, redirects: false };

export async function listDomains() {
  const j = await pb('/domain/listAll');
  return (j.domains || []).map((d) => d.domain.toLowerCase());
}

export async function getZone(domain) {
  const j = await pb(`/dns/retrieve/${domain}`);
  const records = [];
  const warnings = [];
  for (const r of j.records || []) {
    const type = (r.type || '').toUpperCase();
    if (!['A', 'AAAA', 'CNAME', 'TXT', 'NS', 'MX', 'SRV', 'CAA'].includes(type)) {
      warnings.push(`Skipping unsupported ${type} record on "${r.name}"`);
      continue;
    }
    const fqdn = (r.name || domain).toLowerCase().replace(/\.$/, '');
    if (type === 'NS' && fqdn === domain) continue;
    const rec = { type, name: fqdn, content: type === 'TXT' ? String(r.content ?? '') : String(r.content ?? '').toLowerCase().replace(/\.$/, '') };
    if (type === 'MX') rec.priority = Number(r.prio) || 10;
    if (type === 'SRV') {
      rec.priority = Number(r.prio) || 0;
      warnings.push(`SRV ${fqdn} imported as-is — verify weight/port/target shape after sync.`);
    }
    records.push(rec);
  }
  return { records, redirects: [], warnings, errors: [] };
}

export async function getNameservers(domain) {
  const j = await pb(`/domain/getNs/${domain}`);
  return { nameservers: (j.ns || []).map((n) => n.toLowerCase()) };
}

export async function setNameservers(domain, ns) {
  await pb(`/domain/updateNs/${domain}`, { ns });
}

export async function test() {
  const d = await listDomains();
  return { ok: true, message: `${d.length} domain(s) visible` };
}
