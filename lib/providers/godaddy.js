import { requireEnv } from '../env.js';

const API = 'https://api.godaddy.com/v1';

async function gd(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      Authorization: `sso-key ${requireEnv('GODADDY_KEY')}:${requireEnv('GODADDY_SECRET')}`,
      'Content-Type': 'application/json',
    },
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    let msg = '';
    try { msg = (await res.json()).message || ''; } catch { /* no body */ }
    throw new Error(`GoDaddy ${path}: HTTP ${res.status}${msg ? ` — ${msg}` : ''}`);
  }
  return res.status === 204 ? null : res.json();
}

export const name = 'GoDaddy';
export const caps = { syncBack: false, srv: true, transferBoard: false, epp: false, redirects: false };

export async function listDomains() {
  const j = await gd('/domains?statuses=ACTIVE&limit=1000');
  return j.map((d) => d.domain.toLowerCase());
}

export async function getZone(domain) {
  const recs = await gd(`/domains/${domain}/records`);
  const records = [];
  const warnings = [];
  for (const r of recs || []) {
    const type = (r.type || '').toUpperCase();
    if (!['A', 'AAAA', 'CNAME', 'TXT', 'NS', 'MX', 'SRV', 'CAA'].includes(type)) {
      warnings.push(`Skipping unsupported ${type} record on "${r.name}"`);
      continue;
    }
    const fqdn = !r.name || r.name === '@' ? domain : `${r.name.toLowerCase()}.${domain}`;
    if (type === 'NS' && fqdn === domain) continue; // apex NS = old delegation, not content
    const rec = { type, name: fqdn, content: String(r.data ?? '').replace(/\.$/, '') };
    if (type === 'TXT') rec.content = String(r.data ?? '');
    if (type === 'MX') rec.priority = r.priority ?? 10;
    if (type === 'SRV') {
      rec.name = `${r.service || ''}.${r.protocol || ''}.${domain}`.replace(/^\.+/, '').toLowerCase();
      rec.content = `${r.weight ?? 0} ${r.port ?? 0} ${String(r.data || '').replace(/\.$/, '').toLowerCase()}`;
      rec.priority = r.priority ?? 0;
    }
    records.push(rec);
  }
  return { records, redirects: [], warnings, errors: [] };
}

export async function getNameservers(domain) {
  const j = await gd(`/domains/${domain}`);
  return { nameservers: (j.nameServers || []).map((n) => n.toLowerCase()) };
}

export async function setNameservers(domain, ns) {
  await gd(`/domains/${domain}`, { method: 'PATCH', body: JSON.stringify({ nameServers: ns }) });
}

export async function test() {
  const d = await listDomains();
  return { ok: true, message: `${d.length} domain(s) visible` };
}
