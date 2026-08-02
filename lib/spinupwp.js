import { requireEnv } from './env.js';

const API = 'https://api.spinupwp.app/v1';

async function sw(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${requireEnv('SPINUPWP_TOKEN')}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(20_000),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`SpinupWP ${path}: HTTP ${res.status}${j.message ? ` — ${j.message}` : ''}`);
  return j;
}

async function paged(path) {
  const out = [];
  let page = 1;
  for (;;) {
    const j = await sw(`${path}${path.includes('?') ? '&' : '?'}page=${page}&limit=100`);
    const data = j.data || [];
    out.push(...data);
    const hasNext = j.pagination?.next ?? (data.length === 100);
    if (!hasNext || page >= 20) break;
    page++;
  }
  return out;
}

export const listServers = () => paged('/servers');
export const listSites = () => paged('/sites');
export const getSite = (id) => sw(`/sites/${id}`);
export const updateSite = (id, fields) => sw(`/sites/${id}`, { method: 'PATCH', body: JSON.stringify(fields) });
export const backupSite = (id) => sw(`/sites/${id}/backups`, { method: 'POST', body: JSON.stringify({}) });
