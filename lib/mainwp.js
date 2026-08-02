import { requireEnv } from './env.js';

/**
 * MainWP Dashboard REST API v2 (enable in MainWP → Settings → REST API,
 * generate a consumer key/secret). Shapes are best-effort — verify on first use.
 */
function base() {
  return requireEnv('MAINWP_URL').replace(/\/+$/, '');
}

async function mw(path, opts = {}) {
  const url = new URL(`${base()}/wp-json/mainwp/v2${path}`);
  url.searchParams.set('consumer_key', requireEnv('MAINWP_KEY'));
  url.searchParams.set('consumer_secret', requireEnv('MAINWP_SECRET'));
  const res = await fetch(url, {
    ...opts,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    signal: AbortSignal.timeout(60_000),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok || j.success === false || j.code) {
    throw new Error(`MainWP ${path}: HTTP ${res.status}${j.message ? ` — ${j.message}` : ''}`);
  }
  return j;
}

const count = (v) => {
  if (v == null || v === '') return 0;
  if (typeof v === 'number') return v;
  if (Array.isArray(v)) return v.length;
  if (typeof v === 'object') return Object.keys(v).length;
  try { return count(JSON.parse(v)); } catch { return 0; }
};

export async function listSites() {
  const j = await mw('/sites/all-sites');
  const sites = Array.isArray(j) ? j : (j.data || j.sites || []);
  return sites.map((s) => ({
    id: s.id ?? s.site_id,
    name: s.name || s.title || '',
    url: String(s.url || '').replace(/\/+$/, '').toLowerCase(),
    coreUpdates: count(s.wp_upgrades),
    pluginUpdates: count(s.plugin_upgrades),
    themeUpdates: count(s.theme_upgrades),
    offline: s.offline_check_result === -1 || s.sync_errors ? true : false,
  }));
}

/** what: 'plugins' | 'themes' | 'wordpress' */
export async function updateSite(id, what) {
  return mw(`/site/${id}/update/${what}`, { method: 'POST' });
}
