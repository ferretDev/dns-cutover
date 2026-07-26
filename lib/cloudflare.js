import { requireEnv, env } from './env.js';

const API = 'https://api.cloudflare.com/client/v4';

async function cf(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${requireEnv('CF_API_TOKEN')}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.success === false) {
    const msgs = (json.errors || []).map((e) => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Cloudflare ${method} ${path} failed (HTTP ${res.status}) ${msgs}`);
  }
  return json;
}

/** Find a zone by exact name. Returns the zone object or null. */
export async function getZone(name) {
  const json = await cf(`/zones?name=${encodeURIComponent(name.toLowerCase())}`);
  return json.result?.[0] ?? null;
}

/** Create a zone (full setup). Requires CF_ACCOUNT_ID. */
export async function createZone(name) {
  const accountId = requireEnv('CF_ACCOUNT_ID');
  const json = await cf('/zones', {
    method: 'POST',
    body: { name: name.toLowerCase(), account: { id: accountId }, type: 'full' },
  });
  return json.result;
}

/** All DNS records in a zone (paginated). */
export async function listRecords(zoneId) {
  const records = [];
  let page = 1;
  for (;;) {
    const json = await cf(`/zones/${zoneId}/dns_records?per_page=100&page=${page}`);
    records.push(...json.result);
    const info = json.result_info;
    if (!info || page >= info.total_pages) break;
    page++;
  }
  return records;
}

/** All zones in the account (paginated). Returns [{ name, id, status, name_servers }]. */
export async function listZones() {
  const zones = [];
  let page = 1;
  for (;;) {
    const json = await cf(`/zones?per_page=50&page=${page}`);
    zones.push(...json.result);
    const info = json.result_info;
    if (!info || page >= info.total_pages) break;
    page++;
  }
  return zones;
}

/** Create one DNS record. `rec` is already in Cloudflare's shape. */
export async function createRecord(zoneId, rec) {
  const json = await cf(`/zones/${zoneId}/dns_records`, { method: 'POST', body: rec });
  return json.result;
}

export function proxyDefault() {
  return env('CF_PROXY_WEB', 'false') === 'true';
}

/** Patch fields on an existing DNS record (e.g. flip proxied on). */
export async function updateRecord(zoneId, recordId, fields) {
  const json = await cf(`/zones/${zoneId}/dns_records/${recordId}`, { method: 'PATCH', body: fields });
  return json.result;
}

const REDIRECT_PHASE = 'http_request_dynamic_redirect';

/** Single Redirect rules for a zone. Empty array when no ruleset exists yet. */
export async function getRedirectRules(zoneId) {
  try {
    const json = await cf(`/zones/${zoneId}/rulesets/phases/${REDIRECT_PHASE}/entrypoint`);
    return json.result?.rules || [];
  } catch (err) {
    if (/HTTP 404/.test(err.message)) return [];
    throw err;
  }
}

/** Replace the zone's Single Redirect rules. Rules must be clean (no ids/versions). */
export async function setRedirectRules(zoneId, rules) {
  const json = await cf(`/zones/${zoneId}/rulesets/phases/${REDIRECT_PHASE}/entrypoint`, {
    method: 'PUT',
    body: { rules },
  });
  return json.result?.rules || [];
}

/** Append one redirect rule, preserving existing ones. */
export async function addRedirectRule(zoneId, { hostname, target, status = 301, description }) {
  const existing = await getRedirectRules(zoneId);
  const clean = existing.map((r) => ({
    expression: r.expression,
    action: r.action,
    action_parameters: r.action_parameters,
    description: r.description,
    enabled: r.enabled !== false,
  }));
  clean.push({
    // Wildcard hosts (*.example.com) need the `wildcard` operator; exact hosts use eq.
    expression: hostname.startsWith('*')
      ? `http.host wildcard "${hostname}"`
      : `http.host eq "${hostname}"`,
    action: 'redirect',
    action_parameters: {
      from_value: {
        status_code: status,
        target_url: { value: target },
        preserve_query_string: false,
      },
    },
    description: description || `enom-migrate: ${hostname}`,
    enabled: true,
  });
  return setRedirectRules(zoneId, clean);
}
