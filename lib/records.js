/**
 * Normalization + diffing between Enom host records and Cloudflare DNS records.
 * Everything is compared in a canonical shape:
 *   { type, name (fqdn, lowercase), content (normalized), priority? }
 */

const MAPPABLE = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA']);
// Enom redirect pseudo-records — no DNS equivalent, must be handled in Cloudflare rules manually.
const UNMAPPABLE = new Set(['URL', 'URL301', 'FRAME']);

function normHostname(host, domain) {
  const h = (host || '@').trim().toLowerCase().replace(/\.$/, '');
  if (h === '' || h === '@') return domain;
  if (h === domain || h.endsWith(`.${domain}`)) return h; // already fqdn
  return `${h}.${domain}`;
}

function normContent(type, content) {
  let c = (content || '').trim();
  switch (type) {
    case 'CNAME':
    case 'MX':
    case 'NS':
      return c.toLowerCase().replace(/\.$/, '');
    case 'TXT': {
      // Join split quoted segments ("part1" "part2" -> part1part2), strip outer quotes.
      if (/^".*"$/.test(c)) {
        c = c.replace(/"\s+"/g, '').replace(/^"|"$/g, '');
      }
      return c;
    }
    default:
      return c;
  }
}

export function key(rec) {
  const parts = [rec.type, rec.name, normContent(rec.type, rec.content)];
  if (rec.type === 'MX') parts.push(String(rec.priority ?? 10));
  return parts.join('|');
}

const REDIRECT_STATUS = { URL: 302, URL301: 301, FRAME: 302 };

/**
 * Enom -> canonical. Returns { records, warnings, redirects }.
 * Enom's legacy "SPF" record type is folded into TXT.
 * URL/URL301/FRAME pseudo-records come back as structured `redirects`
 * so they can be recreated as Cloudflare redirect rules.
 */
export function fromEnom(hosts, domain) {
  const records = [];
  const warnings = [];
  const redirects = [];
  for (const h of hosts) {
    let type = h.type;
    if (type === 'SPF') type = 'TXT';
    if (UNMAPPABLE.has(type)) {
      redirects.push({
        name: normHostname(h.host, domain),
        target: (h.address || '').trim(),
        status: REDIRECT_STATUS[type],
        enomType: type,
      });
      if (type === 'FRAME') {
        warnings.push(`Enom FRAME on "${h.host}" is iframe masking — Cloudflare can only do a real redirect (302). The URL bar will change.`);
      }
      continue;
    }
    if (!MAPPABLE.has(type)) {
      warnings.push(`Skipping unsupported Enom record type ${type} on "${h.host}" (${h.address}).`);
      continue;
    }
    const rec = {
      type,
      name: normHostname(h.host, domain),
      content: normContent(type, h.address),
    };
    if (type === 'MX') rec.priority = Number.isFinite(h.mxpref) ? h.mxpref : 10;
    records.push(rec);
  }
  return { records, warnings, redirects };
}

/** Cloudflare -> canonical. Skips the NS records Cloudflare auto-manages at the apex. */
export function fromCloudflare(cfRecords, domain) {
  const records = [];
  for (const r of cfRecords) {
    if (r.type === 'NS' && r.name.toLowerCase() === domain) continue;
    const rec = {
      type: r.type,
      name: r.name.toLowerCase(),
      content: normContent(r.type, r.content),
      proxied: r.proxied,
    };
    if (r.type === 'MX') rec.priority = r.priority ?? 10;
    records.push(rec);
  }
  return records;
}

/**
 * Diff canonical record sets.
 *   missing — in Enom, not in Cloudflare (needs creating)
 *   extra   — in Cloudflare, not in Enom (reported, never deleted)
 *   matched — present in both
 */
export function diff(enomRecs, cfRecs) {
  const cfKeys = new Set(cfRecs.map(key));
  const enomKeys = new Set(enomRecs.map(key));
  return {
    missing: enomRecs.filter((r) => !cfKeys.has(key(r))),
    extra: cfRecs.filter((r) => !enomKeys.has(key(r))),
    matched: enomRecs.filter((r) => cfKeys.has(key(r))),
  };
}

/** Canonical record -> Cloudflare create payload. */
export function toCloudflarePayload(rec, { proxyWeb = false } = {}) {
  // Cloudflare requires TXT content quoted (it quotes on your behalf otherwise;
  // being explicit avoids ambiguity). Our diff strips quotes, so matching is unaffected.
  const content = rec.type === 'TXT' && !/^".*"$/.test(rec.content)
    ? `"${rec.content}"`
    : rec.content;
  const payload = {
    type: rec.type,
    name: rec.name,
    content,
    ttl: 1, // "auto"
  };
  if (rec.type === 'MX') payload.priority = rec.priority ?? 10;
  if (['A', 'AAAA', 'CNAME'].includes(rec.type)) payload.proxied = proxyWeb;
  return payload;
}

const TYPE_ORDER = ['NS', 'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA'];
// Record types Enom's SetHosts accepts — SRV/CAA can't be pushed CF -> Enom.
export const ENOM_WRITABLE = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']);

/**
 * Align both zones into top-down side-by-side rows for the diff UI.
 * Every record from both sides appears exactly once:
 *   { key, status: 'same' | 'enom-only' | 'cf-only', enom?, cf? }
 */
export function buildRows(enomRecs, cfRecs) {
  const cfByKey = new Map(cfRecs.map((r) => [key(r), r]));
  const seen = new Set();
  const rows = [];
  for (const r of enomRecs) {
    const k = key(r);
    const match = cfByKey.get(k);
    rows.push(match ? { key: k, status: 'same', enom: r, cf: match } : { key: k, status: 'enom-only', enom: r });
    seen.add(k);
  }
  for (const r of cfRecs) {
    const k = key(r);
    if (!seen.has(k)) rows.push({ key: k, status: 'cf-only', cf: r });
  }
  rows.sort((a, b) => {
    const ra = a.enom || a.cf, rb = b.enom || b.cf;
    const nameCmp = ra.name.split('.').reverse().join('.').localeCompare(rb.name.split('.').reverse().join('.'));
    if (nameCmp !== 0) return nameCmp;
    const t = TYPE_ORDER.indexOf(ra.type) - TYPE_ORDER.indexOf(rb.type);
    if (t !== 0) return t;
    return (ra.content || '').localeCompare(rb.content || '');
  });
  return rows;
}

/** Canonical record -> Enom host shape (relative hostname). */
export function toEnomHost(rec, domain) {
  const host = rec.name === domain ? '@' : rec.name.replace(new RegExp(`\\.${domain.replace(/\./g, '\\.')}$`), '');
  const h = { host, type: rec.type, address: rec.content };
  if (rec.type === 'MX') h.mxpref = rec.priority ?? 10;
  return h;
}

export function fmt(rec) {
  const prio = rec.type === 'MX' ? ` ${rec.priority}` : '';
  return `${rec.type.padEnd(5)} ${rec.name}  ->${prio} ${rec.content}`;
}
