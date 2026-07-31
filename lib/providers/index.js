/**
 * Source-provider registry. A provider is where domains live BEFORE Cloudflare —
 * the registrar/DNS host we read zones from and point NS away from.
 *
 * Interface every provider exports:
 *   name                                  display name
 *   caps                                  { syncBack, srv, transferBoard, epp, redirects }
 *   listDomains()                         -> [domain, ...]
 *   getZone(domain)                       -> { records (canonical), redirects, warnings, errors }
 *   getNameservers(domain)                -> { nameservers: [] }
 *   setNameservers(domain, ns[])
 *   test()                                -> { ok, message }
 * Enom additionally exports sync-back + transfer-prep functions (see caps).
 */
import * as enom from './enom.js';
import * as godaddy from './godaddy.js';
import * as namecheap from './namecheap.js';
import * as porkbun from './porkbun.js';

const REGISTRY = { enom, godaddy, namecheap, porkbun };

export const PROVIDERS = Object.keys(REGISTRY);

export function activeProvider() {
  const key = (process.env.PROVIDER || 'enom').toLowerCase();
  const p = REGISTRY[key];
  if (!p) throw new Error(`Unknown source provider "${key}" — one of: ${PROVIDERS.join(', ')}`);
  return p;
}
