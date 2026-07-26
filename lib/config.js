import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const FILE = join(root, 'config.json');

export const CONFIG_KEYS = ['ENOM_UID', 'ENOM_PW', 'ENOM_ENV', 'CF_API_TOKEN', 'CF_ACCOUNT_ID'];

function read() {
  try {
    return JSON.parse(readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

/** Apply stored config to process.env. UI-saved values win over .env so key rotation takes effect immediately. */
export function loadConfig() {
  const cfg = read();
  for (const k of CONFIG_KEYS) {
    if (cfg[k]) process.env[k] = cfg[k];
  }
  return cfg;
}

/** Merge non-empty fields into config.json and re-apply. Empty string clears a key. */
export function saveConfig(partial) {
  const cfg = read();
  for (const k of CONFIG_KEYS) {
    if (partial[k] === undefined) continue;
    if (partial[k] === '') {
      delete cfg[k];
      delete process.env[k];
    } else {
      cfg[k] = String(partial[k]).trim();
    }
  }
  writeFileSync(FILE, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  loadConfig();
  return cfg;
}

/** Never send secrets back to the browser — masked previews only. */
export function maskedConfig() {
  const out = {};
  for (const k of CONFIG_KEYS) {
    const v = process.env[k];
    if (!v) { out[k] = null; continue; }
    out[k] = k === 'ENOM_ENV' ? v : (v.length <= 6 ? '••••' : `${v.slice(0, 3)}…${v.slice(-2)}`);
  }
  return out;
}
