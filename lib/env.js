import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// Tiny .env loader — no dependency. Real env vars win over .env values.
try {
  const raw = readFileSync(join(root, '.env'), 'utf8');
  for (const line of raw.split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    const [, key, valRaw] = m;
    if (process.env[key] !== undefined) continue;
    process.env[key] = valRaw.replace(/^["']|["']$/g, '');
  }
} catch {
  // no .env file — fine, rely on real environment
}

export function requireEnv(key) {
  const val = process.env[key];
  if (!val) {
    throw new Error(`Missing credential ${key} — set it in the UI settings, .env, or the environment`);
  }
  return val;
}

export function env(key, fallback = undefined) {
  return process.env[key] ?? fallback;
}
