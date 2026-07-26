import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const FILE = join(dirname(dirname(fileURLToPath(import.meta.url))), 'rollbacks.json');

function read() {
  try {
    return JSON.parse(readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function getRollbacks() {
  return read();
}

/** Persist the pre-cutover NS for a domain. Never overwrites the ORIGINAL entry —
 *  the first snapshot is the true rollback target even across repeated cutovers. */
export function saveRollback(domain, entry) {
  const all = read();
  if (!all[domain]) {
    all[domain] = entry;
    writeFileSync(FILE, JSON.stringify(all, null, 2) + '\n');
  }
  return all[domain];
}

export function markRolledBack(domain) {
  const all = read();
  if (all[domain]) {
    all[domain].rolledBackAt = new Date().toISOString();
    writeFileSync(FILE, JSON.stringify(all, null, 2) + '\n');
  }
  return all[domain];
}
