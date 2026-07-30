import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const FILE = join(dirname(dirname(fileURLToPath(import.meta.url))), 'transfers.json');

function read() {
  try {
    return JSON.parse(readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function getTransfers() {
  return read();
}

/** Merge fields into a domain's transfer record (timestamps of prep actions). */
export function recordTransfer(domain, patch) {
  const all = read();
  all[domain] = { ...(all[domain] || {}), ...patch };
  writeFileSync(FILE, JSON.stringify(all, null, 2) + '\n');
  return all[domain];
}
