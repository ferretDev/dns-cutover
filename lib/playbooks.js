import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const FILE = join(dirname(dirname(fileURLToPath(import.meta.url))), 'playbooks.json');

const MAIL_PATTERNS = ['pm-bounces', '_domainkey', 'dkim'];

export const BUILTIN_PLAYBOOKS = {
  'Full migration': {
    steps: { zone: true, records: true, apex: true, redirects: true, dmarc: true, unproxy: true, verify: true, cutover: true },
    unproxyPatterns: MAIL_PATTERNS,
    builtin: true,
  },
  'Stage only (no cutover)': {
    steps: { zone: true, records: true, apex: true, redirects: true, dmarc: true, unproxy: true, verify: true, cutover: false },
    unproxyPatterns: MAIL_PATTERNS,
    builtin: true,
  },
  'Fixes + verify only': {
    steps: { zone: false, records: false, apex: true, redirects: true, dmarc: true, unproxy: true, verify: true, cutover: false },
    unproxyPatterns: MAIL_PATTERNS,
    builtin: true,
  },
};

function readCustom() {
  try {
    return JSON.parse(readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function getPlaybooks() {
  const custom = {};
  for (const [name, cfg] of Object.entries(readCustom())) {
    custom[name] = { ...cfg, builtin: false };
  }
  return { ...BUILTIN_PLAYBOOKS, ...custom };
}

export function savePlaybook(name, config) {
  if (BUILTIN_PLAYBOOKS[name]) throw new Error(`"${name}" is a built-in playbook — save it under a different name`);
  const custom = readCustom();
  custom[name] = {
    steps: { ...config.steps },
    unproxyPatterns: (config.unproxyPatterns || []).map((p) => String(p).trim().toLowerCase()).filter(Boolean),
  };
  writeFileSync(FILE, JSON.stringify(custom, null, 2) + '\n');
}

export function deletePlaybook(name) {
  if (BUILTIN_PLAYBOOKS[name]) throw new Error('Cannot delete a built-in playbook');
  const custom = readCustom();
  delete custom[name];
  writeFileSync(FILE, JSON.stringify(custom, null, 2) + '\n');
}
