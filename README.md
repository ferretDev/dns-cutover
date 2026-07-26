# dns-cutover

A local web UI + CLI for migrating DNS hosting from **Enom** to **Cloudflare**, safely and in bulk:

1. Load the full zone from both sides (Enom host records + Cloudflare DNS records).
2. Diff them git-style, side by side — TXT, CNAME, MX, A/AAAA, NS, SRV, DMARC/SPF/DKIM —
   with normalization (quote-stripping, trailing dots, case, `@` vs fqdn, split TXT segments).
3. Sync anything missing into Cloudflare — per record, per domain, or batched across domains.
   Never deletes; extras are only reported.
4. Cut over: read the zone's assigned nameservers from Cloudflare and apply them
   at the registrar via Enom `ModifyNS` — with the previous NS snapshotted for one-click rollback.

Zero dependencies. Node 18+.

## Web UI

```bash
node server.js     # -> http://127.0.0.1:8899 (localhost only)
```

- **Domain list** with search, status filter, and pending-first sorting
- **Auto-scan on load** — every domain gets header pills: `✓ all N records match`,
  `✗ 3/14 missing`, `ready to cut over`, `awaiting activation`, `migrated`
- **Notice bar** — clickable chips aggregating the fleet: ready / need sync /
  awaiting activation / mail gaps / redirects pending
- **Side-by-side zone diff** per domain — same/missing/extra rows, per-row and
  batch directional sync
- **Redirect migration** — Enom `URL`/`URL301`/`FRAME` pseudo-records become
  Cloudflare Single Redirect rules (wildcard hosts supported), including the
  proxied placeholder DNS record a redirect needs to fire
- **Mail provider intelligence** — detects Google Workspace / Microsoft 365 from
  signature records and checks the provider's complete expected set (MX, SPF,
  DKIM selectors, autodiscover, DMARC), distinguishing "exists in Enom, not yet
  synced" from pre-existing gaps
- **NS cutover with stored rollback** — previous nameservers persist to
  `rollbacks.json`; one-click restore
- **EPP/auth codes** — unlock + trigger Enom's EPP email per domain for registrar transfers
- **API keys managed in the UI** — stored locally in gitignored `config.json`
  (chmod 600), masked in the browser, rotatable without restart

## CLI

```bash
node cli.js list                          # all domains in the Enom account
node cli.js status example.com            # NS at Enom + CF zone state
node cli.js check example.com             # diff both zones, no writes
node cli.js sync example.com              # create CF zone if needed + missing records
node cli.js cutover example.com           # verify match, then point NS at Cloudflare
```

All per-domain commands accept multiple domains: `node cli.js sync a.com b.com c.com`.

## Setup

Credentials via the UI settings panel, or `cp .env.example .env`:

| Var | What |
|-----|------|
| `ENOM_UID` / `ENOM_PW` | Enom reseller login (pw can be an API token) |
| `ENOM_ENV` | `prod` or `test` (resellertest.enom.com) |
| `CF_API_TOKEN` | needs Zone Read/Write, DNS Read/Write; add Dynamic URL Redirects Read/Write for redirect rules |
| `CF_ACCOUNT_ID` | for zone creation |

**Enom gotchas:** the reseller API only answers from IPs whitelisted in the Enom
control panel, and EPP codes are emailed to the registrant contact — the API
never returns them directly.

### Flags

| Flag | Effect |
|------|--------|
| `--yes` | Skip the cutover confirmation prompt |
| `--force` | Cut over even if records are missing in Cloudflare |
| `--proxy-web` | Create A/AAAA/CNAME proxied (orange cloud). Default is DNS-only so behavior is identical post-cutover; flip proxying on in the dash afterwards. |

### Typical migration

```bash
node cli.js check example.com     # see what's there
node cli.js sync example.com      # create zone + records, note assigned NS
node cli.js check example.com     # confirm 0 missing
node cli.js cutover example.com   # applies CF nameservers at Enom
node cli.js status example.com    # later: confirm zone went "active"
```

## Safety rails

- `sync` refuses to run when Enom returns **zero** records (wrong domain / not on Enom DNS hosting).
- `check`/`sync` warn when the domain's registrar NS aren't Enom's own DNS servers —
  in that case Enom's stored records may be stale and live DNS is served elsewhere.
- `cutover` aborts if any record is missing in Cloudflare (unless `--force`), prints the
  old NS for rollback, and asks for confirmation (unless `--yes`).
- Enom `URL`/`URL301`/`FRAME` redirect pseudo-records have no DNS equivalent — they're
  flagged so you can recreate them as Cloudflare redirect rules.
- Nothing is ever deleted, on either side.
