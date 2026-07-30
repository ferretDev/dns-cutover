# dns-cutover — Feature Roadmap

> **Status 2026-07-30:** built since this was written — fleet uptime board (interval
> probe, tiles/chips/dots, per-hostname probes: partial 1.2), diagnostic sweeper
> (partial 1.1's checks, on-demand), missing-@/www detector-fixer + playbook `apex`
> step, named playbooks + editor, exportable run logs, MD reports (bulk/per-domain),
> triage report (grouped flags + actions), Postmark email + auto-email post-run.
> **Top open items, in build order:** registrar-transfer tracker (3.3 — the imminent
> phase), ops journal (1.4), post-cutover `confirm` playbook step (rest of 1.1),
> server-side queue persistence (1.3), unattended scheduled triage email, dead-IP
> registry (2.2), deep mail validation (2.3 — 13 domains now sit at p=none).

Where the tool is: diff/sync engine, named playbooks + windowed queue, scan pills +
dashboard, corrective tools (un-proxy, DMARC fixer, shared-IP + source-truth audits),
redirect migration, EPP requests, NS rollback, mail-provider intelligence, identity guards.

Where it's going: from a **migration desk** to a **Cloudflare operations dashboard** —
detection, diagnostics, and batch administration for the whole fleet. Every item below
is motivated by something the migration actually surfaced.

---

## Tier 1 — Close the migration loop (highest leverage now)

### 1.1 Post-cutover live verification (playbook step 8)
Cutover currently ends at "NS applied". Add a `confirm` step: resolve NS/A/MX via
public DNS (1.1.1.1 DoH JSON API), then HTTP-probe apex + www through Cloudflare and
grade the response. *Would have auto-caught istalliance.com's 520 and acariresources.com's
timeout instead of finding them by hand.*
- Statuses: `live` (2xx/3xx to sane destination) / `origin-error` (52x → vhost/cert
  missing on origin) / `dead` (timeout) / `not-propagated` (NS mismatch).
- Failing `confirm` never rolls back automatically — it reports loudly.

### 1.2 Fleet HTTP/SSL health board
A dash tab probing every active zone: HTTP status, redirect chain, TLS handshake,
edge-cert status, SSL mode (flag *Flexible*), response time. The "is everything
actually up" oversight grid. Re-runnable any time; deltas highlighted.
- Needs token scopes: SSL and Certificates Read, Zone Settings Read.

### 1.3 Server-side queue persistence
The queue dies with the browser tab. Move the runner into the server (it already has
all state): `POST /api/queue` starts, UI subscribes to progress, queue survives
reloads and resumes on server restart from a `queue.json` journal.

### 1.4 Ops journal (audit log)
Append-only `journal.jsonl` of every write the tool performs (domain, action, payload
summary, result, timestamp). Per-domain timeline view in the panel; fleet log in Tools.
Rollback data becomes one entry type instead of a special case. This is the client-facing
"what did you do to my DNS" answer.

---

## Tier 2 — DNS record intelligence (detection sweeps)

All follow the existing find → review-table → apply(or report-only) pattern in Tools.

### 2.1 Dangling record / subdomain-takeover sweep
- CNAMEs whose targets NXDOMAIN — dead vendors, decommissioned services.
- Takeover-vulnerable danglers: targets on github.io, *.herokuapp.com, *.azurewebsites.net,
  S3 buckets, etc. that don't resolve/claim — security finding, not just hygiene.
- A/AAAA records pointing at IPs that answer nothing on 80/443 (candidate dead hosts).

### 2.2 Dead-IP registry
Mark IPs as **dead** (e.g. the old `161.35.229.7` box). Tool flags every record
fleet-wide referencing a dead IP, offers batch-repoint to a chosen replacement.
Turns the istalliance rescue from a one-off into a workflow.

### 2.3 Mail-auth deep validation (beyond presence checks)
- **SPF analyzer**: parse the tree — >10 lookups (permerror), duplicate SPF records
  (invalid), missing terminal `~all`/`-all`, includes that NXDOMAIN.
- **DMARC grader**: p=none flagged as "monitoring only, no enforcement" with an
  upgrade path; missing `rua`; the 13 mirrored policies are all p=none — a natural
  follow-up engagement.
- **DKIM end-to-end**: actually resolve selector CNAMEs and confirm the target
  publishes a key (catches tenant-deleted DKIM that presence checks miss).
- **MX sanity**: MX → CNAME (RFC violation), MX → nonexistent host.

### 2.4 Proxy advisor
Inverse of un-proxy: web-looking A/AAAA/CNAME records that are DNS-only and *could*
be proxied for CDN/WAF benefit — reviewed batch apply. Pairs with a per-record
"must stay DNS-only" allowlist (mail patterns) so advice never fights the guards.

### 2.5 CAA audit
Zones with no CAA (suggest baseline `letsencrypt.org` + `pki.goog` + `digicert.com`
per what's actually in use), and CAA sets that would block the CA the zone depends on
(silent cert-renewal failures).

### 2.6 Fleet record search
"Which domains reference X?" — arbitrary substring/regex over every record name+content
across all zones. Generalizes the shared-IP audit; the first question during any incident.

---

## Tier 3 — Cloudflare administration (batch oversight)

### 3.1 Zone-settings baseline
Define a desired baseline (SSL mode Full-strict, Always Use HTTPS on, min TLS 1.2,
HTTP/3, Brotli, …) as a named profile — audit all zones against it, show drift as a
table, batch-apply to selected. The "playbook" idea applied to zone settings.

### 3.2 DNSSEC rollout
Enable DNSSEC at Cloudflare per zone, fetch DS record, push to Enom
(`ModifyDNSSEC`-family commands) automatically. Batch-able; verify chain after.
Post-migration security win that's miserable to do by hand at fleet scale.

### 3.3 Registrar-transfer tracker (the next phase's tool)
The EPP button exists; the *process* doesn't. Per-domain transfer checklist: reg-lock
off ✓, privacy off ✓, EPP emailed (date) ✓, 60-day-lock clear ✓, transfer initiated,
Enom approval state (poll `TP_GetOrder`/transfer-status APIs), completed. Fleet
progress board — this is literally the migration's second act.

### 3.4 Pending-cap gauge + activation watcher
Live "N pending / ceiling" tile on the dash (data already exists in the queue path);
standalone background watcher that nudges `activation_check` and toasts when zones
flip active — without needing a queue run.

---

## Tier 4 — Reporting & UX

### 4.1 Migration report export
Per-domain or fleet CSV/Markdown: records migrated, fixes applied (DMARC mirror,
un-proxy, redirects), cutover timestamp, rollback NS, verification result. The
client-facing deliverable/"migration certificate". Draws from the ops journal (1.4).

### 4.2 Domain timeline
Per-domain event view (zone created → synced → fixed → cut over → activated →
confirmed live) rendered from the journal.

### 4.3 Diff snapshots
Persist the last N scans per domain; "what changed since yesterday" view — catches
third parties editing zones out from under you.

---

## Build order recommendation

1. **1.4 Ops journal** first — it's the substrate for reports (4.1), timelines (4.2), and honest oversight.
2. **1.1 Post-cutover confirm** — closes the loop the current batches need *this week*.
3. **1.3 Server-side queue** — batches stop depending on a browser tab staying open.
4. **1.2 Health board** + **2.1 dangling sweep** — the two highest-signal detections.
5. **3.3 Transfer tracker** — ready before registrar-transfer season starts.
6. Everything else as the fleet stabilizes.

Deliberately out of scope: multi-registrar support (Enom-specific by design), WHOIS/RDAP
monitoring and uptime checks (DeadWatch's job — this tool hands off, doesn't compete).
