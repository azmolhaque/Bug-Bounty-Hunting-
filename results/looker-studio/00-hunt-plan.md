# Looker Studio (datastudio.google.com / lookerstudio.google.com) — Hunt Plan
# Program: Google Cloud VRP   Scope: datastudio.google.com (explicit) + google.com
# Account: free, sign in with Google (azmolhaque95@gmail.com)
# Setup: phone browser + a free OOB listener (webhook.site)

## Why this target
Free, self-service, multi-tenant. Real bug classes a solo researcher CAN test:
SSRF (server-side URL fetch), IDOR (report/data-source ids + sharing), broken
access control on embeds. Google-core = hardened, so be methodical: find the
*non-obvious* fetch/ACL flow, not the front-door.

## Rules of engagement (Cloud VRP)
- Test only your OWN reports/data sources/accounts.
- SSRF: benign OOB canary only (webhook.site / your collaborator). For metadata,
  prove the *fetch* reaches an internal target — do NOT exfiltrate real tokens
  beyond what proves impact; stop at proof.
- No DoS, no mass automation. Stop on any other tenant's data.

---

## PHASE 1 — Map every URL-fetch + id-bearing surface (recon)
Open lookerstudio.google.com logged in. Enumerate where the BACKEND might fetch a
URL or where a resource id appears:

URL-fetch candidates (SSRF surface):
- [ ] Community/Partner **connectors** that take a user URL (e.g. "JSON/CSV/REST
      API connector") — Add data → Connect to data → search community connectors.
- [ ] **Image** components in a report (insert image → "by URL").
- [ ] **Data source** configs with an endpoint/URL field.
- [ ] **Embed**/URL/iframe components (note: usually client-side, not SSRF).
- [ ] "Get data from **URL**" / file-import-from-URL anywhere.
- [ ] Report **theme/logo** by URL, scheduled-email logo, PDF export image fetch.

Id-bearing surface (IDOR):
- [ ] /reporting/{reportId}, /datasources/{dataSourceId}, /embed/reporting/{id}
- [ ] /u/0/reporting/... vs /u/1/... (account index)
- [ ] share links / ?params= tokens

## PHASE 2 — Server-side vs client-side (the SSRF filter)
For each URL-fetch candidate: set the URL to your **webhook.site** unique URL,
trigger it (refresh data / render the image / preview).
- Hit logged on webhook.site **from a Google/GCP IP** (not your phone IP) =>
  SERVER-SIDE fetch => SSRF-capable. Note the User-Agent (e.g. "Google-Apps-Script",
  "DataStudio", "Google" — tells you which backend).
- No hit, or hit from YOUR IP => client-side => not SSRF, drop it.

## PHASE 3 — SSRF escalation (only on confirmed server-side fetchers)
Point the server-side fetcher at, in order (benign):
1. `http://169.254.169.254/latest/meta-data/`  (AWS IMDS — usually N/A on GCP)
2. `http://metadata.google.internal/computeMetadata/v1/`  (GCP — needs header
   `Metadata-Flavor: Google`; test whether the fetcher lets you add headers, or
   try `http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true`)
3. `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
4. Bypasses if blocked: redirect from your webhook.site URL (302 → metadata),
   DNS-rebinding host, decimal/hex IP, `http://[::ffff:169.254.169.254]`,
   `http://metadata.google.internal.<yourdomain>`, trailing dot.
5. Non-HTTP: `file:///etc/passwd`, `gopher://`, `http://localhost:<port>/`.
A response/render containing metadata or a token = Critical SSRF — STOP, document.

## PHASE 4 — IDOR / broken access control
1. Create a **private** report + data source on account A. Note their ids.
2. From a 2nd Google account (or logged out), open /reporting/{id},
   /embed/reporting/{id}, /datasources/{id} — expect denied.
3. Test: edit-vs-view, ?mode=, embed token reuse, copy-report by id, the
   data-source "credentials owner" model (can B query A's data source by id?).
4. Data-source IDOR is highest value — it can expose A's connected data/creds.

---

## Status log
- 2026-06-28: plan created. NEXT: Phase 1 recon in browser + set up webhook.site.
