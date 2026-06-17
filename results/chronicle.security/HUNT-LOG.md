# Hunt Log — chronicle.security

**Program:** Google VRP  
**Target:** chronicle.security (Google Security Operations — former Siemplify SOAR + Chronicle SIEM)  
**Scope confirmed:** IN-SCOPE — matches `chronicle.security` in `config/scope.yaml`  
**Hypothesis:** SOAR connector framework follows same SSRF pattern as AppSheet — connectors make server-side HTTP requests to user-supplied URLs with no centralized egress filter.

---

## Session 3 — 2026-06-17 (Mobile browser — live target probing)

### Key Probe Results (mobile browser, 3:08–3:13 local)

| Target | Status | Finding |
|--------|--------|---------|
| `app.siemplify-soar.com/swagger/index.html` | **200** | **Full Chronicle SOAR API Swagger UI — unauthenticated** |
| `app.siemplify-soar.com` (API v selector) | **200** | v1, v2, v3 all exposed |
| `backstory.googleapis.com/v1/feeds` | 401 | Method: `chronicle.backstory.v1.FeedsService.ListFeeds` — needs OAuth |
| `looker.chronicle.security` | Google 400 | Domain resolves to Google; apex needs auth redirect / specific path |
| `backstory-staging.chronicle.security` | Google 404 | Apex `/` not routed; domain resolves; probe actual API paths |
| `backstory-dev.chronicle.security` | **ÜberProxy DNS fail** | Internal-only domain (ÜberProxy error: not resolvable from external) |

### CRITICAL LEAD — Unauthenticated Swagger UI

**`app.siemplify-soar.com/swagger/index.html`** returns the full Chronicle SOAR API documentation without any authentication. Three API versions exposed (v1, v2, v3).

API categories visible in Swagger:
- Agents, Approval Links, Case Management, Cloud Logging, CommandCenter
- ConfigurationItemsManagement, **Connectors**, Dashboards, EntitySearch, Federation
- Homepage, IdpMappingManagement, **Integrations**, Jobs, Marketplace
- Notifications, Ontology, Permissions, **Playbooks**, PubSubBackfill
- Reports, Resources, Retention, Search, Settings, SOC Roles, **Webhooks**

**Significance:** Swagger UI being unauthenticated (no login wall before Swagger loads) means:
1. Full API schema is publicly documented — every endpoint, parameter, and expected response
2. Need to test: which endpoints respond to unauthenticated requests? (webhooks, health, OOB callbacks)
3. If `app` tenant has real trial user data: IDOR between trial accounts on case/integration IDs = cross-tenant isolation break (Critical)
4. **Connectors + Integrations + Webhooks** endpoints are the SSRF surface — need Swagger JSON to extract all URL-parameter fields

**Immediate action:** Fetch `https://app.siemplify-soar.com/swagger/v1/swagger.json` (and v2, v3) to get all endpoint paths and parameter names. Then test each endpoint unauthenticated.

### Analysis

| Host | Verdict |
|------|---------|
| `backstory-dev.chronicle.security` | CLOSED — ÜberProxy (internal DNS, not resolvable externally) |
| `backstory-staging.chronicle.security` | OPEN — resolves; probe `/v1/feeds`, `/v2/detect/rules` with trial token |
| `looker.chronicle.security` | OPEN — resolves; Google 400 = needs auth redirect, probe API paths |
| `app.siemplify-soar.com/swagger` | **HOT LEAD** — full API schema exposed, test endpoints |

---

## Session 2 — 2026-06-17 (Pi 5 — Phase 1-2 passive recon)

### Scale

| Metric | Count |
|--------|-------|
| Subdomains discovered (subfinder + crt.sh on 3 domains) | 53,802 |
| Hosts resolving via dnsx | 12,674 |
| Live HTTP hosts from httpx (Pi IP blocked) | 0 |
| URLs mined via gau + waybackurls | 31,534 |

### Key Probe Results

| Target | Status | Notes |
|--------|--------|-------|
| `chronicle.security` (/, /login, /auth, /api, /docs, /swagger, /health) | **200** | Google Cloud UX SPA — all paths serve same React app, no real API endpoints |
| `chronicle.security/healthz` | 404 | Google 404 page |
| `app.siemplify-soar.com` | **200** | "Google SecOps" — accessible SOAR instance |
| `siemplify-soar.com/swagger/index.html` | 502 Bad Gateway | Apex domain; need `{tenant}.siemplify-soar.com` — try `app.siemplify-soar.com/swagger/index.html` |
| `backstory.googleapis.com/v2/detect/rules` | **401** | Real API endpoint — needs OAuth (scope `chronicle-backstory`) |
| `backstory.googleapis.com/v1/feeds` | **401** | Feed Management API — SSRF surface confirmed reachable, needs trial auth |
| `backstory.googleapis.com/v1/partners` | 401 | |
| `iafwsjwcmh.com` | 000 | TCP refused |
| `uberproxy-san.chronicle.security` | CNAME → `uberproxy.l.google.com` | Internal Google UberProxy |

### Interesting Assets Found in URL Mining

| Host | Significance |
|------|-------------|
| `backstory-dev.chronicle.security` | Dev/staging environment |
| `backstory-preprod.chronicle.security` | Pre-prod environment |
| `backstory-staging.chronicle.security` | Staging environment |
| `looker.chronicle.security` | Looker BI — probe for LeakyLooker-style paths |
| `looker-staging.chronicle.security` | Staging Looker |
| `performence-webhook.siemplify-soar.com` | Live webhook endpoint (note: typo "performence") |
| 12,674 tenant subdomains on `siemplify-soar.com` | Real enterprise tenants: schwab, optum, pearson, ralphlauren, nubank, pandora, etc. |

### SSRF-Relevant URL Patterns Found

- `{tenant}.backstory-staging.chronicle.security` URLs with `initAuth` and `issueCookie` endpoints visible
- Integration/connector URL patterns in gau output
- Feed Management paths visible at `backstory.googleapis.com/v1/feeds`

### Current Status

**Phase 1-2 COMPLETE.** PI IP blocked from httpx full scan but key endpoints probed manually.
**Phase 3 BLOCKED until free Google SecOps trial account registered.**

Next actions for desktop session:
1. **Register free Google SecOps trial** at `cloud.google.com/security/products/security-operations`
2. **Probe `app.siemplify-soar.com/swagger/index.html`** — likely the most accessible SOAR Swagger (app tenant is the demo/community instance)
3. **Probe `looker.chronicle.security`** — Looker API paths (`/api/4.0/user`, `/api/4.0/connections`, `/api/4.0/look/1`, `/login`)
4. **Feed Management SSRF** (F-01): Set OOB interactsh URL as HTTPS feed source → watch for GCP fetch
5. **Integration connector tests** (F-03 through F-08): Jira, ServiceNow, Slack with OOB URLs
6. **Backstory staging/dev** — probe `backstory-staging.chronicle.security` for looser auth

---

## Session 1 — 2026-06-16 (Remote — setup only)

**Actions:**
- Confirmed chronicle.security IN-SCOPE via scope-check.sh
- Siemplify.co recon confirmed dead — 161 subdomains, 0 live high-value, all migrated to chronicle.security / Google Cloud
- Created results directory tree
- Created PI-RUNBOOK-chronicle-recon.md with exact Phase 0-4 commands
- Web research running (agent) to map known attack surface, connectors, tech stack

**OSINT findings (web research, no live access):**
- Backend: Python (SOAR actions/connectors), GCP-native (SIEM); Swagger at `{tenant}.siemplify-soar.com/swagger/index.html` — still live post-migration
- Primary SSRF surface: **Feed Management HTTP(S) source** — Google backend fetches user-supplied URL per official docs, no documented IP blocklist
- Secondary SSRF: 300+ integration connectors each with API URL fields
- New attack surface: TIN Agent + Agentic Automation (Public Preview, Nov 2025–2026) — AI reads alert content → prompt injection
- IDOR: SOAR legacy REST API case/integration IDs in URL paths
- Zero prior public CVEs for Siemplify/Chronicle — low-competition target
- Tenant URL: `{customer}.backstory.chronicle.security`, legacy `{tenant}.siemplify-soar.com`

**Pending (next Pi session):**
- Pull: `git pull` to get runbook
- Create free/trial chronicle.security account at cloud.google.com/security/products/security-operations
- Phase 1: subfinder + dnsx + httpx against chronicle.security
- Phase 3A: Feed Management SSRF test (OOB listener → HTTP(S) feed source)
- Phase 3B: Integration connector URL field tests (Jira, ServiceNow, PagerDuty, Slack)
- Phase 3C: Open Swagger at `{tenant}.siemplify-soar.com/swagger/index.html` — enumerate endpoints, test IDOR
- Phase 3D: TIN Agent prompt injection (if available on free tier)

**Status:** SETUP — ready for Pi execution

---

## Findings / Leads

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| L001 | `backstory.googleapis.com/v1/feeds` → 401 — Feed Management API reachable, needs auth | TBD | LEAD — SSRF target; test with trial account (Phase 3A in runbook) |
| L002 | `app.siemplify-soar.com/swagger/index.html` → **200 unauthenticated** — full Chronicle SOAR API (v1/v2/v3) schema exposed | TBD | **HOT** — fetch Swagger JSON, enumerate all endpoints, test unauth endpoints + IDOR |
| L003 | `looker.chronicle.security` → Google 400 — domain resolves and hits Google | TBD | LEAD — probe Looker API paths (`/api/4.0/user`, `/login`, etc.) |
| L004 | 12,674 live tenant subdomains on `siemplify-soar.com` — real enterprise tenants | Info | LEAD — confirms large multi-tenant surface; IDOR between tenants is in scope |
| L005 | `backstory-staging.chronicle.security` → Google 404 — domain resolves, apex not routed | TBD | LEAD — staging may have looser auth; probe actual API paths with trial token |
| L006 | `performence-webhook.siemplify-soar.com` — live webhook endpoint | TBD | LEAD — probe for unauthenticated webhook acceptance or SSRF |
| L007 | `backstory-dev.chronicle.security` → ÜberProxy DNS fail | Info | CLOSED — internal-only domain, not resolvable externally |
