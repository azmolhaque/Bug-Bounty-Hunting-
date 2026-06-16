# Hunt Plan — AppSheet (appsheet.com)
# Phase 0 — Scope & Authorization
# Date: 2026-06-15

## Target Classification
**Archetype:** Multi-tenant no-code SaaS platform with rich automation and connector surface.
**Tier:** TIER0 (up to $101,010 → $151,515 with quality multiplier)
**Scope gate:** `*.appsheet.com` IN-SCOPE per config/scope.yaml

## Hunt Thesis

AppSheet is a Google-acquired no-code platform where every user can build apps
that send HTTP requests, connect to external databases, and render files.
The attack surface is massive and underresearched because AppSheet's security
posture was built pre-acquisition and has not been through a Google-level security
review cycle. The highest-probability bug class is **SSRF** — AppSheet's
"Run a webhook" automation action sends server-side HTTP requests to
user-supplied URLs, which may reach AWS/GCP metadata endpoints.

**#1 Attack Chain Hypothesis:**
```
Create free AppSheet account
→ Add "Run a webhook" automation with URL = http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ Trigger the automation
→ AppSheet servers make request to IMDS
→ AWS role credentials returned in webhook response/log
→ TIER0 SSRF → cloud credential access
```

**#2 Attack Chain:**
```
AppSheet data connector accepts custom REST endpoint URL
→ Set connector URL to attacker-controlled OOB endpoint
→ Observe server-side request headers (may include internal service tokens)
→ SSRF confirmed → escalate to metadata probe
```

**#3 Attack Chain:**
```
AppSheet PDF/email report generation renders user-supplied content
→ Inject URL reference in report template
→ SSTI or file: protocol path → local file read
→ TIER0 RCE via server-side template injection
```

## Target Inventory (from scope.yaml)

| Host | Priority | Reason |
|------|----------|--------|
| `api.appsheet.com` | P0 | REST API for app creation — webhook/connector entry points |
| `www.appsheet.com` | P1 | Main web UI — app builder, automation config |
| `eu.appsheet.com` | P1 | EU instance — may lag in security patches |
| `*.appsheet.com` | P2 | Wildcard — dev/staging/internal subdomains |

## Phase 1+2 Recon Priorities

1. **Enumerate `*.appsheet.com` subdomains** — look for `api-staging`, `dev`, `internal`, `admin`, `rde`
2. **Check all CNAMEs** — AppSheet was recently acquired; may have old Vercel/GH Pages CNAMEs
3. **Crawl `www.appsheet.com`** — find all automation endpoint URLs in JS
4. **Find API documentation** — `/swagger`, `/openapi.json`, `/api/v2/docs`
5. **Mine JS for internal hostnames** — launch js-hunter on all JS bundles

## Phase 3 — Top 3 Bug Classes to Test

### Priority 1: SSRF via Webhook/Automation
- **Where:** Automation → "Run a webhook" action in any app
- **How:** Create a free AppSheet account, create an app, add webhook automation
- **Test payload:** OOB interactsh URL first, then IMDS on confirmation
- **Script:** `./scripts/appsheet-ssrf-probe.sh`

### Priority 2: IDOR in App/Data Access
- **Where:** AppSheet apps are accessed via `https://www.appsheet.com/start/<AppId>`
- **Where:** API endpoint `GET /api/v2/apps/<appId>/tables/<tableId>/data`
- **How:** With Account A, record your AppId. With Account B (different tenant), attempt to read Account A's app data using Account A's AppId
- **Test:** Change app visibility settings; test if private apps are truly private

### Priority 3: Data Connector SSRF
- **Where:** App Settings → Data → Add a new data source → REST API connector
- **How:** Set REST API URL to OOB endpoint, observe if server requests arrive
- **Escalation:** If SSRF confirmed → redirect to `file:///etc/passwd` or IMDS

## Required Test Accounts

1. Create `appsheet-test-a@gmail.com` — primary test account (Account A)
2. Create `appsheet-test-b@gmail.com` — second tenant account (Account B)
3. Register both at `https://www.appsheet.com/` (free tier sufficient)

## Phase 4 Verification Standard

For SSRF: must get DNS or HTTP interaction on OOB URL from AppSheet servers
(IP range should be GCP, confirming server-side request).
Then: attempt IMDS access; if response contains `iam/security-credentials/<role>` → TIER0.

## CVSS Projection

| Scenario | Vector | Score |
|----------|--------|-------|
| SSRF → OOB only | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 Medium |
| SSRF → IMDS cloud creds | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N | 9.9 Critical |
| IDOR cross-tenant data | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 High |
| SSTI → RCE | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | 10.0 Critical |

## Dedup Check

- ~~AppSheet CVE history: CVE-2023-4212~~ — **correction (Session 3):** verified
  unrelated to AppSheet/Google Cloud (it's a Trane thermostat command-injection
  CVE). Dropped.
- Google VRP known issues: none listed for appsheet.com
- Prior disclosures (confirmed via research, Session 4): **two** prior rewarded
  AppSheet connector-framework SSRF reports exist, both for *different*
  connector implementations than F002:
  1. David Nechuta, Dec 2021 — Workflows/Bots "Run a webhook" → IMDS token theft
     (fixed). https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
  2. "SSRF in Adding apigee account sources in appsheet.com" — Apigee
     account-source connector accepts arbitrary URL, makes server-side request
     (fixed, separate report). https://bughunters.google.com/reports/vrp/PnwRwydmr

## Fastest Path to a High/Critical

1. Register free AppSheet account (5 min)
2. Create a simple app with Google Sheets data source (5 min)
3. Add "Run a webhook" automation with interactsh URL (5 min)
4. Trigger the automation and watch interactsh dashboard (2 min)
5. If DNS hit → submit SSRF (OOB, Medium) while chaining IMDS

**Total time to first valid submission: ~20 minutes if SSRF is present.**

---

## Session 4 — Recurring-Pattern Finding & Next-Target Decision (2026-06-16)

### The pattern is now confirmed, not hypothesized

Three independent AppSheet connector/automation features have now each had
their own SSRF-capable outbound HTTP client, found and fixed (or, for F002,
pending submission) **separately**:

| # | Component | HTTP client | Status |
|---|-----------|-------------|--------|
| 1 | Workflows/Bots "Run a webhook" | webhook executor | Fixed (Nechuta, 2021) |
| 2 | Apigee account-source connector | Apigee connector client | Fixed (separate VRP report) |
| 3 | OData data connector | `Microsoft.OData.Client` | F002, this engagement, submission-ready |

Google has fixed each instance individually rather than centralizing outbound
HTTP through one SSRF-safe client. That means **every other AppSheet
connector/data-source type is, by default, an unreviewed instance of the same
root cause** — not a fresh hypothesis, a near-certain pattern continuation.

### Recommendation: PRIMARY target = continue AppSheet (same engagement, new connector surface)

Lowest friction, highest signal option available right now:
- Already have a live free account, working OOB tooling, scope confirmed,
  and 2 submission-ready reports proving the methodology works on this target.
- Remaining untested connector/data-source types on a free AppSheet plan:
  **REST API connector** (flagged as next priority since Session 1/2, not yet
  attempted), Google Sheets-external/Smartsheet, Box/Dropbox, MySQL/Postgres,
  Salesforce. Each is a 5-10 minute test using the same pattern as F002
  (`scripts/appsheet-ssrf-probe.sh` generalizes directly).
- Secondary priority on the same target: the cross-tenant IDOR test
  (`./scripts/appsheet-ssrf-probe.sh --idor`) and the staging-UUID hunt
  (`./scripts/staging-uuid-hunt.sh`) to escalate F001 from Medium → Critical —
  both already scripted from prior sessions, neither executed yet.

### Backup target: Siemplify SOAR (TIER1, *.siemplify.co — already in scope.yaml)

`config/scope.yaml` flags Siemplify (Google-acquired SOAR platform, Jan 2022)
with the note "hundreds of SSRF connectors" — structurally the same
connector-proliferation thesis that just paid off on AppSheet, but on a
genuinely fresh, lightly-researched target. Higher cost: needs Phase 0-2
recon from zero (no existing account, no asset map). Hold in reserve if
AppSheet's remaining connector types are exhausted without a new finding.

### Ruled out this round (researched, low signal or high friction)
Looker (heavy recent professional/Tenable scrutiny, patched, high competition),
Mandiant Advantage (no exploitable-surface signal found), Cameyo/Photomath (no
signal), Pring (Japan-only regulatory/regional friction).

**Next session action:** run `./scripts/appsheet-ssrf-probe.sh --setup
--target rest_api_connector` (or the equivalent REST API connector flow
through the AppSheet UI if the script needs generalizing) on the Pi.
