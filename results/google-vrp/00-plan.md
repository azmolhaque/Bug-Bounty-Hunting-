# Hunt Plan — Google / Alphabet VRP
**Date:** 2026-06-11
**Program:** bughunters.google.com
**Scope source:** github.com/google/bughunters (authoritative protobuf, June 2026)
**Tracks:** Web VRP · Cloud VRP · Mobile VRP · Hardware VRP · AI VRP

---

## CRITICAL CORRECTION — Wiz IS in scope NOW

`*.wiz.io` is **TIER1 and explicitly exempt from the 6-month blackout** per the
official bughunters domain tier database. Acquired March 2026 — testable today.
Wiz is a CNAPP (Cloud-Native Application Protection Platform) with deep IAM
permissions into customer AWS/GCP/Azure environments. This is the highest-value
underresearched target in the program right now.

---

## Hunt Thesis

The recurring pattern across all high-value Google VRP payouts:

> **Acquisition seam + complex OAuth/SSO bridge + multi-tenant B2B API +
> insufficient tier isolation = authorization/access-control bugs that
> scanners miss and manual hunters find.**

Priority ranking based on three factors: **(1) reward tier × (2) confirmed prior
bug class recurring = still active × (3) current research saturation (lower =
better ROI).** Wiz scores highest on all three — TIER1 reward, CNAPP = SSRF/
tenant-isolation class, and virtually zero public VRP research exists yet.

---

## Phase 0 — Authorization check

```bash
# Run all of these before doing anything active:
./scripts/scope-check.sh app.wiz.io            # → IN-SCOPE (TIER1, blackout exempt)
./scripts/scope-check.sh advantage.mandiant.com # → IN-SCOPE (TIER1)
./scripts/scope-check.sh api.fitbit.com         # → IN-SCOPE (TIER1)
./scripts/scope-check.sh appsheet.com           # → IN-SCOPE (TIER0)
./scripts/scope-check.sh storage.googleapis.com # → OUT-OF-SCOPE (TIER4)
./scripts/scope-check.sh doubleclick.net        # → OUT-OF-SCOPE (TIER4)
```

**NEVER TEST:** `*.appspot.com`, `*.googleusercontent.com`, `doubleclick.net`,
`gstatic.com`, `*.googleapis.com` (most subdomains TIER4). See scope.yaml.

---

## Priority Target List

### P0 — Test immediately (TIER1, underresearched, high ROI)

| Target | Domains | Why now | Primary bug class |
|--------|---------|---------|------------------|
| **Wiz** | `*.wiz.io`, `app.wiz.io` | TIER1, zero public research, CNAPP = cloud permissions | SSRF → cloud metadata; cross-tenant CNAPP finding isolation; IDOR on cloud misconfig objects |
| **Apigee** | `apigee.com`, `apigee.google.com` | 4 confirmed VRP payouts; same root cause class recurs | Sandbox escape via policy execution (JavaCallout, PythonScript, new gRPC policies) |
| **AppSheet** | `api.appsheet.com`, `www.appsheet.com` | TIER0; SSRF + RCE proven; new AI features = new URL-intake | SSRF via any new bot/automation/AI integration URL field |

### P1 — High priority (confirmed prior findings, high reward)

| Target | Domains | Primary bug class |
|--------|---------|------------------|
| **Looker Studio** | `lookerstudio.google.com` | Fix bypass on LeakyLooker (9 vulns, Mar 2026); untested connectors |
| **Looker SaaS** | `looker.com`, `lk.looker.com` | RCE via Git hooks (LookOut); cross-tenant BI query injection |
| **Fitbit API** | `api.fitbit.com`, `accounts.fitbit.com` | IDOR on health data; OAuth scope abuse; Mobile VRP up to $450K |
| **Mandiant Advantage** | `advantage.mandiant.com`, `intel.mandiant.com` | Multi-org IDOR; legacy FireEye ↔ Google SSO bridge; minimal prior research |

### P2 — Medium-high priority

| Target | Domains | Primary bug class |
|--------|---------|------------------|
| **Chronicle / SecOps** | `chronicle.security` | Cross-tenant SIEM data; SSRF via Siemplify SOAR connectors |
| **VirusTotal** | `virustotal.com` | SSRF via URL analysis; YARA/retrohunt server-side code exec |
| **Waze Biz** | `biz.waze.com`, `waze.com` | Advertiser portal IDOR; location-privacy API leak |
| **Kaggle** | `kaggle.com` | Notebook SSRF to GCP metadata; container escape |
| **Nest / SDM API** | `home.nest.com`, `smartdevicemanagement.googleapis.com` | IoT auth bypass; OAuth overprivilege on SDM API |

### P3 — Opportunistic

| Target | Domains | Note |
|--------|---------|------|
| Photomath | `*.photomath.net`, `internal.photomath.com` | TIER0 internal admin portals; very little research |
| Cameyo | `cameyo.com`, `*.svc.cameyo.com` | TIER0; virtual app delivery; SSRF/RCE surface |
| Siemplify SOAR | `siemplify.co`, `siemplifycloud.com` | SSRF-rich SOAR connector library |
| Google Cloud Console | `console.cloud.google.com`, `ide.cloud.google.com` | TIER0; Cloud VRP S0 = $7,500+ minimum; Cloud IDE = code exec surface |

---

## Phase 3 — Vulnerability Hypotheses

### H1 — Wiz: SSRF via cloud connector configuration
**Target:** `app.wiz.io`
**Hypothesis:** Wiz connects to customer cloud accounts (AWS, GCP, Azure) via
service account / role. The connector configuration UI accepts external URLs /
webhook endpoints for notifications and integrations. If Wiz makes server-side
HTTP requests to user-supplied URLs without SSRF controls, a request to
`http://169.254.169.254/latest/meta-data/` (AWS) or
`http://metadata.google.internal/computeMetadata/v1/` (GCP) confirms SSRF.
The impact: Wiz's service account likely has broad read-only cloud permissions,
making the token high-value.
**Class:** SSRF → cloud metadata → service account credentials
**Severity estimate:** Critical (TIER1 × cloud metadata × cross-account reach)
**Reward estimate:** $31,337–$101,010

### H2 — Wiz: Cross-tenant finding isolation
**Target:** `app.wiz.io`
**Hypothesis:** Wiz findings (cloud misconfigurations, vulnerabilities) are scoped
to a customer's cloud environment. With two Wiz trial/free-tier accounts (OrgA,
OrgB), test: does OrgA's API token return OrgB's findings by enumerating finding
IDs? Wiz has a rich REST API — finding IDs are likely sequential or UUID-based.
If UUIDs: test prediction; if sequential: enumerate directly.
**Class:** IDOR / broken tenant isolation
**Severity estimate:** High–Critical

### H3 — Apigee: gRPC policy sandbox escape
**Target:** `apigee.com`, `apigee.googleapis.com`
**Hypothesis:** The JavaCallout and PythonScript sandbox escapes (CVE-2025-13426,
LookOut class) recur because policy execution is architecturally pre-acquisition
legacy code. Apigee added gRPC support and extensible policies in 2023–2024.
Test whether these new policy types share the same sandbox boundary via cross-
policy flow variable contamination or ClassShutter bypass.
**Class:** Sandbox escape → RCE on shared Apigee infrastructure
**Severity estimate:** Critical ($101,010 range)

### H4 — AppSheet: SSRF via AI Automation features
**Target:** `api.appsheet.com`, `www.appsheet.com`
**Hypothesis:** AppSheet added AI-powered automation and bot features (2024–2025).
Any feature that accepts a user-supplied URL and makes a server-side fetch is
a SSRF candidate. The 2021 SSRF was in the "Add Apigee account source" URL field.
Create an app → configure a webhook bot / AI action / external API source with
URL pointing to OOB DNS (interactsh). If the DNS ping arrives from Google's IP
range, SSRF is confirmed. Then test metadata endpoint access.
**Class:** SSRF → GCP metadata service account token
**Severity estimate:** High (→ Critical if token has GCP-wide permissions)

### H5 — Looker Studio: LeakyLooker fix bypass
**Target:** `lookerstudio.google.com`
**Hypothesis:** 9 cross-tenant vulns were patched in Feb–Mar 2026 across BigQuery,
Spanner, PostgreSQL, MySQL connectors. Patches at the input sanitization layer are
frequently incomplete. Test: (a) alternative injection points (nested queries,
export templates, custom SQL mode) in the patched connectors; (b) sibling
connectors not in the original disclosure (AlloyDB, Firestore, Elasticsearch,
Redshift); (c) collaborative workspace sharing — is cross-tenant workspace
isolation fully enforced when a dashboard is shared via a link?
**Class:** Cross-tenant SQL injection / IDOR
**Severity estimate:** High–Critical (LeakyLooker patches may be bypassable)

### H6 — Mandiant Advantage: Multi-org IDOR
**Target:** `advantage.mandiant.com`
**Hypothesis:** Mandiant Advantage is a B2B multi-org threat intelligence platform.
Register two trial organizations. Use Org A's API key to enumerate resource IDs
(threat reports, IOC collections, playbooks, case files) and attempt to access
Org B's objects by changing IDs in API requests. Also: does the legacy FireEye
API v3 endpoint still accept Mandiant Advantage OAuth tokens?
**Class:** IDOR / broken multi-tenant isolation
**Severity estimate:** High ($13,337–$31,337)

### H7 — Fitbit API: IDOR on health data
**Target:** `api.fitbit.com`
**Hypothesis:** Register two Fitbit test accounts. Account A authenticates with
OAuth and obtains a token. Attempt to access Account B's health data by
substituting B's user ID in the API path:
`GET /1/user/[USER_B_ID]/activities/heart/date/today/1d.json`.
Also test: the `/1/user/-/` shorthand — does it always resolve to the
authenticated user, or is there a bypass via cached session state?
**Class:** IDOR on health data (TIER1 → Mobile VRP up to $450K for critical)
**Severity estimate:** High–Critical (max sensitivity health PII × 120M users)

### H8 — Chronicle / Siemplify: SSRF via SOAR connector URL
**Target:** `chronicle.security`, `siemplify-soar.com`
**Hypothesis:** Siemplify SOAR (now Google Security Operations) has 300+ pre-built
integrations. Each integration configuration form has a server URL/IP field.
Navigate to an integration (e.g. "Generic REST API", "Slack", "ServiceNow"),
set the server URL to `http://metadata.google.internal/computeMetadata/v1/` with
a `Metadata-Flavor: Google` test header, and trigger a connection test.
If the connector makes the outbound request, SSRF is confirmed.
**Class:** SSRF → GCP metadata
**Severity estimate:** High (Chronicle's service account likely has log-access permissions)

---

## Phase 4 — Verification Protocol

1. **Clean state** — fresh Google test account or trial org, incognito browser.
2. **Minimize PoC** — single API request or minimal UI steps.
3. **Prove impact safely** — your own test data, OOB DNS/HTTP for blind confirmation.
4. **Chain it** — SSRF + cloud metadata token → what can that token access?
5. **Score CVSS 3.1** — then map to program tier for reward estimate.
6. **Never exfiltrate real user data.** A screenshot of your own test account data + CVSS is enough.

---

## Recon Commands

```bash
# Verify scope gate
./scripts/scope-check.sh app.wiz.io
./scripts/scope-check.sh advantage.mandiant.com

# Tier 0/1 recon — passive first
./scripts/recon.sh wiz.io --passive-only
./scripts/recon.sh mandiant.com --passive-only
./scripts/recon.sh appsheet.com
./scripts/recon.sh apigee.com

# Or via Claude Code slash commands:
/recon wiz.io
/hunt app.wiz.io --class ssrf
/hunt advantage.mandiant.com --class idor
/hunt api.appsheet.com --class ssrf
/hunt apigee.com --class injection
/hunt api.fitbit.com --class idor
```

---

## Reporting Priority

Submit in this order (first valid report wins; speed matters):
1. Any Critical (RCE, cross-tenant data access, cloud metadata) → report immediately
2. Wiz TIER1 findings (new program, fast triage likely)
3. Apigee sandbox class (confirmed-recurring, fast acceptance)
4. Fitbit IDOR (Mobile VRP = highest dollar tier)
5. AppSheet SSRF
6. Looker Studio / Mandiant IDOR

---

## HUNT-LOG

| Date | Phase | Action | Outcome |
|------|-------|---------|---------|
| 2026-06-11 | 0 | Scope populated from google/bughunters protobuf + VRP rules | scope.yaml written (TIER0–TIER3 in scope; TIER4 excluded) |
| 2026-06-11 | 0 | Confirmed Wiz TIER1 exempt from blackout | *.wiz.io added to in_scope |
| 2026-06-11 | 0 | Removed TIER4 domains incorrectly in scope (doubleclick, gstatic, etc.) | scope.yaml corrected |
| 2026-06-11 | 0 | Hunt plan written; 8 hypotheses formed | 00-plan.md created |
| — | 1+2 | Recon pending | Not started |
