# Hunt Log — Marriott Bug Bounty Program

**Program:** Marriott Bug Bounty (HackerOne — hackerone.com/marriott)
**Platform:** HackerOne
**Started:** 2026-06-21
**Status:** SESSION 1 — Recon + Initial Probe
**Scope file:** `config/marriott-scope.yaml`
**Scope check:** `SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh <host>`

---

## Program Overview

| Stat | Value |
|------|-------|
| Program live | Feb 2020 |
| Total bounties paid | $559,803 |
| 90-day bounties | $38,057 |
| 90-day reports | 239 |
| Reports resolved | 776 |
| Hackers thanked | 377 |
| In-scope assets | 80 |
| Response efficiency | 97% |
| Avg time to first response | 2 hours |
| Avg time to triage | 21 hours |
| Avg time to bounty | ~3 days |

### Bounty Table

| Severity | Range | Avg |
|----------|-------|-----|
| Critical | $8,001 – $11,000 | $11,000 |
| High | $6,000 – $8,000 | $4,465 |
| Medium | $600 – $3,429 | $2,202 |
| Low | $300 – $599 | $442 |

---

## Attack Surface Analysis

### High-Value Clusters (by report count + freshness)

| Asset | Severity Tier | Prior Reports | Priority |
|-------|--------------|--------------|----------|
| `gatewaydsapdev2.marriott.com` | Critical | 0 | **TOP — DEV env, untouched** |
| `psp.marriott.com` | Critical | 0 | **TOP — payment system, untouched** |
| `lawmanager.marriott.com` | Critical | 0 | **TOP — legal data, untouched** |
| `*gateway-apc.marriott.com` | Critical | 0 | **TOP — new wildcard Oct 2025** |
| `*.artifactory.marriott.com` | High | 0 | **TOP — artifact stores = cred exposure** |
| `*.apigwc.marriott.com` | High | 0 | **TOP — API gateway wildcard, untouched** |
| `*.apigatewayc.marriott.com` | High | 0 | **TOP — API gateway wildcard, untouched** |
| `auth-apc.marriott.com` | High | 0 | **TOP — auth endpoint, untouched** |
| `ssm-marriottms.saviyntcloud.com` | High | 0 | **TOP — IAM platform, new Oct 2025** |
| `*uat.marriott.com` | High | 0 | **TOP — UAT env wildcard, untouched** |
| `gatewaydsaptst1.marriott.com` | Critical | 2 | HIGH — TEST env |
| `dcfgatewaytst1.marriott.com` | Critical | 1 | HIGH — TEST env |
| `passwordchallenge.marriott.com` | Critical | 2 | HIGH — employee PW reset |
| `sso.marriott.com` | Critical | 33 | MEDIUM — well-tested but critical |
| `homes-and-villas.marriott.com` | Critical | 17 | MEDIUM — multi-tenant property IDOR |
| `help.marriott.com` | Critical | 17 | MEDIUM — support data access |
| `owa.marriott.com` | Medium | 0 | HIGH — OWA/Exchange NTLM disclosure |

### Bug Class Hypothesis by Target

**DEV/TEST Gateways** (`gatewaydsapdev2`, `gatewaydsaptst1`, `dcfgatewaytst1`, `*uat.marriott.com`):
- Missing auth on API endpoints (401 not 403 → register → test)
- Spring Boot Actuator exposure (`/actuator`, `/actuator/env`, `/actuator/heapdump`)
- Swagger / OpenAPI without auth (`/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`)
- Debug endpoints (`/debug`, `/console`, `/trace`)
- SAP DSP gateway-specific endpoints (`/sap/opu/odata/`, `/sap/bc/`)
- Hardcoded credentials or API keys in JS bundles

**Artifactory** (`*.artifactory.marriott.com`):
- Anonymous access to artifact repositories
- API token exposure in artifact metadata
- Unauthenticated REST API (`/api/v1/system/ping`, `/api/v1/repositories`, `/api/storage/`)
- Package files containing hardcoded credentials (`.env`, `application.properties`)

**API Gateways** (`*.apigwc.marriott.com`, `*.apigatewayc.marriott.com`, `*.dcfgateway.marriott.com`):
- SSRF via URL-forwarding parameters
- Auth bypass on GET vs POST (method confusion)
- Missing auth on `/health`, `/status`, `/metrics` endpoints
- Token replay / JWT algorithm confusion

**PSP** (`psp.marriott.com` — payment service):
- Webhook URL SSRF (Stripe/payment webhook forwarder)
- Payment amount manipulation (integer, negative, zero)
- Cross-tenant payment context leak
- IDORs on payment records (`/payments/{id}`, `/transactions/{id}`)

**Auth/SSO** (`sso.marriott.com`, `auth-apc.marriott.com`):
- OIDC redirect_uri bypass
- OAuth state parameter fixation
- Token leakage via Referer header
- Account pre-takeover (email change flow race condition)

**Saviynt IAM** (`ssm-marriottms.saviyntcloud.com`):
- Role enumeration without auth
- Privilege escalation via role assignment API
- User management IDOR (access others' role assignments)

**OWA** (`owa.marriott.com`):
- NTLM hash disclosure via `/autodiscover/autodiscover.xml`
- Pre-auth internal host enumeration via `/EWS/Exchange.asmx`

---

## OOS Quick Reference (avoid these or lose the bounty)

- Reflected XSS → OOS since April 2025
- DOM XSS requiring interaction → OOS
- Open redirects → OOS unless chain to ATO
- Web Cache Poisoning → OOS
- Leaked tokens → need ATO proof
- HTML injection → OOS
- MITM at hotel network → OOS
- Do NOT fuzz with 10k+ requests

---

## Sessions

### Session 1 — 2026-06-21 (COMPLETE — Recon Done)

**Goal:** Phase 1-2 recon — DNS fingerprint + HTTP surface mapping.
**Status:** COMPLETE. 60/80 assets resolved. See `RECON-SESSION1.md` + `01-assets/` + `02-surface/`.

**Key recon findings:**
- `sso.marriott.com` is **NXDOMAIN** — 33-report SSO endpoint is dead. Auth surface moved.
- **7 raw AWS EC2 hosts with no WAF/CDN**: esupplier, device, marrtool, marriottfranchisetransactions, mgs, splunk-phantom-nlb, university — direct exploitation viable
- **APC cluster convergence**: auth-apc, apcgateway, gateway-apc all → `23.61.96.201` — one backend, 3 virtual hosts, Host-header routing determines which service responds
- `dcfgatewaytst1.marriott.com` → `159.166.124.24` (Marriott private DC, no CDN)
- `sba.marriott.com` → `159.166.44.21` (Marriott private DC, no CDN)
- `ssm-marriottms.saviyntcloud.com` → Cloudflare proxy, 0 reports, Saviynt IAM
- CT log queries blocked from cloud env — run crt.sh wildcard queries from Pi

**Infrastructure map:**

| Infra | Count | Notable |
|-------|-------|---------|
| Akamai (WAF) | 24 | Most public-facing assets |
| AWS EC2 direct (NO WAF) | 7 | esupplier, device, marrtool, franchisetx, mgs, splunk, university |
| AWS CloudFront | 8 | mipartnerprivileges, ifast, efast, eidhelp, activities, ifast |
| Zscaler/Marriott-CDN | 6 | owa, lawmanager, oasisprod, bpa2 — internal-facing |
| Marriott Private DC | 2 | dcfgatewaytst1, sba.marriott.com |
| Cloudflare | 2 | ssm-marriottms.saviyntcloud.com, hotel-development |
| GCP | 2 | join.marriott.com, moments.marriott.com |
| Oracle Cloud OCI | 1 | ocijlbex1prd.marriott.com |
| NXDOMAIN (dead) | 6 | **sso.marriott.com** (33 prior reports — moved), wechat.api, ifast alt |

### Session 2 — 2026-06-21 (QUEUED — Pi required)

**Goal:** Active HTTP probe + port scan of raw EC2 hosts + wildcard CT log enum.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session1.md` (Phases A-I still valid; reorder by priority below)

**Revised Pi probe priority order:**
1. Raw EC2 hosts (no WAF) — port scan + HTTP: esupplier, device, marrtool, marriottfranchisetransactions, mgs, splunk-phantom-nlb
2. APC cluster Host-header routing — auth-apc / apcgateway / gateway-apc all on same IP
3. DEV gateways — gatewaydsapdev2 + gatewaydsapdev1 (Akamai)
4. PSP + financial — psp.marriott.com (Akamai)
5. Saviynt IAM — ssm-marriottms.saviyntcloud.com
6. CT log wildcard enum — *.apigwc, *.apigatewayc, *.dcfgateway, *uat, *gateway-apc
7. OWA NTLM — owa.marriott.com via Zscaler CDN
8. Private DC direct — dcfgatewaytst1.marriott.com (159.166.124.24)

---

## Lead Status

| ID | Class | Surface | IP / Infra | Status | Priority |
|----|-------|---------|-----------|--------|----------|
| M001 | Missing auth / debug API + IDOR | `esupplier.marriott.com` | `3.219.138.243` RAW EC2, NO WAF | PENDING — Pi session 2 | **CRITICAL** |
| M002 | MDM/device API missing auth | `device.marriott.com` | `54.243.246.159` RAW EC2, NO WAF | PENDING — Pi session 2 | **CRITICAL** |
| M003 | SAP debug APIs / missing auth | `gatewaydsapdev2.marriott.com` | Akamai | PENDING — Pi session 2 | CRITICAL |
| M004 | Payment bypass / IDOR | `psp.marriott.com` | Akamai dedicated | PENDING — Pi session 2 | CRITICAL |
| M005 | Legal doc IDOR / SSRF | `lawmanager.marriott.com` | Zscaler/internal | PENDING — Pi session 2 | CRITICAL |
| M006 | Host-header routing / auth bypass | APC cluster: `auth-apc` + `apcgateway` + `gateway-apc` | `23.61.96.201` Akamai | PENDING — Pi session 2 | HIGH |
| M007 | IAM privilege escalation / IDOR | `ssm-marriottms.saviyntcloud.com` | Cloudflare / Saviynt | PENDING — Pi session 2 | HIGH |
| M008 | NTLM hash disclosure | `owa.marriott.com` | Zscaler CDN | PENDING — Pi session 2 | MEDIUM |
| M009 | Splunk SOAR admin exposure | `splunk-phantom-nlb.marriott.com` | `34.205.160.170` RAW EC2 | PENDING — Pi session 2 | HIGH (Critical impact if open) |
| M010 | Private DC gateway probe | `dcfgatewaytst1.marriott.com` | `159.166.124.24` Private DC | PENDING — Pi session 2 | HIGH |
| M011 | Wildcard CT enum: API gateway, UAT, APC | `*.apigwc`, `*.apigatewayc`, `*uat.marriott.com` | — | PENDING — crt.sh from Pi | HIGH |
| M012 | Partner privileges IDOR | `mipartnerprivileges.marriott.com` | AWS CloudFront | PENDING — Pi session 2 | HIGH |
| M013 | SSO endpoint discovery | `sso.marriott.com` **NXDOMAIN** — auth moved | Find current auth endpoint | PENDING | HIGH |
| ~~M014~~ | ~~OIDC / auth~~ | ~~sso.marriott.com~~ | NXDOMAIN | CLOSED — endpoint dead | — |
