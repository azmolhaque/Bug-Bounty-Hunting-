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

### Session 1 — 2026-06-21 (ACTIVE)

**Goal:** Phase A-G recon + initial probe of all 0-report high-priority targets.
**Status:** Runbook ready → `runbooks/PI-RUNBOOK-marriott-session1.md`

---

## Lead Status

| ID | Class | Surface | Status | Priority |
|----|-------|---------|--------|----------|
| M001 | Missing auth / debug API | `gatewaydsapdev2.marriott.com` | PENDING — session 1 | CRITICAL |
| M002 | Anon access / cred exposure | `*.artifactory.marriott.com` | PENDING — session 1 | CRITICAL |
| M003 | SSRF / auth bypass | `*.apigwc.marriott.com` + `*.apigatewayc.marriott.com` | PENDING — session 1 | HIGH |
| M004 | Payment bypass / IDOR | `psp.marriott.com` | PENDING — session 1 | CRITICAL |
| M005 | Auth bypass / OIDC | `auth-apc.marriott.com` + `sso.marriott.com` | PENDING — session 1 | HIGH |
| M006 | IAM privilege escalation | `ssm-marriottms.saviyntcloud.com` | PENDING — session 1 | HIGH |
| M007 | NTLM disclosure | `owa.marriott.com` | PENDING — session 1 | MEDIUM |
| M008 | SAP debug APIs | `gatewaydsaptst1.marriott.com` + `dcfgatewaytst1.marriott.com` | PENDING — session 1 | HIGH |
| M009 | Employee PW reset bypass | `passwordchallenge.marriott.com` | PENDING — session 1 | HIGH |
| M010 | UAT env missing auth | `*uat.marriott.com` | PENDING — session 1 | HIGH |
