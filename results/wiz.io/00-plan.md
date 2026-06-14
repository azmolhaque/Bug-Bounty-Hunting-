# Hunt Plan — wiz.io (Google VRP TIER1)
# Generated: 2026-06-11 | Last updated: 2026-06-14

## Target Classification

- **Root domain:** wiz.io
- **Archetype:** CNAPP (Cloud-Native Application Protection Platform) — multi-tenant SaaS, enterprise customer base, rich API surface, GraphQL-first, microservice fleet
- **Platform:** AWS (CloudFront, ELB, Lambda@Edge, API Gateway, S3), Auth0 SSO, Vercel edge
- **Scope tier:** TIER1, blackout-exempt — highest priority

## Hunt Thesis

Wiz is a CNAPP product that brokers access to customer cloud environments. Its architecture combines a React/GraphQL portal, a CLI scanner (WizCLI) that runs inside customer VPCs, a webhook/connector engine that makes outbound HTTP requests, and a microservice fleet of 100+ regional subdomains. The three most plausible bug classes — in priority order — are:

1. **Webhook/connector SSRF → internal service exfiltration (Chain 3):** Webhook integrations that accept attacker-controlled URLs and make server-side HTTP requests. If VPC-level filtering is absent, a webhook trigger can reach `169.254.169.254` (cloud IMDS), internal Grafana instances, auth services, or language servers — all confirmed present inside the Wiz VPC. This is the single highest-leverage attack surface.

2. **Cross-tenant GraphQL IDOR (Chain 4+9):** Wiz's GraphQL API is the control plane for all cloud asset visibility. If tenant isolation is enforced only by JWT claims on the outer resource (`project`) but not on nested objects (`connector`, `issue`, `cloudResource`, `forensicsPackage`), any authenticated user can read another tenant's cloud inventory, credentials, and scan results. The multi-tenant forensics-package fleet (Lambda@Edge) is a confirmed IDOR candidate surface.

3. **Subdomain takeover chain elevation (Chains 1+2):** `win-test.wiz.io` is a confirmed dangling Vercel CNAME (DEPLOYMENT_NOT_FOUND) that any Vercel account can claim. Standalone this is High (CVSS 8.2). If it appears in CSP `script-src` of `app.wiz.io` or in an Auth0 OAuth `redirect_uri` allowlist, this chain reaches Critical.

## Confirmed Findings

| ID | Title | CVSS | Status |
|----|-------|------|--------|
| F001 | Subdomain Takeover — win-test.wiz.io → Vercel dangling CNAME | 8.2 High | VERIFIED — SUBMIT NOW |

## Attack Chain Priority Matrix

| Chain | Class | Potential Severity | Blocker |
|-------|-------|--------------------|---------|
| 3 | Webhook SSRF → IMDS / Grafana | Critical | Trial account |
| 4 | GraphQL cross-tenant IDOR | Critical | Trial JWT |
| 9 | forensics-package IDOR | High | WizCLI token + 2nd account |
| 1 | F001 → CSP script-src bypass | Critical | Pi ACTION C output |
| 2 | F001 → OAuth redirect hijack | Critical | Pi probe |
| 5 | WizCLI binary → internal endpoints | High | Pi ACTION A output |
| 10 | events-ingestion tenant spoofing | Medium | Trial token |
| 8 | PR preview GraphQL introspection | Medium | Pi ACTION B output |
| 7 | dynamic-dns-checker SSRF | High | Pi probe |
| 6 | Ghost CMS Content API key | Low-Medium | Pi ACTION D output |

## Fastest Path to High/Critical — Today

```
STEP 1 (no account needed, run on Pi):
  bash scripts/phase3-wiz-pi.sh   # ACTIONs A, B, C, D, G

STEP 2 (parallel):
  Submit F001 NOW → https://bughunters.google.com/report/
  See: results/wiz.io/F001-SUBMIT-GUIDE.md
  Use: results/wiz.io/findings/submission/F001-problem-description.md
       results/wiz.io/findings/submission/F001-impact-analysis.md

STEP 3 (unblocks P0 chains):
  Register trial at https://app.wiz.io
  Get JWT from browser DevTools
  Run: WIZ_JWT="eyJ..." bash scripts/phase4-trial-account-wiz.sh
```

## Resource Plan (Pi 5, 16 GB ARM64)

- Recon: background, streaming to disk, concurrency ≤ 3
- Phase 3: nuclei fan-out max 3 parallel, dead-end after 3 failures
- Temp cap: 78°C / RAM cap: 82%

## Environment Constraint

Cloud exec env (claude.ai/code) routes ALL outbound via `Anthropic Egress Gateway` — cannot probe targets directly. ALL active network operations run on Pi.

## Phase History

| Phase | Status | Timestamp | Notes |
|-------|--------|-----------|-------|
| 0 | DONE | 2026-06-11T18:04:09Z | Scope confirmed, plan written |
| 1 | DONE | 2026-06-11 | dnsx enumeration, 200+ subdomains |
| 2 | DONE | 2026-06-11/12 | 40+ subdomains fingerprinted; httpx, gau, waybackurls |
| 3 | DONE | 2026-06-11/12 | F001 confirmed; 10 attack chains hypothesized |
| 4 | PARTIAL | 2026-06-11 | F001 verified manually (dig + curl + TLS); P0 chains blocked on trial account |
| 5 | PARTIAL | 2026-06-14 | F001 triaged CVSS 8.2 High; P0 chains not yet verified |
| 6 | READY | 2026-06-14 | F001 report complete, submission texts ready |
