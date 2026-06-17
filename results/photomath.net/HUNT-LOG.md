# Hunt Log — photomath.net / photomath.com (Google VRP TIER0)

**Started:** 2026-06-16  
**Target:** Photomath (Google-acquired June 2023) — math solver iOS/Android + expert marketplace  
**Scope:** TIER0 — photomath.net, photomath.com, + explicitly listed subdomains  
**VRP blackout ended:** December 2023 — fully in scope  
**Program:** Google VRP / bughunters.google.com

---

## CURRENT STATUS

| # | Item | Status |
|---|------|--------|
| 1 | **argocd-dwh-eu-dev.photomath.net** — 403 not via IAP; auth bypass candidate | 🎯 PURSUE — highest priority |
| 2 | **portal.photomath.net** — IDOR on quiz/user integer IDs | 🎯 PURSUE — requires expert account |
| 3 | **dpcapi-admin.photomath.com** — only `/healthz` exposed externally; API is internal-only | ❌ CLOSED — de-prioritized |
| 4 | **portal.photomath.net** — horizontal privilege escalation | 🎯 PURSUE — secondary |
| 5 | **idp.photomath.net** — Identity Provider; type unknown | ⏳ PENDING — identify IDP type, check CVEs |
| 6 | **glooker.photomath.net** — Looker instance (in-scope via `looker.com` TIER1) | ⏳ PENDING — LeakyLooker / cross-tenant SQLi |
| 7 | **github.com/photomath** — secrets scan | ⏳ PENDING (Pi) |
| 8 | **metabase.photomath.net** — CVE-2023-38646 | ❌ DEAD — NXDOMAIN, record removed |
| 9 | **internal.photomath.com** — 302 → sites.google.com intranet | ❌ CLOSED — Google Workspace SSO, intended |

**NEXT ACTIONS (Pi):**
1. Run ArgoCD auth probe on `argocd-dwh-eu-dev.photomath.net` (see runbook)
2. Probe `dpcapi-admin.photomath.com` specific API paths with WAF bypass headers
3. Register expert account at portal.photomath.net → Burp IDOR test
4. Identify `idp.photomath.net` IDP type
5. Probe `glooker.photomath.net` for Looker cross-tenant SQLi (LeakyLooker pattern)

---

## Session 1 — 2026-06-16 (Remote — OSINT + passive recon)

### DNS Resolution (confirmed 2026-06-16)

| Host | IP | Status |
|------|----|--------|
| `portal.photomath.net` | 35.190.48.90 (GCP GCLB) | LIVE — 403 from probe IP |
| `dpcapi-admin.photomath.com` | 35.241.40.166 (GCP GCLB) | LIVE — 403 from probe IP |
| `internal.photomath.com` | 209.85.145.121 (GCP) | LIVE — 302 → Google Sites intranet |
| `lapi.photomath.net` | 34.149.49.67 (GCP GCLB) | LIVE — 403 from probe IP |
| `tlapi.photomath.net` | 35.190.29.4 (GCP GCLB) | LIVE — 403 from probe IP |
| `taportal.photomath.net` | 34.160.2.216 (GCP GCLB) | LIVE — 403 from probe IP |
| `cuvar.photomath.net` | 34.120.249.107 (GCP GCLB) | LIVE — 403 from probe IP |
| `metabase.photomath.net` | **NXDOMAIN** | DEAD — DNS record removed |
| All other .net subdomains | ECONNREFUSED | Port closed / VPN-only |

All live IPs are GCP (AS15169) behind Google Cloud Load Balancer — full GCP migration confirmed.

### Key Intelligence

| Finding | Detail | Impact |
|---------|--------|--------|
| Prior XSS on portal | `bughunters.google.com/reports/vrp/weBR95rVi/report` — confirmed valid VRP target | Confirms portal bugs are accepted + rewarded |
| Integer quiz IDs | `/expert-training/qualification-quiz/[N]` — integer enumerable | IDOR candidate for quiz content/answers |
| Expert dashboard | `/home` — expert account home | Horizontal privilege escalation target |
| All live IPs are GCP | Post-migration to Google infra | If SSRF found anywhere → GCP IMDS in scope |
| metabase NXDOMAIN | CVE-2023-38646 angle dead | No takeover/RCE surface here |
| Official GitHub org | `github.com/photomath` | Secret scan target |
| Tech: GKE + React + MongoDB + Node.js | Full stack confirmed from OSINT | Informs IDOR/injection hypothesis |

### Tech Stack (confirmed)
GCP (GCLB + GKE) • React/TypeScript frontend • Node.js/C++/Python backend • MongoDB + PostgreSQL + BigQuery • Redis • Microblink OCR SDK • ArgoCD CI/CD • github.com/photomath (official org)

---

## Session 2 — 2026-06-17 (Pi 5 — Full Phase 1-4 deep scan)

### Subdomain Discovery

- **99 subdomains** discovered (subfinder + crt.sh + scope seed)
- **84 hosts** resolved via dnsx
- httpx returned 0 live hosts (Pi IP blocked by GCP GCLB WAF for HTTP probing)

### New Subdomains Confirmed Live

| Host | IP | Auth | Status |
|------|----|------|--------|
| `argocd-gke-app-eu-prod.photomath.net` | GCP | **Google IAP** (client_id: `867278860234-g77td6ok1cqi9acb0abq8a0d33sn77an`) | IAP protected |
| `argocd-gke-app-us-prod.photomath.net` | GCP | **Google IAP** (same client_id) | IAP protected |
| `argocd-dwh-eu-dev.photomath.net` | GCP | **403 direct (no IAP redirect)** | ⚠️ HIGHEST PRIORITY |
| `idp.photomath.net` | GCP | Unknown IDP | Type unknown |
| `glooker.photomath.net` | GCP | Unknown | Looker BI instance candidate |
| `cms.photomath.net` | GCP | Unknown | CMS type unknown |

### ArgoCD Analysis

- **Prod/test instances** → redirect to `iap.googleapis.com` = properly protected by Google IAP. Dead end.
- **argocd-dwh-eu-dev** → 403 directly (no IAP redirect). Difference: uses different auth mechanism.
  - All ArgoCD API paths tested (`/api/v1/settings`, `/api/v1/applications`, `/api/v1/clusters`, `/api/version`, `/healthz`) → all 403
  - This is either: (A) ArgoCD's own OIDC/LDAP auth returning 403, or (B) separate IP-level firewall
  - **Critical distinction**: ArgoCD unauth typically returns 401 or redirects to `/auth/login`, NOT 403. 403 = WAF or IP block
  - **Action**: From Pi, probe `/auth/login` (ArgoCD login page), `/auth/callback` (OIDC callback), check response headers for auth clues

### WAF Bypass Results (Pi)

| Host | Result |
|------|--------|
| `dpcapi-admin.photomath.com` | **GCLB 404 with bypass headers** (WAF bypassed — real GCLB routing response) |
| `internal.photomath.com` | 302 → `sites.google.com/photomath.com/internal-plus-access` |
| `lapi.photomath.net` | Response varies with bypass headers |
| `tlapi.photomath.net` | Response varies with bypass headers |
| `portal.photomath.net` | TCP 000 (connection refused from Pi IP) |
| `cuvar.photomath.net` | TCP 000 (connection refused from Pi IP) |

### Mobile Browser Results (2026-06-17, no bypass headers needed)

| Path | Response |
|------|----------|
| `dpcapi-admin.photomath.com/` | GCLB 404 (`service rules for the path non-existent`) |
| `dpcapi-admin.photomath.com/api/v1` | GCLB 404 |
| `dpcapi-admin.photomath.com/api/v2` | GCLB 404 |
| `dpcapi-admin.photomath.com/health` | GCLB 404 |
| `dpcapi-admin.photomath.com/healthz` | **`alive`** ← CONFIRMED LIVE BACKEND |
| `dpcapi-admin.photomath.com/admin` | GCLB 404 |
| `dpcapi-admin.photomath.com/swagger` | GCLB 404 |
| `dpcapi-admin.photomath.com/metrics` | GCLB 404 |
| `dpcapi-admin.photomath.com/v1` | GCLB 404 |
| `dpcapi-admin.photomath.com/dpc` | GCLB 404 |
| `argocd-dwh-eu-dev.photomath.net/` | `ERR_EMPTY_RESPONSE` |
| `portal.photomath.net/` | `ERR_EMPTY_RESPONSE` |
| `portal.photomath.net/api/quiz/grade-quizzes/user/273638` | `ERR_EMPTY_RESPONSE` |

**Analysis:** `/healthz` → `alive` confirms the backend service is live and responding without authentication. `/health` (note: no `z`) returns GCLB 404 — precise path routing. The service is likely Go or Kubernetes-native (uses `/healthz` convention). GCLB routing rules are very specific — need to find which other paths have configured backends.

### URL Mining (portal.photomath.net)

- **5383 URLs** mined via gau + waybackurls
- Key finding: `/api/quiz/grade-quizzes/user/273638` — integer user ID `273638` exposed in URL
- This is a **quiz grade IDOR candidate** — if user IDs are enumerable, other users' quiz grades accessible
- Portal blocks Pi IP at TCP level (000) — need browser/VPN for Burp testing

### Quiz ID Probe (unauthenticated from Pi)

All quiz IDs (1, 2, 5, 10, 50, 100, 147, 200, 500, 1000) → 000 (TCP refused from Pi). Portal blocks Pi IP entirely.

### internal.photomath.com — CLOSED

302 → `https://sites.google.com/photomath.com/internal-plus-access` → Google Workspace SSO protected intranet. Not a vulnerability — correctly gated by Google SSO.

---

## Decision Log

| Date | Item | Decision | Rationale |
|------|------|----------|-----------|
| 2026-06-17 | `internal.photomath.com` | CLOSED | 302 → Google Sites intranet; intended design; Google SSO gated |
| 2026-06-17 | `argocd-gke-app-*-prod` | LOW PRIORITY | Google IAP protects prod; requires Google account in allowlist |
| 2026-06-17 | `argocd-dwh-eu-dev` | HIGH PRIORITY | 403 without IAP redirect = different auth; worth probing |
| 2026-06-17 | `dpcapi-admin.photomath.com` | PURSUE | WAF bypassed (404 on /); need to find live API paths |
| 2026-06-17 | `metabase.photomath.net` | CLOSED | NXDOMAIN; CVE-2023-38646 dead |

---

## Findings

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | — | — | No confirmed findings yet — active testing in progress |
| L001 | `argocd-dwh-eu-dev.photomath.net` — 403 without IAP (auth bypass candidate) | TBD | Lead — needs manual probe |
| L002 | `dpcapi-admin.photomath.com/healthz` — only `/healthz` has GCLB routing rule | Info | CLOSED — health check only, no sensitive data, no chain |
| L003 | `dpcapi-admin.photomath.com` — 80+ paths all GCLB routing-miss 404 | — | CLOSED — actual admin API is internal-only (GKE service mesh) |
| L004 | `/api/quiz/grade-quizzes/user/273638` — integer user ID in URL | TBD | Lead — needs authenticated IDOR test |
| [Ref] | Reflected XSS on portal.photomath.net | — | Prior disclosed — not ours |
