# Photomath — OSINT Research Report

**Date:** 2026-06-16 | **Method:** Web search + passive DNS — no live system exploitation  
**Target:** photomath.net / photomath.com (Google-acquired June 2023, TIER0, VRP fully in scope since Dec 2023)

---

## DNS Resolution Summary (confirmed 2026-06-16)

| Host | IP | Hosting | Status |
|------|----|---------|--------|
| `metabase.photomath.net` | **NXDOMAIN** | — | Record removed — no takeover surface |
| `portal.photomath.net` | 35.190.48.90 | **GCP US (GCLB)** | Live — 403 from this probe IP |
| `dpcapi-admin.photomath.com` | 35.241.40.166 | **GCP (GCLB)** | Live — 403 from this probe IP |
| `internal.photomath.com` | 209.85.145.121 | **GCP / Google** | Live — 403 from this probe IP |
| `lapi.photomath.net` | 34.149.49.67 | **GCP (GCLB)** | Live — 403 from this probe IP |
| `tlapi.photomath.net` | 35.190.29.4 | **GCP (GCLB)** | Live — 403 from this probe IP |
| `taportal.photomath.net` | 34.160.2.216 | **GCP (GCLB)** | Live — 403 from this probe IP |
| `cuvar.photomath.net` | 34.120.249.107 | **GCP (GCLB)** | Live — 403 from this probe IP |
| `dpcapi-admin.photomath.net` | ECONNREFUSED | — | Port closed |
| `internal.photomath.net` | ECONNREFUSED | — | Port closed |
| `baja/daportal/dpcapi/mankey/zuja.photomath.net` | ECONNREFUSED | — | Port closed |

**Key insight:** All live services are on GCP Google Cloud Load Balancer. Google has migrated the infrastructure. The 403 responses are WAF/IP restrictions, NOT dead services — the TCP handshake succeeds and the server is replying.

---

## 1. Product Overview

Photomath (acquired by Google June 2023) is an AI-powered math solver iOS/Android app with 250M+ downloads. Users photograph or type math problems; the app solves them with step-by-step explanations.

The **expert marketplace** (`portal.photomath.net`) is a B2B platform where human math experts are hired to solve problems and create solution content that trains the ML model. This is the primary security-relevant web surface.

**Acquisition timeline:**
- May 2022: Google announces intent (largest Croatian startup exit ever)
- March 2023: EU Commission approves
- June 6, 2023: Deal closes
- Feb 2024: Play Store + App Store publisher switches to "Google LLC"
- Dec 2023+: VRP blackout period ends — fully in scope

---

## 2. Tech Stack

| Layer | Technology | Confidence |
|-------|-----------|-----------|
| Cloud | **GCP** (confirmed — all IPs in GCP ASN15169) | HIGH |
| Load balancer | **Google Cloud Load Balancer** (all IPs in GCLB range) | HIGH |
| Orchestration | **Kubernetes** (GKE) | HIGH |
| CI/CD | Jenkins, GitHub CI, **ArgoCD** | HIGH |
| Backend | **Node.js** (historical), **C++** (math engine), **Python** (ML/data), Kotlin, Java | HIGH |
| Web frontend | **React + TypeScript** | HIGH |
| Mobile | **Swift** (iOS), **Kotlin/Java** (Android) — native | HIGH |
| Databases | **MongoDB, PostgreSQL, MySQL, BigQuery** | HIGH |
| Cache | **Redis** | HIGH |
| ML/AI | PyTorch, ClearML, self-hosted GPUs | HIGH |
| OCR | **Microblink SDK** (C++) — package name still `com.microblink.photomath` | HIGH |
| VCS | **github.com/photomath** (official org) | HIGH |

---

## 3. Live Attack Surfaces

### Surface 1 — portal.photomath.net (PRIMARY TARGET)

**What it is:** Expert marketplace — external contractors (math experts) log in to solve problems submitted by users, take qualification quizzes, and earn money per correct solution. Google-indexed, real user traffic.

**Confirmed live:** GCP IP 35.190.48.90, TCP handshake succeeds, 403 from probe IP  
**Prior VRP finding:** Reflected XSS already disclosed — `bughunters.google.com/reports/vrp/weBR95rVi/report` — confirms the VRP team accepts portal findings and that bugs exist here.

**Exposed endpoints (from Google-indexed cache):**
- `https://portal.photomath.net/login` — expert login
- `https://portal.photomath.net/home` — expert dashboard
- `https://portal.photomath.net/expert-training/qualification-quiz/[integer]` — quiz system with **integer IDs**
- `https://portal.photomath.net/solve` — solver/submission interface

**Bug classes to test:**
1. **IDOR on quiz IDs** — integer enumeration on `/expert-training/qualification-quiz/N` could expose other experts' quiz content, answers, or evaluation status
2. **Horizontal privilege escalation** — can Expert A view Expert B's dashboard, earnings, submitted solutions?
3. **Vertical privilege escalation** — can an expert account access admin/grader functionality?
4. **OAuth misconfiguration** — Google Sign-In OAuth client IDs for this app; redirect_uri allowlist
5. **API IDOR** — underlying API calls from the portal frontend (IDOR on solution IDs, user IDs, case IDs)

---

### Surface 2 — dpcapi-admin.photomath.com (HIGH VALUE)

**What it is:** Admin plane for the "DPC" (Data Processing/Content) API — the internal API that handles math problem submissions and solutions.

**DNS:** 35.241.40.166 (GCP) — live server, 403 from probe IP  
**Why high value:** An admin API (`-admin` suffix) returning 403 is a WAF block, not a disabled service. From Pi (different IP), this may serve a login page or expose API endpoints.

**Bug classes to test:**
1. **Auth bypass on admin login** — is the login protected by Google SSO or legacy Photomath credentials?
2. **Unauthenticated endpoint discovery** — `/health`, `/actuator`, `/swagger`, `/api-docs`, `/v1/status`
3. **HTTP header WAF bypass** — `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `CF-Connecting-IP: 127.0.0.1`

---

### Surface 3 — lapi / tlapi / taportal / cuvar.photomath.net (MEDIUM VALUE)

All GCP-hosted, TCP-alive, returning 403. Likely API microservices:
- `lapi` = Learning API
- `tlapi` = Teacher/Tutor Learning API (versioned)
- `taportal` = Teacher/Tutor A Portal (instructor-facing)
- `cuvar` = Croatian codename microservice

**Bug classes:** same as Surface 2 — WAF bypass + endpoint discovery + IDOR

---

### Surface 4 — github.com/photomath (PASSIVE — LOW RISK)

Official GitHub org exists. Public repos may contain:
- Hardcoded API keys, credentials, or tokens in commit history
- Internal service names and endpoint paths
- CI/CD config revealing infrastructure details

---

## 4. Metabase (CVE-2023-38646) — Status

`metabase.photomath.net` → **NXDOMAIN** — DNS record removed. The instance was in scope.yaml (suggesting it existed and was tested at some point) but the record is gone. Either:
- (A) The instance was decommissioned after someone already hit it
- (B) It moved to a different hostname or VPN-only

**CVE-2023-38646 details (for reference if Metabase found elsewhere):**
- CVSS 9.8 Critical, pre-auth RCE
- Attack: `GET /api/session/properties` → get `setup-token` → `POST /api/setup/validate` with H2 JDBC payload containing JavaScript TRIGGER
- Vulnerable: Metabase OSS < 0.46.6.1 / Enterprise < 1.46.6.1
- Fixed: July 21, 2023 (Photomath acquisition closed June 6, 2023 — tight window)

If Metabase is reachable anywhere in Photomath's network (internal recon via SSRF), test for it.

---

## 5. Prior Security Research

- **Reflected XSS on portal.photomath.net** — confirmed via Google Bug Hunters public report URL. Demonstrates the portal has had real vulnerabilities and is an accepted VRP target.
- No HackerOne/Bugcrowd public reports (Google uses its own platform)
- No public CVEs for Photomath pre-acquisition
- Zero publicly documented bug bounty writeups for Photomath

→ **Low-competition target.** The XSS is the only publicly known finding.

---

## 6. Google Integration Status

- **Infrastructure:** Fully on GCP (all live IPs confirm GCP GCLB)
- **App store:** Publisher switched to Google LLC in Feb 2024
- **Internal auth migration:** Unknown from public sources — likely Google Workspace SSO by now (deal closed June 2023, typical 6–18 month migration)
- **portal.photomath.net:** Still running legacy Photomath infrastructure on GCP; Cloudflare-fronted (per historical data, but current DNS shows direct GCP IP)
- **Standalone app:** Photomath not yet merged into Google Lens/Search; remains standalone

---

## 7. Top Attack Classes (Prioritized)

### #1 — IDOR on portal.photomath.net quiz/solution IDs

Integer IDs at `/expert-training/qualification-quiz/[N]` are the clearest IDOR target. Register as an expert, observe your quiz ID N, try N±1, N+100, etc. If another expert's quiz data (answers, score, personal info) is accessible, that's a valid High finding.

### #2 — Horizontal privilege escalation between expert accounts

Two expert accounts — can Account A view Account B's solutions, earnings, or personal details? Classic multi-tenant isolation break on a marketplace platform.

### #3 — WAF bypass → admin API access on dpcapi-admin.photomath.com

From Pi, try HTTP header manipulation bypasses on the 403. If the underlying admin panel is accessible once WAF is bypassed, look for unauthenticated endpoints or weak auth.

### #4 — API IDOR on underlying portal API calls

Capture API calls from the portal frontend (Burp Suite). Solution IDs, user IDs, case assignment IDs — any numeric/GUID identifier that could be enumerated across expert accounts.

### #5 — GitHub secrets at github.com/photomath

Run trufflehog or gitleaks against the official GitHub org. One leaked API key = immediate High.
