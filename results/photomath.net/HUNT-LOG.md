# Hunt Log — photomath.net / photomath.com (Google VRP TIER0)

**Started:** 2026-06-16  
**Target:** Photomath (Google-acquired June 2023) — math solver iOS/Android app + backend  
**Scope:** TIER0 — photomath.net, photomath.com, + 13 explicitly named internal subdomains  
**Program:** Google VRP / bughunters.google.com

---

## Priority Targets (from OSINT)

| Subdomain | Reason | Priority |
|-----------|--------|----------|
| `metabase.photomath.net` | Metabase BI tool — CVE-2023-38646 pre-auth RCE (CVSS 9.8) | ⭐⭐⭐ CRITICAL |
| `dpcapi-admin.photomath.net` | Admin API — auth bypass candidate | ⭐⭐⭐ HIGH |
| `internal.photomath.net` | Internal tooling — weak auth candidate | ⭐⭐ HIGH |
| `dpcapi-admin.photomath.com` | Admin API (com variant) | ⭐⭐ HIGH |
| `dpcapi.photomath.net` | Data processing API — IDOR candidate | ⭐⭐ MEDIUM |
| `lapi.photomath.net` / `tlapi.photomath.net` | API endpoints — auth/IDOR | ⭐ MEDIUM |
| `mankey.photomath.net` | Internal service (Pokémon codename?) — unknown surface | ⭐ MEDIUM |
| `baja/cuvar/zuja.photomath.net` | Internal microservices (Croatian codenames) | ⭐ LOW |

---

## Session 1 — 2026-06-16 (Remote — OSINT + passive recon)

### Tech Stack (confirmed from OSINT)

| Layer | Technology | Source |
|-------|-----------|--------|
| Cloud | **GCP** (primary, post-acquisition) | Engineering blog |
| Orchestration | **Kubernetes** | LinkedIn job listing |
| CI/CD | Jenkins, GitHub CI, **ArgoCD** | LinkedIn |
| Backend (API) | **Node.js** (historical), **C++** (math engine), **Python** (ML), Kotlin, Java | Engineering blog + jobs |
| Web frontend | **React, TypeScript** | Job listings |
| Mobile | **Swift** (iOS), **Kotlin/Java** (Android) — native, not React Native | Job listings |
| Databases | **MongoDB, PostgreSQL, MySQL, BigQuery** | Job listings |
| Cache | **Redis** (GKE Cloud MemoryStore) | Engineering blog |
| Search | **Elasticsearch** | Job listings |
| ML/AI | PyTorch, ClearML, self-hosted GPUs | ClearML case study |
| OCR/camera | **Microblink SDK** (C++) | GitHub code |
| Analytics/BI | **Metabase** (`metabase.photomath.net`) | scope.yaml explicit listing |
| VCS | GitHub — official org: **github.com/photomath** | Search confirmed |
| HQ | Zagreb, Croatia + San Mateo, CA | Crunchbase |
| Headcount | ~200 employees | LinkedIn |
| Acquisition | Google completed acquisition June 2023 | Wikipedia |

### Key Findings (OSINT phase)

1. **github.com/photomath** — official GitHub org exists. Need to enumerate public repos for: hardcoded secrets, API endpoint paths, internal service names, CI/CD config.

2. **Metabase confirmed as target** — `metabase.photomath.net` is explicitly in VRP scope.yaml (added by Google VRP team = tested surface). Metabase CVE-2023-38646 is pre-auth RCE via JDBC H2 database connection string injection. If unpatched: unauthenticated RCE from public internet.

3. **Croatian microservice codenames** — `baja`, `cuvar`, `zuja`, `mankey`, `daportal`, `taportal` suggest Zagreb engineering team's internal naming. "Mankey" is a Pokémon. These are likely internal microservices exposed on the `photomath.net` subdomain with potentially weak auth.

4. **"dpc" prefix** — `dpcapi.photomath.net`, `dpcapi-admin.photomath.net` — "dpc" likely = "Data Processing Controller" or "Data Processing Core" — Photomath's internal API for math problem submission/result retrieval. `-admin` variant = admin panel, highest value target.

5. **GCP post-acquisition** — Moved from pre-acquisition cloud to GCP. Migration period = highest risk for exposed legacy services.

### Pending (live probe results — waiting for agent)

- All 18 subdomains probed via WebFetch — results pending
- crt.sh additional subdomains — results pending
- Metabase CVE-2023-38646 attack path details — results pending

---

## Findings

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | — | — | OSINT phase only — no confirmed findings yet |
