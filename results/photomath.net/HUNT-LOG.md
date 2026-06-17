# Hunt Log — photomath.net / photomath.com (Google VRP TIER0)

**Started:** 2026-06-16  
**Target:** Photomath (Google-acquired June 2023) — math solver iOS/Android + expert marketplace  
**Scope:** TIER0 — photomath.net, photomath.com, + 13 explicitly named internal subdomains  
**VRP blackout ended:** December 2023 — fully in scope  
**Program:** Google VRP / bughunters.google.com

---

## CURRENT STATUS

| # | Item | Status |
|---|------|--------|
| 1 | **portal.photomath.net** — IDOR on quiz integer IDs | 🎯 PURSUE — primary target |
| 2 | **portal.photomath.net** — horizontal privilege escalation | 🎯 PURSUE — secondary |
| 3 | **dpcapi-admin.photomath.com** — WAF bypass + auth bypass | ⏳ PENDING (Pi) |
| 4 | **github.com/photomath** — secrets scan | ⏳ PENDING (Pi) |
| 5 | **metabase.photomath.net** — CVE-2023-38646 | ❌ DEAD — NXDOMAIN, record removed |

**NEXT ACTION:** On Pi — register two expert accounts at portal.photomath.net, set up Burp Suite, enumerate quiz IDs with Intruder, replay API calls cross-account.

---

## Session 1 — 2026-06-16 (Remote — OSINT + passive recon)

### DNS Resolution (confirmed 2026-06-16)

| Host | IP | Status |
|------|----|--------|
| `portal.photomath.net` | 35.190.48.90 (GCP GCLB) | LIVE — 403 from probe IP |
| `dpcapi-admin.photomath.com` | 35.241.40.166 (GCP GCLB) | LIVE — 403 from probe IP |
| `internal.photomath.com` | 209.85.145.121 (GCP) | LIVE — 403 from probe IP |
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

## Findings

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | — | — | OSINT phase only — no confirmed findings yet |
| [Ref] | Reflected XSS on portal.photomath.net | — | Prior disclosed — not ours |
