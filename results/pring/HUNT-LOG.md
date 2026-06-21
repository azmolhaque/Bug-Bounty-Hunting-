# Hunt Log — Pring Cluster (TIER0)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER0 (Pring — Japanese P2P payment app, acquired ~2022)
**Probe Date:** 2026-06-21
**Status:** ⛔ CLOSED — SERVICE TERMINATED MAY 2026

---

## Scope (from config/scope.yaml — TIER0)

```
- admin.pring.app
- callback.pring.app
- staging.callback.pring.app
- api.pring.jp
- dev-api.pring.jp
- future-api.pring.jp
- support.pring.jp
- www.pring.jp
```

---

## ⛔ PRING CLOSED — 2026-06-21

**Pring app service terminated 2026-05-22.**

From www.pring.jp news section (live as of today):
- `2026-05-22: pringアプリサービス終了のお知らせ` ("pring app service termination notice")
- `2026-05-21: 【お詫び】アプリにログインできない不具合について` ("Login issue apology notice")

This explains the entire cluster state. All API infrastructure decommissioned post-shutdown.

---

## Session 1 — 2026-06-21 — Cluster Fingerprint

### DNS / HTTP Status

| Host | IP | Status | Finding |
|------|----|--------|---------|
| `admin.pring.app` | NXDOMAIN | 000 | Dead — DNS removed |
| `callback.pring.app` | 18.164.144.85 (AWS CF) | 403 | AWS CloudFront → API Gateway; `x-amzn-errortype: ForbiddenException` — API key required |
| `staging.callback.pring.app` | 54.192.151.52 (AWS CF) | 403 | Same — API key required; prior orchestrator "RCE" candidate Ndddf1e = false positive (API GW headers matched nuclei template) |
| `api.pring.jp` | NXDOMAIN | 000 | Dead |
| `dev-api.pring.jp` | NXDOMAIN | 000 | Dead |
| `future-api.pring.jp` | NXDOMAIN | 000 | Dead |
| `support.pring.jp` | pring.zendesk.com CNAME | 000 | Zendesk (OOS) |
| `www.pring.jp` | AWS ELB Tokyo | **200** | Live marketing tombstone site |

### www.pring.jp Analysis

**Stack:** Rails 6+ on AWS ELB (ap-northeast-1); CloudFront CDN `db2a0lgmp98ef.cloudfront.net`.
- CSP: `report-uri https://csp.withgoogle.com/csp/pring/pring-customer-portal` (Google-owned)
- Cookie: `_pring_www_session` (Rails 6+ 3-part encrypted session)
- Not SPA: random path → 404 (real route table)

**Active routes (informational):**
- `/` → 200 (marketing landing)
- `/terms` → 200
- `/robots.txt` → 200 (empty body)
- `/news_info/:id` → news articles (e.g. `/news_info/294` = termination notice)
- `/faq?question=...` → FAQ search

**JSON catch-all:** All paths with `Accept: application/json` → 200 with empty body (`text/plain`, head:ok). Not real API routes — confirmed by random paths `/api/v99/completelyfake → 200` etc.

**No auth surface:** No login, register, or API endpoints. www.pring.jp is a static marketing/info site only.

### Orchestrator Candidates (staging.callback.pring.app) — CLOSED as False Positives

| ID | Class | Status |
|----|-------|--------|
| Ndddf1e | [RCE] | FALSE POSITIVE — API Gateway `ForbiddenException` headers matched nuclei RCE template; actual 403 API key gate |
| N4c7514 | [unknown-info] | CLOSED — insufficient data |
| N952f65 | [unknown-info] | CLOSED — insufficient data |
| Ncfe8dc | [unknown-info] | CLOSED — insufficient data |
| Nf11d8d | [unknown-info] | CLOSED — insufficient data |

---

## Lead Status — FINAL

| ID | Surface | Status |
|----|---------|--------|
| All leads | All Pring TIER0 hosts | ⛔ CLOSED — service terminated 2026-05-22 |

**PIVOT → adhawkdev.com** (TIER1, Adhawk Microsystems eye-tracking acquisition, completely untested)
