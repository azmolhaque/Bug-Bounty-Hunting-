# Hunt Log — Area 120 Cluster (TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Area 120 — Google's internal incubator)
**Started:** 2026-06-21
**Status:** RECON — Session 1 runbook ready, awaiting Pi execution

---

## Scope (from config/scope.yaml — TIER1)

```
- orionwifi.area120.com
- signals.area120.com
- threadit.area120.com
- threadit.app
- enexpress.app
```

---

## DNS Fingerprint (cloud env — 2026-06-21)

| Host | IP | Infra | Notes |
|------|----|-------|-------|
| orionwifi.area120.com | 173.194.206.113 | Google GFE | Orion WiFi = premium WiFi marketplace |
| signals.area120.com | 8.232.133.29 | Akamai CDN | Analytics/engagement product |
| threadit.area120.com | 173.194.206.102 | Google GFE | Threadit = async video messaging |
| threadit.app | 74.125.69.101 | Google | .app TLD version |
| enexpress.app | NXDOMAIN | — | Dead / decommissioned |

**403s from cloud env = Anthropic egress gateway blocking. Actual HTTP responses unknown — need Pi.**

---

## Pre-Recon Thesis

Area 120 is Google's internal experimental product incubator. These are/were live consumer
products that received less security scrutiny than core Google products.

| Product | Status | Bug class |
|---------|--------|-----------|
| **Orion WiFi** (orionwifi.area120.com) | Active — connects travelers to hotel/venue WiFi for revenue share | Auth, payment bypass, venue IDOR |
| **Signals** (signals.area120.com) | Analytics dashboard | IDOR on org data, auth bypass |
| **Threadit** (threadit.area120.com + threadit.app) | Async video messaging for teams | User IDOR, video access, auth |
| **enexpress.app** | NXDOMAIN — dead product | — |

**Key insight:** Area 120 products have historically had weaker security review than
core Google. They often ship faster with smaller teams. Orion WiFi in particular has a
multi-tenant model (venues + users) with payment logic — historically a rich target class.

---

## Session 1 — 2026-06-21

[Pending Pi probe output — see runbooks/PI-RUNBOOK-area120-session1.md]

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| A120-L001 | IDOR / auth | `orionwifi.area120.com` | PENDING — session 1 |
| A120-L002 | IDOR / auth | `signals.area120.com` | PENDING — session 1 |
| A120-L003 | IDOR / auth | `threadit.area120.com` + `threadit.app` | PENDING — session 1 |
