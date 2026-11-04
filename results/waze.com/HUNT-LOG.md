# Hunt Log — waze.com / biz.waze.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)  
**Targets:** biz.waze.com, adsapi.waze.com, adsapi-staging.waze.com, proxy.waze.com, proxy-staging.waze.com  
**Tier:** TIER1 (Waze)  
**Started:** 2026-06-21  
**Status:** PLANNING — Session 1 runbook ready, awaiting Pi execution

---

## CURRENT STATUS

| # | Item | Status |
|---|------|--------|
| 1 | OSINT research | ✅ COMPLETE — see OSINT-prior-art-and-leads.md |
| 2 | Session 1 Pi runbook | ✅ READY — runbooks/PI-RUNBOOK-waze-session1.md |
| 3 | proxy.waze.com probe | ⏳ PENDING — Pi execution required |
| 4 | adsapi-staging.waze.com probe | ⏳ PENDING — Pi execution required |
| 5 | WAM API (ads.wazeapis.com) probe | ⏳ PENDING — Pi execution required |
| 6 | biz.waze.com pre-auth surface | ⏳ PENDING — Pi execution required |

**NEXT ACTION**: Run PI-RUNBOOK-waze-session1.md from the Pi.

---

## Key Research Findings (pre-session)

### Platform Status — CRITICAL
Waze Ads **shut down September 1, 2023**. No new Waze Ads accounts can be created. The biz.waze.com portal shows wind-down messaging. This removes write-surface (ad creation = XSS/SSRF vector) and blocks authenticated testing without a pre-2023 Waze Ads account.

### WAM API Resource Format (IDOR candidate if accessible)
- Base: `https://ads.wazeapis.com/v1/`
- Resources: `accounts/{account}/campaigns`, `accounts/{account}/locations`, `accounts/{account}/ads`, `accounts/{account}/roleAssignments`
- Account IDs: GID format = region_code + sequential_integer (NA = 10xxxx, others TBD)
- Auth: WAZE_ACCESS_TOKEN (1-hour validity) obtained from `biz.world.waze.com/app/auth/refresh-token`
- **Blocker**: WAZE_ACCESS_TOKEN requires pre-2023 Waze Ads account

### Partner Hub Data Feed (SSRF candidate if partnership accessible)
- Waze's backend fetches partner-provided URLs every few minutes (dynamic IPs)
- Classic SSRF if URL can be set to GCP IMDS
- **Blocker**: Requires approved "Waze for Cities" partner status (municipal/government program)

### Prior Disclosures (all old)
- Stored XSS on biz.waze.com (2018, Rojan Rijal) — fixed in ad content fields
- User tracking (2020, Peter Gasper, $1,337) — fixed, API-level
- Remote vulnerabilities (2018, PanguTeam) — unspecified

### Unknown Surfaces (Pi probe will determine)
- `proxy.waze.com` — undocumented; "proxy" name suggests URL-fetching → potential SSRF
- `proxy-staging.waze.com` — staging variant, potentially weaker auth
- `adsapi-staging.waze.com` — staging API, potentially exposed endpoints

---

## Decisions Log

| Date | Item | Decision | Rationale |
|------|------|----------|-----------|
| 2026-06-21 | Waze Ads authenticated surface | BLOCKED | No new Waze Ads account registration possible (shut down Sept 2023) |
| 2026-06-21 | Partner Hub SSRF | BLOCKED | Requires Waze for Cities partnership |
| 2026-06-21 | proxy.waze.com | PURSUE (Session 1) | Undocumented, highest uncertainty, potential SSRF |
| 2026-06-21 | adsapi-staging.waze.com | PURSUE (Session 1) | Staging often less guarded |
| 2026-06-21 | WAM API health probe | PURSUE (Session 1) | May respond without auth; reveals if API still live |
| 2026-06-21 | biz.waze.com pre-auth | PURSUE (Session 1) | Standard pre-auth sweep |

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| WAZ-L001 | SSRF (potential) | proxy.waze.com + proxy-staging.waze.com | ❌ CLOSED — DEAD. Blanket 301 → www.waze.com on every path (GFE redirector, not a fetcher) |
| WAZ-L002 | IDOR (WAM API accounts) | ads.wazeapis.com/v1/accounts/{account}/... | BLOCKED — needs WAZE_ACCESS_TOKEN; host 301s (parked, redirect target TBD) |
| WAZ-L003 | Unauthenticated exposure | adsapi-staging.waze.com | ❌ CLOSED — DEAD. Same blanket 301 → www.waze.com as adsapi.waze.com |
| WAZ-L004 | SSRF (partner feed) | www.waze.com/partnerhub | BLOCKED — needs Waze for Cities partner status |

---

## Session 1 — 2026-06-21 (Pi probe results)

**All four ad-API hosts are decommissioned.** `proxy.waze.com`, `proxy-staging.waze.com`,
`adsapi-staging.waze.com`, `adsapi.waze.com` all resolve to `130.211.9.172` (CNAME → waze.com)
and return `HTTP/2 301 → https://www.waze.com/` on every path, served by `Google Frontend`.
No app behind them. WAZ-L001 and WAZ-L003 CLOSED (dead infra, confirms Sept-2023 ads shutdown).

`ads.wazeapis.com` (WAM API) → 301 on /v1/health, /v1/, /v1/accounts. Parked; redirect target
to be confirmed (Session 1b).

`biz.waze.com` (34.111.115.4) and `biz.world.waze.com` (34.36.203.208) → live SPA, **catch-all
200 on every probed path** (/, /app/signup, /health, /.well-known/openid-configuration, etc.).
This is the SPA index.html shell, NOT distinct endpoints. Real surface = the backend API the
SPA calls (needs auth; no new ads accounts possible). Session 1b: mine the SPA JS for the real
API host + check if openid-configuration is real JSON.

**DECISION GATE:** If Session 1b finds no live backend API reachable pre-auth → Waze surface is
exhausted for an unauthenticated solo hunter → PIVOT.

### Session 1b — 2026-06-21 (deciding probe) → WAZE CLOSED

- `biz.waze.com/.well-known/openid-configuration` → **empty body** (no real OIDC; the earlier
  catch-all 200 was the SPA following a redirect to an empty 200).
- `ads.wazeapis.com/v1/health` and `/v1/accounts` → redirect chain
  `→ waze.com/ads → www.waze.com/ads → support.google.com/wazeads → 404`. **WAM API fully
  decommissioned.** WAZ-L002 CLOSED (dead, not just blocked).
- `biz.waze.com/app/login` → 0 bytes without `-L`+browser UA. Auth-gated SPA shell; no new
  Waze Ads accounts can be created (platform shut down Sept 2023).

**VERDICT: WAZE CLOSED.** Every host is either a dead redirector or an auth-gated SPA behind
an account that cannot be created. No unauthenticated live surface exists. All leads
WAZ-L001..L004 closed or permanently blocked.

**PIVOT → Nest** (fresh TIER0/TIER1 cluster, see results/nest.com/HUNT-LOG.md).
Photomath portal IDOR (TIER0) remains documented as the concrete desktop-session lead.
