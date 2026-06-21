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
| WAZ-L001 | SSRF (potential) | proxy.waze.com + proxy-staging.waze.com | HYPOTHESIS — needs Pi probe |
| WAZ-L002 | IDOR (WAM API accounts) | ads.wazeapis.com/v1/accounts/{account}/... | BLOCKED — needs WAZE_ACCESS_TOKEN |
| WAZ-L003 | Unauthenticated exposure | adsapi-staging.waze.com | HYPOTHESIS — needs Pi probe |
| WAZ-L004 | SSRF (partner feed) | www.waze.com/partnerhub | BLOCKED — needs Waze for Cities partner status |
