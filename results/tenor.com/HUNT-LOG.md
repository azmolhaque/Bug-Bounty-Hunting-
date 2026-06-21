# Hunt Log — tenor.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1
**Started:** 2026-06-21
**Status:** RECON — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- tenor.com    # TIER1, acquired 2018
```

**SCOPE NOTE:** Only `tenor.com` apex is explicitly listed. Per acquisition-domain rules,
unlisted subdomains default to TIER4. Key implication: `api.tenor.com` and `www.tenor.com`
are technically OOS unless the Google VRP rules treat the listed apex as covering direct
subdomains. Probe `tenor.com` itself first; if real API surface exists at apex level (e.g.,
`tenor.com/api/...`), that is clearly in scope.

The GIF developer API (`tenor.googleapis.com`) is served through `googleapis.com` which is
explicitly TIER4 in scope.yaml — do NOT probe it.

---

## Pre-Recon Hypothesis

| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | `tenor.com` API paths | GIF platform — upload, search, embed endpoints | SSRF (URL import), IDOR (GIF/user ID), stored XSS |
| 2 | Upload endpoint | Animated GIF processing — URL-based import = SSRF | SSRF |
| 3 | Content delivery | Cross-account GIF access, unlisted content | IDOR |

---

## Session 1 — 2026-06-21 (COMPLETE)

**tenor.com root (HTTP/2 200):**
- Live web application: 250KB response, App Engine Flex backend
- Build: `release=r260617-1-master-a09c` (2026-06-17 — very recent)
- `set-cookie: countryCode=BD; path=/` — geo-detection cookie, not auth
- `unsafe-eval` present in `script-src` (alongside nonce)
- `via: 1.1 google` — GFE proxied

**CSP domains (passive, informational):**
- `connect-src`: `*.tenor.co`, `*.tenor.com`, `*.googleapis.com`, `tenor.googleapis.com`
- `img-src / media-src`: `media.tenor.co`, `media.tenor.com`, `media1.tenor.co`, `media1.tenor.com`, `c.tenor.com`
- All subdomains OOS (unlisted acquisition subdomains = TIER4)

**Path probe results:**
| Path | Status | Notes |
|------|--------|-------|
| `/` | **200** | Live SPA |
| `/search` | **200** | Real endpoint — not a catch-all |
| `/robots.txt` | **200** | To be mined |
| `/api` | 301 | Redirect |
| `/api/v1` | 404 | Real 404 — route table exists (not catch-all) |
| `/health` | 404 | — |
| `/upload` | 404 | — |
| `/gif` | 404 | — |
| `/trending` | 404 | — |
| `/.well-known/openid-configuration` | 404 | No OIDC |

**www.tenor.com:** 301 → `https://tenor.com/`. Response includes `x-debug-*` headers:
`x-debug-canonicalpath`, `x-debug-currentpath`, `x-debug-host`, `x-debug-hostname`,
`x-debug-protocol`, `x-debug-scheme` — debug routing headers in production. www.tenor.com
is OOS (unlisted subdomain), so not directly reportable, but confirms same App Engine app.

**Session 1 verdict:** tenor.com is LIVE with a real route table. Pursue Session 2.

---

## Session 2 — 2026-06-21 (COMPLETE)

**Full config blob decoded from `<script id="data" type="text/x-cache">` on /gifapi:**
```json
{
  "API_KEY": "JJHDC7UK73EH",          → api-v1.tenor.com/v1  (OOS)
  "API_V2_KEY": "AIzaSyCZt6SSh5VgVPzD9fhyzG1DprdPRhtoaR4",  → tenor.googleapis.com/v2  (OOS/TIER4)
  "GOOGLE_SIGNIN_CLIENT_ID": "598652403343-harjvt5thjol9qjkrfqpmb7njrnek80v.apps.googleusercontent.com",
  "FB_ID": "210233399450162",
  "MV_RESET_TIMESTAMP": 1546300800
}
```
All credentials public-by-design: OAuth client IDs and Facebook App IDs are meant to be public;
browser API keys target OOS endpoints. TEN-L004 **CLOSED** — no reportable credential exposure.

**gifapi/documentation (200):** Same SPA shell + same config blob. API docs only.

**search/cats-gifs (200):** Returns 250KB rendered HTML (SSR'd SPA). Not a JSON API.
Content-type: text/html — real search results are baked into SSR HTML, not served as JSON.

**Account paths:** All 404. No user account management surface on tenor.com.

**GAE paths:** All 404. No admin console exposure.

**CORS:** No Access-Control-Allow-Origin reflection observed.

## ⛔ TENOR CLOSED — 2026-06-21

**Verdict:** Same architectural pattern as Waze biz.waze.com and accounts.fitbit.com.
tenor.com is a pure SSR/SPA frontend. All API, auth, and user-data surface lives on:
- `api-v1.tenor.com/v1` → OOS (unlisted acquisition subdomain = TIER4)
- `tenor.googleapis.com/v2` → OOS (googleapis.com = TIER4)
- Google Sign-In → OOS (accounts.google.com)

The in-scope `tenor.com` domain has: rendered HTML search pages + developer docs + zero API
or user-data endpoints. No attack surface accessible to an unauthenticated external tester.

**PIVOT → Fitbit unprobed TIER1 subdomains:** `health-admin.fitbit.com`, `mgmt.fitbit.com`,
`ngw.fitbit.com`, `coaching-dashboard.fitbit.com`, `strava.fitbit.com` — none of these have
been touched. Admin-class names (health-admin, mgmt) are the highest priority.

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| TEN-L001 | Search endpoint | `tenor.com/search` (200) | ❌ CLOSED — SSR HTML, no JSON API |
| TEN-L002 | JS bundle mining | `tenor.com` SPA | ❌ CLOSED — all API endpoints on OOS hosts |
| TEN-L003 | GAE internal paths | `tenor.com/_ah/...` | ❌ CLOSED — all 404 |
| TEN-L004 | Credential exposure | Config blob API keys | ❌ CLOSED — all public-by-design or OOS targets |
