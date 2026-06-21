# Hunt Log — work.webpass.net (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Webpass — Google Fiber ISP subsidiary, acquired 2016)
**Started:** 2026-06-21
**Status:** ACTIVE — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- webpass.net
- work.webpass.net
```

**Scope notes:**
- `work.webpass.net` is explicitly listed — TIER1. **PRIMARY TARGET.**
- `webpass.net` (apex) is explicitly listed — TIER1.
- `api.webpass.net`, `www.webpass.net` are NOT listed → TIER4 (OOS). Do not test.
- `webpass.withgoogle.com` explicitly TIER4 in VRP protobuf. Do not test.

---

## Pre-Recon Intelligence (from passive recon, 2026-06-19 session)

| Host | IP | Stack | Role |
|------|----|-------|------|
| `work.webpass.net` | 34.72.62.205 (GCP us-central1) | Rails app | ISP customer portal |
| `webpass.net` (apex) | 34.120.232.54 (GCP Global LB) | Unknown | Marketing or redirect |

**`work.webpass.net` attack surface hypothesis:**
- **IDOR on customer accounts** — Rails ISP portals expose `/accounts/:id`, `/invoices/:id`, `/services/:id` with sequential or guessable integer IDs. Billing data + ISP account info = high-impact.
- **Open registration** — if unauthenticated sign-up exists, can create account and enumerate API surface without being a real Webpass customer.
- **Rails-specific exposures** — `/rails/info/properties` (dev mode), `/assets/application-*.js` (JS bundle with route list), ActiveAdmin if admin panel deployed.
- **OAuth bridge** — ISP portals use Google OAuth; check for open redirect in callback, state fixation.

**Why TIER1:** Successful IDOR on billing/account data exposes another ISP customer's:
- PII (name, address, account number)
- Billing history / invoice amounts
- Service plan details
- Network status / installation details

---

## Session 1 — 2026-06-21 (Pi probe — fingerprint + surface map)

### Runbook
See: `runbooks/PI-RUNBOOK-webpass-session1.md`

### Results

**Stack confirmed:**
- `X-Powered-By: Phusion Passenger(R)` + `X-Runtime: 0.004997` + `X-Rack-Cache: miss` + `X-Request-Id` → **Rails on Phusion Passenger + nginx**
- Cookie: `_portal_session=...` (Rails signed/encrypted session, `--` separator = Rails 4+)
- Auth controller: `/user_sessions/new` → **Authlogic** (NOT Devise — older, less-reviewed auth gem)
- **NOT a SPA**: random path `/thisdoesnotexist_xhsj38` → 404 = **real route table** ✓

**CSP disclosure:**
- `frame-ancestors https://apps.usw2.pure.cloud/` → Genesys Cloud PureCloud CRM integration: portal is embedded in support-agent CRM console
- `report-uri https://csp.withgoogle.com/csp/webpass-internal/20191113_experiment` → Google-internal CSP reporting

**Path probe summary:**

| Path | Status | Finding |
|------|--------|---------|
| `/` | 302 → `/user_sessions/new` | Login required |
| `/login` | 301 | Redirect (to login) |
| `/users/sign_in` | 302 | Redirect (Devise path also exists?) |
| `/register` | **404** | No self-registration |
| `/sign_up` | **404** | No self-registration |
| `/users/sign_up` | **302** | Redirect — destination unknown (could be registration OR login redirect) |
| `/accounts` | 302 | Auth-gated |
| `/dashboard` | 302 | Auth-gated |
| `/api` | 404 | No API at this path |
| `/api/v1` | 404 | No API |
| `/health` | 404 | — |
| `/robots.txt` | **200** | MINE for sensitive paths |
| `/rails/info/properties` | 404 | Not in debug mode |
| `/admin` | **302** | Admin panel EXISTS — auth-gated |
| `/accounts/1` | **404** | Accounts do NOT use integer IDs |
| `/invoices/1` | **302** | `invoices/:id` route EXISTS, integer ID format, auth-gated → **IDOR CANDIDATE** |

### Analysis

**Highest priority — WP-L001 (/invoices/:id IDOR):**
- `/invoices/1` → 302 (route exists, redirected to login) — NOT 404
- Integer ID confirmed in URL path
- Once authenticated, test: does `/invoices/2`, `/invoices/3` return another customer's billing data?
- If invoice ownership isn't checked per-user = IDOR → billing data = TIER1

**WP-L002 status (self-registration):**
- `/register`, `/sign_up` → 404 (no Devise-style registration)
- `/users/sign_up` → 302 — NEED to follow this redirect
- Likely redirects to login (ISP portal = must be a real customer to have account)
- If redirect lands at an actual registration page → can create test account

**WP-L003 (Rails info) — CLOSED:**
- `/rails/info/properties` → 404 — not in debug mode

**WP-L004 (Auth):**
- Need to fetch `/user_sessions/new` body — does it offer Google OAuth or email/password only?
- Google OAuth via OmniAuth = check `redirect_uri` parameter

**WP-L005 (robots.txt mining) — NEW:**
- `/robots.txt` → 200 — fetch and mine for sensitive paths

**WP-L006 (Genesys Cloud integration) — NEW:**
- `apps.usw2.pure.cloud` in CSP `frame-ancestors` = portal embeds in Genesys CRM
- May have agent-specific endpoints (different auth flow for support agents vs end users)
- If iframe context has looser auth checks on some paths = auth bypass candidate

### Next Steps (Session 2)

1. Fetch `robots.txt` — mine for paths
2. Follow `/users/sign_up` redirect chain — open registration?
3. Fetch `/user_sessions/new` body — auth methods, OAuth hints
4. Mine JS bundle — real route list
5. Follow `/invoices/1` redirect to see exact URL (session 2 auth test)

See: `runbooks/PI-RUNBOOK-webpass-session2.md`

---

## Session 2 — 2026-06-21 (robots.txt + auth surface + JS bundle)

### Runbook
See: `runbooks/PI-RUNBOOK-webpass-session2.md`

### Output

(Paste Pi output here after running)

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| WP-L001 | IDOR on invoices | `work.webpass.net /invoices/:id` (integer IDs, route confirmed) | **ACTIVE** — needs auth account to test cross-user access |
| WP-L002 | Open registration | `work.webpass.net /users/sign_up` (302 destination unknown) | ACTIVE — follow redirect in session 2 |
| WP-L003 | Rails info disclosure | `/rails/info/properties` | ❌ CLOSED — 404, not in debug mode |
| WP-L004 | OAuth callback redirect | `/user_sessions/new` auth methods | ACTIVE — fetch body session 2 |
| WP-L005 | robots.txt path disclosure | `work.webpass.net/robots.txt` (200) | ACTIVE — fetch session 2 |
| WP-L006 | Genesys Cloud iframe bypass | `frame-ancestors apps.usw2.pure.cloud` | ACTIVE — investigate agent-facing paths |
