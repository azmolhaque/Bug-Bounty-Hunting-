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

### Results

- **`/users/sign_up` → 302 → `/user_sessions/new`** — no self-registration; redirects to login
- **Login page: email+password only** (Authlogic). No Google OAuth / OmniAuth buttons in HTML.
- **JS bundles**: `user_sessions-*.js` = 112 bytes (empty stub); `application-*.js` = 2.5 MB
- **Bundle routes extracted**: `/set_complete_personal_todo_from_non_dashboard_page`, `/set_complete_team_assignment_from_non_dashboard_page`, `/set_complete_user_assignment`, `/update_address_two/`, `/users/5`, `/workflows/`, `/alerts/`, `/increment_opp_reminder_date`, `/reminders/`, `/search`, `/spotlight_search`
- **App is a support CRM** — routes like `/increment_opp_reminder_date`, `/reminders/`, `/alerts/`, `/spotlight_search`, `/set_complete_*_assignment` confirm sales/support CRM. Users are Webpass support agents, not ISP customers.
- **Forgot password**: all variants → 404 (no password reset flow exposed)
- **New routes confirmed** (integer IDs, auth-gated): `/tickets`, `/contacts`, `/contacts/1`

---

## Session 3 — 2026-06-21 (Format bypass + AJAX + CSRF test)

### Results

- **Format bypass (`.json` extension)**: `/invoices/1.json`, `/accounts.json`, `/dashboard.json`, `/admin.json` → all **302** (auth filter is format-agnostic)
- **Format bypass (`Accept: application/json`)**: all auth-gated routes → still **302** (no JSON-specific bypass)
- **AJAX POST endpoints without CSRF**: 4x 404 (routes not found); `/increment_opp_reminder_date` → **422** (route exists — CSRF rejection, not auth redirect)
- **CSRF bypass test**: Fetched valid `_portal_session` cookie + CSRF token (unauthenticated), replayed POST to `/increment_opp_reminder_date` → **302 → `/user_sessions/new`** — auth `before_action` fires after CSRF passes
- **GET search/CRM endpoints with CSRF+session**: all → **302** (consistently auth-gated)

**The 422 on `/increment_opp_reminder_date` without CSRF was purely Rails CSRF protection (`protect_from_forgery :exception`). Once CSRF is satisfied, the `require_user` before_action fires and redirects to login. No auth bypass.**

## ⛔ WEBPASS CLOSED — 2026-06-21

All unauthenticated surface exhausted across 3 sessions:
- Real route table confirmed (not SPA)
- **Confirmed attack surface for authenticated testing**: `/invoices/:id`, `/contacts/:id`, `/users/:id`, `/tickets/:id` (all integer IDs, all auth-gated)
- **Fundamental blocker**: No self-registration. Portal is ISP employee support CRM (embedded in Genesys Cloud). Requires Webpass employee credentials. Cannot create test account from external.
- Format bypass: NOT possible
- AJAX auth bypass: NOT possible
- No password reset flow exposed

**PIVOT → prod.respond-software.com** (TIER1, Respond Software acquired by Google 2021, AI security detection platform, completely untested)

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
