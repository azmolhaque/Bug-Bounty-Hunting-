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

### Output

(Paste Pi output here after running)

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| WP-L001 | IDOR on billing/account | `work.webpass.net /accounts/:id`, `/invoices/:id` | PENDING — needs session 1 probe |
| WP-L002 | Open registration | `work.webpass.net /register` or `/sign_up` | PENDING |
| WP-L003 | Rails info disclosure | `work.webpass.net /rails/info/properties` | PENDING |
| WP-L004 | OAuth callback redirect | Auth flow on `work.webpass.net` | PENDING |
