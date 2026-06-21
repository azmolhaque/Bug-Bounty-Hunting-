# Hunt Log — Nest (nest.com / nestlabs.com cluster)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER0 (accounts.nest.com auth) + TIER1 (home.nest.com + SDM + hardware)
**Started:** 2026-06-21
**Status:** RECON — Session 2 queued; Session 1 Phase B results recorded

---

## Scope (from config/scope.yaml)

**TIER0 — account auth:**
- accounts.nest.com
- accounts.ft.nest.com

**TIER1 — home + SDM API + hardware + admin:**
- home.nest.com, api.home.nest.com, beta.home.nest.com, alpha.home.nest.com
- fleet.home.nest.com, clips.home.nest.com
- home.ft.nest.com, api.home.ft.nest.com
- myaccount.nest.com, myaccount.ft.nest.com
- developer-api.nest.com, developer-api-ft.nest.com
- nssbridge.nest.com
- admin.store.nest.com, admin.store.ft.nest.com
- supportadmin.nestlabs.com

---

## Priority Hypotheses (pre-recon)

| Rank | Host(s) | Why | Bug class |
|------|---------|-----|-----------|
| 1 | `*.ft.nest.com` (field test) | Staging/test envs frequently have weaker auth or debug surface (cf. AppSheet gcp-staging) | Auth bypass / env differential |
| 2 | `admin.store.nest.com`, `admin.store.ft.nest.com` | Admin panels — if reachable pre-auth or weak auth | Admin access / IDOR |
| 3 | `supportadmin.nestlabs.com` | Support admin panel — different domain (nestlabs.com), possibly less hardened | Admin access |
| 4 | `accounts.nest.com` (TIER0) | Account auth host — CORS, OAuth redirect_uri, account enumeration | Auth flaws |
| 5 | `developer-api.nest.com`, `nssbridge.nest.com` | API surfaces — error differentials, IDOR | API auth / IDOR |
| 6 | `fleet.home.nest.com` | Fleet management — multi-device/multi-tenant | Cross-tenant IDOR |

**Pre-recon thesis:** The field-test (`ft`) variants and the admin panels are the highest-EV
unauthenticated targets. Map which are live + how they respond to an anonymous request first.

---

## Session 1 — 2026-06-21 (Pi recon, COMPLETE)

**Phase A** (DNS fingerprint of all 18 hosts): OUTPUT LOST — scope-check.sh received all
hosts as one quoted string argument, returned "SKIP (out of scope)" for each. Phase A needs
re-run with corrected loop syntax (`for H in host1 host2 ...` hardcoded, not `$HOSTS` variable).

**Phase B** (focused probe on ft + admin hosts): COMPLETE. Results:

| Host | Path | Status | Notes |
|------|------|--------|-------|
| `home.ft.nest.com` | / | **200** | ⚠️ Live content — highest priority |
| `home.ft.nest.com` | /health | 200 | Health endpoint live |
| `home.ft.nest.com` | /healthz | 302 | Redirect |
| `home.ft.nest.com` | /api | 401 | API present, auth required |
| `home.ft.nest.com` | /api/v1 | 401 | API v1 present |
| `home.ft.nest.com` | /robots.txt | 200 | Served |
| `api.home.ft.nest.com` | / | 401 | Auth required |
| `api.home.ft.nest.com` | /health | **200** | Health live |
| `api.home.ft.nest.com` | /robots.txt | 200 | Served |
| `api.home.ft.nest.com` | /api/* | 401 | All API paths auth-gated |
| `accounts.ft.nest.com` | /api/v1 | 401 | API exists (distinct from 404) |
| `admin.store.nest.com` | / | 403 | Auth-gated admin |
| `admin.store.nest.com` | /health | 200 | Health endpoint exposed |
| `admin.store.nest.com` | /healthz | 200 | Health endpoint exposed |
| `admin.store.ft.nest.com` | / | 403 | Auth-gated admin (ft) |
| `admin.store.ft.nest.com` | /health | 200 | Health endpoint exposed |
| `admin.store.ft.nest.com` | /healthz | 200 | Health endpoint exposed |
| `supportadmin.nestlabs.com` | / | 302 | Login redirect |
| `supportadmin.nestlabs.com` | all | 302 | Blanket redirect to login |
| `developer-api-ft.nest.com` | all | 000 | VPN-only, unreachable |
| `myaccount.ft.nest.com` | / | 200 | SPA shell |
| `myaccount.ft.nest.com` | all else | 403/404 | — |

**Key differential:** `home.ft.nest.com/` returns **200** while `home.nest.com/` returns auth
redirect. This mirrors the AppSheet staging pattern (gcp-staging returned 200 while prod redirected).
This is the highest-priority target for Session 2.

---

## Session 2 — 2026-06-21 (COMPLETE)

**Phase A — home.ft.nest.com root content:**
- Serves: `<!doctype html><!-- Build: 5.87.0.60073-20260429-1c89441-1 --><title>Log into the Nest app</title>`
- SPA catch-all confirmed: `/this-path-does-not-exist-zz9xyz` → 302 → / → 200 (21738 bytes).
  NST-L001 **CLOSED** — SPA login shell, not auth bypass.

**Phase B — CORS check + CSP extraction:**
- No ACAO reflection on `home.ft.nest.com/`.
- CSP notable entries:
  - `connect-src ... https://*.phoenix.nest.com:*` — **undocumented internal API host** ⚠️
  - `frame-src ... https://www5.dev.nestlabs.com` — **dev server in ft CSP** ⚠️
  - `img-src ... https://d2nk85tze0mjf3.cloudfront.net https://d2ybkvo7oee6te.cloudfront.net`
  - `script-src 'nonce-...' 'unsafe-eval' 'strict-dynamic' 'unsafe-inline'` — unsafe-eval present
  - `wss://*.dropcam.com:80 wss://*.dropcam.com` in connect-src

**Phase C — api.home.ft.nest.com auth body:**
- Unauthenticated → body: `provide authorization`. Simple bearer gate, not IAP. Real API.

**Phase D — supportadmin.nestlabs.com redirect:**
- **Google IAP protected.** `x-goog-iap-generated-response: true` confirmed.
- `redirect_uri=https://iap.googleapis.com/v1/oauth/clientIds/849799817816-...:handleRedirect`
- NST-L004 **CLOSED** — IAP-gated, inaccessible externally.

---

## Session 3 — 2026-06-21 (COMPLETE)

**Phase A — JS bundles extracted from home.ft.nest.com (not yet fetched):**
```
/js/main-30c9a58864910c0d57f2.js          ← main app logic — MINE FIRST
/js/_shared_/main-b15efb8dfb535b5c78cb.js  ← shared core — mine
/js/_vendors_/common-c9405a385b5ad51803c3.js ← vendor bundle — mine
/css/camera-9f4b09a95f34d4358b9c.js        ← camera module
/css/security-c7179311710ad7c2fc43.js       ← security module
```

**Phase B — CSP host DNS + scope check:**

| Host | DNS result | HTTP | Scope |
|------|-----------|------|-------|
| `www5.dev.nestlabs.com` | CNAME → `www5.web-dev.s1.nestlabs.com.` (35.190.38.33 GCP) | 301 → https://www5.web-dev.s1.nestlabs.com/ → **404 nginx/1.18.0** | ❌ OOS — only `supportadmin.nestlabs.com` listed; acquisition unlisted subdomain = TIER4 |
| `phoenix.nest.com` | Resolves (served HTTP) | **301 → `http://accounts.nest.com/login/`** (own CSP, nginx/1.18.0) | ❌ OOS — not in explicit Nest scope list; TIER4 default |
| `integration.store.nest.com` (phoenix.nest.com CSP) | not probed | n/a | ❌ OOS — not listed |

NST-L005, NST-L006: **CLOSED — out of scope.** Cannot probe any of these three hosts.

**Phase C — accounts.nest.com OIDC + CORS:** ⏳ OUTPUT CUT OFF — re-run in Session 4.

---

## Session 4 — 2026-06-21 (QUEUED)

Objectives:
1. **JS bundle mining** — `/js/main-30c9a58864910c0d57f2.js` + `/js/_shared_/main-b15efb8dfb535b5c78cb.js` from home.ft.nest.com
2. **accounts.nest.com TIER0** — OIDC discovery + CORS probe (cut off in S3)
3. **Unprobed in-scope TIER1 hosts** — `fleet.home.nest.com`, `clips.home.nest.com`, `nssbridge.nest.com`, `beta.home.nest.com`, `alpha.home.nest.com`

See runbooks/PI-RUNBOOK-nest-session4.md.

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| NST-L001 | Auth differential | `home.ft.nest.com` root=200 | ❌ CLOSED — SPA catch-all |
| NST-L002 | API surface | `api.home.ft.nest.com` (bearer gate) | ⏳ HOLD — needs Nest account |
| NST-L003 | Admin panel | `admin.store.*.nest.com` | ⏳ HOLD — health content probe in S4 |
| NST-L004 | Support admin | `supportadmin.nestlabs.com` | ❌ CLOSED — Google IAP |
| NST-L005 | Undocumented API | `phoenix.nest.com` (CSP connect-src) | ❌ CLOSED — out of scope (TIER4) |
| NST-L006 | Dev artifact | `www5.dev.nestlabs.com` (CSP frame-src) | ❌ CLOSED — out of scope (TIER4) |
| NST-L007 | JS bundle mining | `home.ft.nest.com` SPA bundles | ⏳ ACTIVE — Session 4 |
| NST-L008 | TIER0 OIDC/CORS | `accounts.nest.com` | ⏳ ACTIVE — Session 4 |
| NST-L009 | Fleet/multi-tenant | `fleet.home.nest.com` | ⏳ NEW — unprobed, Session 4 |
| NST-L010 | Video clips | `clips.home.nest.com` | ⏳ NEW — unprobed, Session 4 |
| NST-L011 | NSS Bridge | `nssbridge.nest.com` | ⏳ NEW — unprobed, Session 4 |
