# Hunt Log — Nest (nest.com / nestlabs.com cluster)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER0 (accounts.nest.com auth) + TIER1 (home.nest.com + SDM + hardware)
**Started:** 2026-06-21
**Status:** RECON — Session 1 queued (Pi)

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

## Session 1 — 2026-06-21 (Pi recon, IN PROGRESS)

Queued: DNS resolution + HTTP fingerprint (status/server/title/redirect) for all 18 hosts,
plus focused path probe on admin + ft hosts. Results pending Pi execution.

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| (none yet) | — | — | Recon pending |
