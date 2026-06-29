# Nest (home.nest.com) — Hunt Log

Program: Google VRP (acquisitions). Scope: `home.nest.com`, `api.home.nest.com`,
`accounts.nest.com` (authoritative — in acquisitions_domains_tiers.asciipb).
Method: browser-session interception (mitmproxy in Termux, non-root) of the
home.nest.com web app, then curl-based authenticated IDOR testing with our own
two test accounts. No third-party data touched.

## Why Nest (vs other Google acquisitions)
Marriott / Photomath / VirusTotal / Fitbit / Waze all came up hardened, dead,
migrated, or wound-down. Nest is the exception: `home.nest.com` is a LIVE,
actively-developed SPA (build 5.87.0.60073-20260429) with a real authenticated
multi-tenant API (`api.home.nest.com`) and a home/family-sharing model — and it
needs no APK patching (it's a website, interceptable on a non-rooted phone).

## Recon facts (confirmed)
- `home.nest.com` = live SPA; `api.home.nest.com` = real API, 401 unauth on every
  endpoint (`/structures`, `/devices`, `/api/0.1/user`, `/put`, `/subscribe`).
- Auth = `Authorization: Basic g.0.<JWT>` issued by nestauthproxyservice issue_jwt
  (Google OAuth -> Nest JWT). Tokens carry `sub: nest_id:nest-phoenix-prod:<uid>`,
  ~50 min `exp`.
- Object model = "buckets": `structure.<uuid>`, `user.<uid>`, `where.<uuid>`,
  `device.<id>`, `shared.<id>`, `quartz.<id>` (camera), `topaz.<id>` (smoke).
- Numeric user ids (NOT adjacent-sequential: A=22529665, B=243212371) — enumerable
  space, not trivially countable.

## Real endpoints captured (IDs in path/bucket)
- `POST /api/0.1/user/{userid}/app_launch`     (userid in path)
- `GET  /api/0.1/structure/{structureid}/entitlements`
- `GET  /api/0.1/structure/{structureid}/members`   <-- members IDOR candidate too
- `POST {transport czfeNN}/v5/subscribe`        (bucket read by object_key)
- `POST {transport}/v5/put`                     (bucket WRITE — device control; NOT tested yet)
- `GET  https://webapi.camera.home.nest.com/api/cameras.get_owned_and_member_of_with_properties`

## Test accounts (ours)
- A: uid 22529665, structure ba347612-73d3-11f1-81f1-12029c642f6d
- B: uid 243212371

## IDOR hypothesis under test (session3 runbook)
Does the server authorize on the path/bucket ID or only on the token's user?
With A's token, attempt to read B's `user/{B}/app_launch`,
`structure/{B}/entitlements`, and subscribe to B's buckets. A 200 returning B's
data from a non-member = cross-account BOLA.

## Status
- [x] Recon, interception, route map, both accounts' ids captured
- [ ] session3 IDOR verdict (PENDING operator run — see N001 draft)
- [ ] If confirmed: minimal PoC + report; consider read-only first, then assess
      /v5/put write (device control) on our OWN account B before any claim
- [ ] If denied: close as "Nest enforces per-object authz" (clean negative)

## Safety / ethics
Own two accounts only. Read-only (app_launch/subscribe are reads; /v5/put NOT
exercised). Tokens kept local, never committed. Proxy + user-CA removed after use.
