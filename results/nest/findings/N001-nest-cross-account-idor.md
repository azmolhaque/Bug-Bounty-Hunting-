# N001 — Nest cross-account IDOR/BOLA on home.nest.com API  [STATUS: CLOSED — NOT A BUG]

> RESULT (2026-06-29, IP 180.148.212.54): tested with a VALID account-A token
> (baseline A->A app_launch = HTTP 200), the cross-account reads are DENIED:
>   * POST /api/0.1/user/{B}/app_launch      -> 401 (A cannot read B's user/structures)
>   * POST {transport}/v5/subscribe user.{B} -> 403 (A cannot read B's bucket)
> Nest enforces per-object authorization on the user-keyed endpoints. No IDOR.
> Clean negative — do NOT file. (Tested with our own two accounts; baseline-200
> confirms the token was accepted, so the 401/403 are real authz denials, not auth
> failures.)
>
> Not exhaustively tested (would need account B's structure UUID + another capture):
>   /api/0.1/structure/{B}/entitlements, /structure/{B}/members, subscribe
>   structure.{B}, and the /v5/put write path. Same per-object authz model observed
>   on the user object; structure endpoints likely behave the same but UNVERIFIED.

- **Target:** `api.home.nest.com` / `home.nest.com` (Google VRP, Nest acquisition, in scope)
- **Class:** Broken Object-Level Authorization (IDOR/BOLA), cross-account
- **Severity (provisional):** High if read of another user's home data; Critical if
  `/v5/put` allows controlling another user's device. (CVSS TBD on confirmation.)
- **Status:** awaiting session3 result

## Summary (fill on confirmation)
The Nest web API authorizes <requests to user/structure/bucket objects> using the
identifier supplied in the request path/bucket rather than (or in addition to) the
caller's token identity, allowing account A to <read/modify> account B's
<home/structure/device> data without being a member of B's structure.

## Reproduction (fill verbatim from the run)
1. Obtain a Nest web session token for two accounts A and B (Google login at
   home.nest.com). A and B are not friends/members of each other's homes.
2. With A's token, call:  (PASTE the exact curl + the path that leaked)
   ```
   curl -s -H 'Authorization: Basic <A_TOKEN>' \
     'https://home.nest.com/api/0.1/user/<B_UID>/app_launch' --data '<APP_BODY>'
   ```
3. Observed: HTTP <code>, body contains B's <structure.<uuid> / where.<uuid> / ...>.
   Expected (secure): 401/403 — A is not a member of B's structure.

## Evidence checklist (per CLAUDE.md §9.8 — complete BEFORE submit)
- [ ] date/time + external IP (`curl ifconfig.me`) + tool versions
- [ ] verbatim copy-pasteable curl reproducing the leak
- [ ] verbatim HTTP response body (the actual bytes) showing B's data
- [ ] HTTP status + response size
- [ ] before/after differential (A→A 200 baseline vs A→B should-be-denied)
- [ ] terminal screenshot
- [ ] first-person human-voice writeup
- [ ] confirm B's data is genuinely B's (our own 2nd account), no third party

## Impact (fill on confirmation)
Any Nest user, given another user's numeric id (leaked/guessed within the id
space), can <read home structure/devices / control devices>. Home/family data and
physical device control are max-sensitivity.

## Remediation
Authorize every `/api/0.1/user/{id}`, `/api/0.1/structure/{id}`, and `/v5/*` bucket
operation against the caller's token identity + structure membership, not the
path/bucket id supplied by the client.

## Notes
- User ids are numeric but NOT adjacent-sequential (A=22529665, B=243212371) — note
  honestly that mass-enumeration is a large space, not trivial counting.
- `/v5/put` (write/device-control) NOT exercised in the read test; if read IDOR
  confirms, assess write only against our OWN account B, one benign field, before
  any Critical claim.
