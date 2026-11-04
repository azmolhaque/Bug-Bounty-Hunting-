# M025 — Homes & Villas: Unauthenticated `reservationDetails` GraphQL — guest PII exposure
# homes-and-villas.marriott.com/gateway/graphql
# Status: STRONG LEAD (confirmed unauth + schema); IDOR-vs-intended UNCONFIRMED — needs a real confirmation_id
# Discovered: 2026-06-27 (Sessions 36–45)

---

## One-line

The Homes & Villas GraphQL gateway (`/gateway/graphql`) is reachable **without
authentication** (only a CSRF token, which any client can fetch from the public
homepage). Its `reservationDetails(confirmation_id: ID!, last_name: String,
email: String)` query exposes a guest's **name, address, property, dates, party
size, status and amount paid**. `confirmation_id` is the **only required**
argument; `last_name`/`email` are optional. Whether `confirmation_id` alone
returns real data (→ IDOR) or the resolver enforces a `last_name`/`email` match
(→ intended "find my reservation" lookup) is **unconfirmed** and requires a real
confirmation number to settle.

---

## Researcher metadata

- Date: 2026-06-27
- Researcher IP: 180.148.212.54 (`curl ifconfig.me`)
- Tool: curl (Termux/Android + Raspberry Pi); GraphQL over HTTPS
- Endpoint IN-SCOPE: `homes-and-villas.marriott.com` (explicit scope entry)
- Account: none required (unauthenticated)

---

## What is CONFIRMED

1. **Endpoint + auth model.** `POST https://homes-and-villas.marriott.com/gateway/graphql`
   requires a CSRF token in header `x-hvmi-csrf-token`. The token is published in
   the public homepage (`#sourceid[data-source]` / `__NEXT_DATA__.csrfToken`) and
   is obtainable with no login. No session cookie (`hvmi_signInToken`) is required
   to execute `reservationDetails`.

2. **Connectivity (unauthenticated):**
   ```
   {"query":"{__typename}"} -> 200 {"data":{"__typename":"Query"}}
   ```

3. **`reservationDetails` schema (via error-oracle; introspection returns 500):**
   - Required arg: `confirmation_id: ID!`
   - Optional args: `last_name: String`, `email: String`
   - Return fields confirmed present:
     `guest_first_name`, `guest_last_name`,
     `guest_address { address, city, state, country }`,
     `property_name`, `property_address { street, city, state, zip_code, country, country_code }`,
     `check_in_date`, `check_out_date`, `number_of_guests`, `reservation_status`,
     `total`, `currency`

4. **Resolver executes unauthenticated.** With a SYNTHETIC confirmation_id, the
   resolver runs and returns the object with null fields (no match), proving no
   session/authorization is required to reach it:
   ```
   POST /gateway/graphql   (header x-hvmi-csrf-token only, no session cookie)
   {"query":"query R($c:ID!){reservationDetails(confirmation_id:$c){guest_first_name guest_last_name property_name check_in_date check_out_date number_of_guests total currency}}","variables":{"c":"ZZTEST-0000-0000-NOTREAL"}}

   -> HTTP 200
   {"data":{"reservationDetails":{"guest_first_name":null,"guest_last_name":null,"property_name":null,"check_in_date":null,"check_out_date":null,"number_of_guests":null,"total":null,"currency":null}}}
   ```

5. **No rate-limit/format constraint observed.** All synthetic id formats
   (8-digit numeric, 10-digit, alphanumeric, UUID, "1", "TEST") returned HTTP 200
   quickly. (We did NOT enumerate real confirmation numbers.)

---

## Client-controlled `isMyTrip` authorization flag (S46–S47)

The real resolver signature (extracted verbatim from the HnV JS bundle, S46):

```graphql
reservationDetails(
  confirmation_id: ID!,      # only required arg
  checkin_date: String,
  last_name: String,
  email: String,
  locale: String,
  switchToPlatformAPI: Boolean,
  isMyTrip: Boolean          # CLIENT-CONTROLLED auth-flow flag
)
```

One resolver serves two flows, switched by the client-supplied `isMyTrip`:
- `isMyTrip: true`  → authenticated "My Trips" (a logged-in user reads their own
  reservation, authorized by SESSION — no `last_name` needed)
- `isMyTrip: false` → public "find reservation" (guest supplies `last_name`/`checkin_date`)

**S47 result:** sending `isMyTrip: true` UNAUTHENTICATED returns **no auth/session
error** — identical null response to baseline. The privileged path does not reject
unauthenticated callers (the session check, if any, runs only after a reservation
is found). This is consistent with broken object-level authorization but is NOT
proof — a synthetic id returns null before any post-lookup `last_name`/session
check could fire. 10 flag variants (isMyTrip true/false, last_name, checkin_date,
email, switchToPlatformAPI, full-client) all returned byte-identical 224B nulls.

## Authenticated path + request-encryption (S48–S51) — observation, not a bug

Captured an authenticated HnV `/gateway/graphql` request (own Bonvoy session).
The sensitive operations (`F=[doBook,quote,getTotalReservationData,
reservationDetails,getProfileDetails,registerPromo]`) do NOT send plaintext
GraphQL — they send `{"encData":"U2FsdGVkX1..."}` (CryptoJS AES, Salted__).

Reverse-engineered scheme (from the JS):
```
realKey = AES.decrypt(page.data.encKey, x.gp)   # encKey per-page (__NEXT_DATA__,
                                                 #   itself Salted__); x.gp = static JS key
encData = AES.encrypt(graphql_json, realKey)
```
This is **client-side encryption with a client-reachable key** = security-through-
obscurity (the browser must hold the key). On its own this is informational/low,
NOT a fundable finding — it is only request obfuscation, not an auth control
(the real gate is the session cookie + CSRF token).

S49–S51 attempts to recover `x.gp` for offline testing FAILED: `encKey` is
per-session (so a stale capture can't be decrypted with a fresh page's key), and
`x.gp` is not a plain JS string literal (brute of 5,365 literals over the live
encKey produced no clean passphrase — it is assembled/computed). Without `x.gp`
we cannot craft `getProfileDetails` requests offline to test the **authenticated
profile IDOR** hypothesis. That avenue is therefore UNRESOLVED and parked.

NOTE: it is unknown whether `getProfileDetails` even takes an IDOR-able id
argument (it may derive the user from the session) — so the authenticated IDOR
is doubly speculative.

## What is NOT confirmed (the critical step)

Does `confirmation_id` **alone** (without a matching `last_name`/`email`) return a
real guest's data?

- `confirmation_id` is the only REQUIRED arg and `last_name`/`email` are OPTIONAL —
  which is suspicious (a properly-guarded lookup would make `last_name` required).
- BUT "optional in schema" ≠ "not enforced in the resolver." The resolver may
  return null unless `last_name` matches.
- A SYNTHETIC id returns null **either way**, so it cannot distinguish
  "guard works" from "fake id". **Only a real confirmation_id can settle this.**

| Outcome of `reservationDetails(confirmation_id:"<REAL>")` with NO last_name | Verdict |
|---|---|
| Returns the guest's real name/address | Second factor NOT enforced → **unauthenticated IDOR/BOLA** (High/Critical) |
| Returns null | Intended guarded "find my reservation" lookup → **not a vulnerability** |

---

## Reproducible PoC (structural — uses SYNTHETIC id, returns null)

```bash
# 1) fetch a CSRF token from the public homepage (no auth)
TOK=$(curl -s https://homes-and-villas.marriott.com/ \
  | grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' | head -1 \
  | sed -E 's/.*data-source="([^"]+)".*/\1/')

# 2) call the gateway UNAUTHENTICATED with only the CSRF token
curl -s 'https://homes-and-villas.marriott.com/gateway/graphql' \
  -H 'content-type: application/json' \
  -H "x-hvmi-csrf-token: $TOK" \
  --data '{"query":"query R($c:ID!){reservationDetails(confirmation_id:$c){guest_first_name guest_last_name guest_address{address city state country} property_name check_in_date check_out_date number_of_guests reservation_status total currency}}","variables":{"c":"<CONFIRMATION_ID>"}}'
```

To CONFIRM the vulnerability: replace `<CONFIRMATION_ID>` with a confirmation
number the tester legitimately holds (own booking) and observe whether real
data is returned with NO `last_name` argument.

---

## Impact (IF confirmation_id alone returns data)

Unauthenticated disclosure of any Homes & Villas guest's full name, address,
booked property, stay dates, party size, reservation status, and amount paid —
keyed only on a confirmation number. If confirmation numbers are low-entropy or
enumerable, this enables bulk PII harvesting. HnV is a multi-tenant rental
platform with 17 prior IDOR reports — this is the same bug class.

Provisional CVSS (IDOR case): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — 7.5 High
(→ Critical if mass-enumerable). NOT applicable if it is a guarded lookup.

---

## Submission gate (per CLAUDE.md §2/§3)

DO NOT submit until the critical step is confirmed with a real confirmation_id.
The presence of optional `last_name`/`email` args means an intended guarded
lookup is plausible; submitting unconfirmed risks an "intended behavior" /
"need PoC at the critical step" closure. Confirm with own-booking data only —
never enumerate or pull third-party confirmations.

---

## Evidence trail (local, not committed)

Sessions 36–45 transcripts in `/tmp/s3*`–`/tmp/s4*` (Pi/Termux). Runbooks:
`runbooks/PI-RUNBOOK-session3[6-9]-*.sh`, `runbooks/PI-RUNBOOK-session4[0-5]-*.sh`.
CSRF mechanism: header `x-hvmi-csrf-token`, token from `#sourceid[data-source]`,
Apollo client `uri:"/gateway/graphql"` (extracted from the HnV JS bundle).
