#!/bin/bash
# Test all token revocation methods on login.apigee.com UAA.
# Context: DELETE /oauth/token/revoke/{JTI} returned HTTP 405 — method not supported.
# This script tests all documented UAA revocation variants to determine if:
#   a) any revocation method works at all
#   b) if a method revokes but token stays valid → actual bypass (CVE-2026-22723)
#   c) if no method works → "missing revocation" finding (Low/Info)
# Usage: export APIGEE_TOKEN="$(cat /tmp/apigee_token.txt)" && bash scripts/apigee_revoke_methods.sh
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

TOKEN="${APIGEE_TOKEN:-}"
UAA="https://login.apigee.com"
OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L004-revoke-methods.txt"

if [ -z "$TOKEN" ]; then
  echo "ERROR: export APIGEE_TOKEN=\"\$(cat /tmp/apigee_token.txt)\" first"
  exit 1
fi

# Extract JTI, access token, and refresh token from JWT
JTI=$(echo "$TOKEN" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
p = parts[1] + '=' * (4 - len(parts[1])%4)
d = json.loads(base64.b64decode(p))
print(d.get('jti',''))
" 2>/dev/null)

REFRESH_TOKEN="${APIGEE_REFRESH_TOKEN:-}"

echo "=== Token Revocation Method Survey ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "JTI: $JTI" | tee -a "$OUT"
echo | tee -a "$OUT"

# Pre-test: confirm token is valid
echo "--- [PRE] Token validity check ---" | tee -a "$OUT"
PRE=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -w "HTTP_%{http_code}" \
  "${UAA}/userinfo" -o /dev/null)
echo "Pre-test /userinfo: $PRE" | tee -a "$OUT"
if ! echo "$PRE" | grep -q "200"; then
  echo "Token already invalid. Get a fresh one and re-run." | tee -a "$OUT"
  exit 1
fi
echo | tee -a "$OUT"

# Method 1: DELETE /oauth/token/revoke/{JTI} — already known to return 405
echo "--- [M1] DELETE /oauth/token/revoke/{JTI} (known: 405) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE "${UAA}/oauth/token/revoke/${JTI}" \
  -w "\nHTTP_%{http_code}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Method 2: POST /oauth/token/revoke (RFC 7009 with token in body, edgecli client auth)
echo "--- [M2] POST /oauth/token/revoke (RFC 7009, token in body) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "edgecli:edgeclisecret" \
  -X POST "${UAA}/oauth/token/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${TOKEN}" \
  -w "\nHTTP_%{http_code}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Method 3: POST /oauth/token/revoke/{JTI}
echo "--- [M3] POST /oauth/token/revoke/{JTI} ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -X POST "${UAA}/oauth/token/revoke/${JTI}" \
  -w "\nHTTP_%{http_code}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Method 4: DELETE /token (some UAA variants)
echo "--- [M4] DELETE /token/{JTI} ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE "${UAA}/token/${JTI}" \
  -w "\nHTTP_%{http_code}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Method 5: POST /logout.do (session logout — different from token revocation)
echo "--- [M5] GET /logout.do (session/cookie logout, not token revocation) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/logout.do" | head -c 200 | tee -a "$OUT"
echo | tee -a "$OUT"

# After all revocation attempts, check if token is still valid
echo "--- [POST] Token validity after all revocation attempts ---" | tee -a "$OUT"
POST=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -w "HTTP_%{http_code}" \
  "${UAA}/userinfo" -o /dev/null)
echo "Post-all-methods /userinfo: $POST" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== VERDICT ===" | tee -a "$OUT"
if echo "$POST" | grep -q "200"; then
  echo "Token still valid after all revocation attempts." | tee -a "$OUT"
  echo "Determine which methods returned 2xx vs 4xx above:" | tee -a "$OUT"
  echo "  - If ALL methods returned 4xx → revocation is not supported (missing feature)" | tee -a "$OUT"
  echo "  - If ANY method returned 2xx (success) but token still works → BYPASS CONFIRMED" | tee -a "$OUT"
elif echo "$POST" | grep -q "401"; then
  echo "Token successfully revoked by one of the above methods." | tee -a "$OUT"
  echo "Identify which method returned 2xx and revocation worked correctly." | tee -a "$OUT"
fi
echo | tee -a "$OUT"
echo "Done. Results: $OUT"
