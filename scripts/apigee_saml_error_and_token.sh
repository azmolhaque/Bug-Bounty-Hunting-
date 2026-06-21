#!/bin/bash
# Two objectives:
# 1. Fetch /saml_error to understand WHY our SAML assertions are rejected
# 2. Use passcode flow to get a real management API token (bypasses MFA)
# Run on Pi.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"

echo "============================================================"
echo " PART A: /saml_error — why are SAML assertions rejected?"
echo "============================================================"
/usr/bin/curl -skL --max-time 10 \
  -H "Cookie: SSO_JSESSIONID=064C3036406B47509A35F70180BE3B05" \
  "https://login.apigee.com/saml_error" \
  -o /tmp/saml_error_page.txt
echo "--- Text content of /saml_error ---"
# Strip HTML tags to get readable text
python3 -c "
import re, sys
html = open('/tmp/saml_error_page.txt').read()
text = re.sub(r'<[^>]+>', ' ', html)
text = re.sub(r'\s+', ' ', text).strip()
print(text[:2000])
" 2>/dev/null || /usr/bin/grep -oiE "[A-Za-z][^<]{10,200}" /tmp/saml_error_page.txt | head -20
echo

echo "============================================================"
echo " PART B: Passcode flow instructions (get real mgmt token)"
echo "============================================================"
echo
echo "MFA-enabled accounts cannot use Basic auth or password grant."
echo "Apigee supports a passcode flow instead:"
echo
echo "  Step 1: Open your browser and go to:"
echo "    https://login.apigee.com/passcode"
echo
echo "  Step 2: Log in with your Google account if prompted."
echo "          You will see a ONE-TIME PASSCODE on the page."
echo "          Copy it — it expires in a few minutes."
echo
echo "  Step 3: Run this command with that passcode:"
echo '    export PASSCODE="PASTE_YOUR_CODE_HERE"'
echo '    curl -sk -X POST "https://login.apigee.com/oauth/token" \'
echo '      -u "edgecli:edgeclisecret" \'
echo '      -d "grant_type=password&username=azmolhaque95@gmail.com&passcode=${PASSCODE}" \'
echo '      | python3 -m json.tool'
echo
echo "  If that still fails try:"
echo '    curl -sk -X POST "https://login.apigee.com/oauth/token" \'
echo '      -H "Content-Type: application/x-www-form-urlencoded" \'
echo '      -d "grant_type=password&username=azmolhaque95@gmail.com&passcode=${PASSCODE}&client_id=edgecli&client_secret=edgeclisecret" \'
echo '      | python3 -m json.tool'
echo
echo "  Step 4: Copy the access_token value, then run:"
echo '    export APIGEE_TOKEN="YOUR_TOKEN_HERE"'
echo '    bash scripts/apigee_mgmt_token_probe.sh'
echo
echo "  Alternatively: Open DevTools in browser while on console.apigee.com,"
echo "  look in Network tab for calls to api.enterprise.apigee.com,"
echo "  copy the Authorization: Bearer ... header value."
echo

# Also probe: can we register an IDP without auth? (long shot)
echo "============================================================"
echo " PART C: Can we register a SAML IDP without admin auth?"
echo "============================================================"
echo "--- PUT /identity-providers (attempt without auth) ---"
/usr/bin/curl -sk --max-time 10 \
  -X POST "https://login.apigee.com/identity-providers" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"type":"saml","name":"test","active":true,"config":{"metaDataLocation":"https://test.invalid/saml/metadata"}}' \
  -w "\nHTTP_%{http_code}" \
  -o /tmp/idp_register.txt
echo "HTTP: $(tail -1 /tmp/idp_register.txt)"
python3 -m json.tool /tmp/idp_register.txt 2>/dev/null || cat /tmp/idp_register.txt | head -c 300
echo

# Check if /saml/metadata reveals registered IDP entityIDs (sometimes embedded)
echo "--- IDP entity IDs from /saml/metadata ---"
/usr/bin/curl -sk --max-time 10 "https://login.apigee.com/saml/metadata" | \
  python3 -c "
import sys, re
data = sys.stdin.read()
# Look for IDPSSODescriptor or known IDP references
idps = re.findall(r'entityID=[\"'\'']([^\"'\'']+)[\"'\'']', data)
idps += re.findall(r'<saml:Issuer>([^<]+)</saml:Issuer>', data)
for x in set(idps): print('EntityID:', x)
" 2>/dev/null
echo
echo "Done."
