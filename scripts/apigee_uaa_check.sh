#!/bin/bash
# Step 1: UAA version fingerprint + SAML surface enumeration
# Determines if login.apigee.com is in CVE-2026-22734 range (v77.21.0 - v78.8.0)
# Run on Pi — no auth required
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L002-uaa-fingerprint.txt"

echo "=== UAA Version + SAML Surface Fingerprint ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- /info (version, prompts, SAML indicators) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 "https://login.apigee.com/info" \
  -o /tmp/uaa_info.txt
/usr/bin/cat /tmp/uaa_info.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# Extract version
VERSION=$(python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/uaa_info.txt'))
    v = d.get('app',{}).get('version','') or d.get('version','') or d.get('uaa_version','')
    print(v)
except: print('PARSE_ERROR')
" 2>/dev/null)
echo "Parsed version: $VERSION" | tee -a "$OUT"

# Check if in vulnerable range v77.21.0 - v78.8.0
python3 -c "
import sys
from packaging.version import Version
v = '$VERSION'
try:
    ver = Version(v)
    lo = Version('77.21.0')
    hi = Version('78.8.0')
    if lo <= ver <= hi:
        print('*** VULNERABLE: version', v, 'is in CVE-2026-22734 range v77.21.0-v78.8.0 ***')
        print('*** Run scripts/apigee_saml_bypass.sh IMMEDIATELY ***')
    elif ver < lo:
        print('Version', v, 'is BELOW vulnerable range — check manually')
    else:
        print('Version', v, 'is ABOVE vulnerable range — CVE-2026-22734 patched')
except Exception as e:
    print('Cannot compare version:', e, '— manual check required')
" 2>/dev/null | tee -a "$OUT"

echo | tee -a "$OUT"
echo "--- /saml/metadata (SAML SP registration) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -w "\nHTTP_%{http_code}" \
  -o /tmp/uaa_saml.txt \
  "https://login.apigee.com/saml/metadata"
echo "HTTP: $(tail -1 /tmp/uaa_saml.txt)" | tee -a "$OUT"
/usr/bin/head -c 800 /tmp/uaa_saml.txt | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- /identity-providers (IDP list — SAML providers registered?) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -H "Accept: application/json" \
  -D /tmp/uaa_idp_headers.txt \
  -w "\nHTTP_%{http_code}" \
  -o /tmp/uaa_idp.txt \
  "https://login.apigee.com/identity-providers"
echo "HTTP: $(tail -1 /tmp/uaa_idp.txt)" | tee -a "$OUT"
/usr/bin/head -c 600 /tmp/uaa_idp.txt | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- /saml/discovery (SAML discovery endpoint) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -w "HTTP_%{http_code}" \
  -o /tmp/uaa_disc.txt \
  "https://login.apigee.com/saml/discovery"
code=$(cat /tmp/uaa_disc.txt | tail -1)
echo "$code" | tee -a "$OUT"
/usr/bin/head -c 300 /tmp/uaa_disc.txt | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- Token revocation check (CVE-2026-22723: revoke endpoint exists?) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -w "HTTP_%{http_code}" \
  -o /tmp/uaa_revoke.txt \
  "https://login.apigee.com/oauth/token/revoke"
echo "HTTP: $(tail -1 /tmp/uaa_revoke.txt)" | tee -a "$OUT"
/usr/bin/head -c 200 /tmp/uaa_revoke.txt | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== SUMMARY ===" | tee -a "$OUT"
echo "UAA Version: $VERSION" | tee -a "$OUT"
echo "Next: check version range output above" | tee -a "$OUT"
echo "Results: $OUT"
