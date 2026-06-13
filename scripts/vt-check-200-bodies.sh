#!/usr/bin/env bash
# Check the 200 response bodies from GCP IMDS root paths stored in VT's file corpus
# These two paths returned HTTP 200 from 169.254.169.254 and VT stored the bodies:
#   /computeMetadata/          sha256=b3cf675c75b8f96212e937c07ed3d681ed30d1d854ca7879dfb1c37d8362d4ce
#   / (root)                   sha256=9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7
# Run: VT_API_KEY=<key> bash scripts/vt-check-200-bodies.sh 2>&1 | tee ~/vt-200-bodies.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

echo "════════════════════════════════════════════════════════"
echo "VT-stored 200 response bodies from GCP IMDS root paths"
echo "════════════════════════════════════════════════════════"

BODIES=(
  "9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7:http://169.254.169.254/"
  "b3cf675c75b8f96212e937c07ed3d681ed30d1d854ca7879dfb1c37d8362d4ce:http://169.254.169.254/computeMetadata/"
)

for entry in "${BODIES[@]}"; do
  SHA="${entry%%:*}"
  URL="${entry#*:}"
  echo ""
  echo "═══ Source URL: ${URL}"
  echo "    SHA256: ${SHA}"

  # Check if the file object exists in VT
  FILE_OBJ=$(c "${BASE}/files/${SHA}")
  HTTP_STATUS=$(echo "$FILE_OBJ" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print('ERROR: ' + d['error'].get('code','') + ' ' + d['error'].get('message','')[:80])
else:
    attrs = d.get('data', {}).get('attributes', {})
    print('EXISTS')
    print('  type_tag:      ' + str(attrs.get('type_tag', 'N/A')))
    print('  type_description: ' + str(attrs.get('type_description', 'N/A')))
    print('  size:          ' + str(attrs.get('size', 'N/A')))
    names = attrs.get('names', [])
    print('  names:         ' + str(names[:3]))
    tags = attrs.get('tags', [])
    print('  tags:          ' + str(tags[:5]))
    # Any AV detections?
    results = attrs.get('last_analysis_stats', {})
    print('  av_stats:      ' + json.dumps(results))
" 2>/dev/null || echo "  parse error")

  echo "$HTTP_STATUS"

  # Try to download the actual file content via the download endpoint
  echo "  [*] Attempting download via /api/v3/files/${SHA}/download..."
  DL_CONTENT=$(curl -sk --connect-timeout 15 -A "$UA" \
    -H "x-apikey: ${VT_API_KEY}" \
    -w "\n__HTTP_CODE__:%{http_code}" \
    "${BASE}/files/${SHA}/download" 2>/dev/null)

  DL_CODE=$(echo "$DL_CONTENT" | tail -1 | cut -d: -f2)
  DL_BODY=$(echo "$DL_CONTENT" | head -c 2000)

  echo "  [*] Download HTTP status: ${DL_CODE}"

  if [ "$DL_CODE" = "200" ]; then
    echo "  [!!!] BODY DOWNLOADED. First 2000 chars:"
    echo "========== BEGIN BODY =========="
    echo "$DL_BODY"
    echo "=========== END BODY ==========="

    # Save to evidence
    echo "$DL_BODY" > "$OUT/imds-200-body-$(echo "$URL" | md5sum | cut -c1-8).html"
    echo "  [*] Saved to evidence/"

    # Check for sensitive patterns
    if echo "$DL_BODY" | grep -qiE "token|access_token|service.account|project.id|instance.id|hostname|network|internal|google"; then
      echo "  [!!!] SENSITIVE DATA DETECTED IN BODY"
      echo "$DL_BODY" | grep -iE "token|access_token|service.account|project.id|instance.id|hostname|network|internal|google" | head -20
    fi

  elif [ "$DL_CODE" = "403" ]; then
    echo "  [-] Download requires premium tier (403) — file exists but needs intelligence subscription"
    echo "      This means the IMDS response body IS in VT's corpus but gated behind premium"
    echo "      However, the sha256 itself is public information from the URL object"

  elif [ "$DL_CODE" = "404" ]; then
    echo "  [-] File not in download store (404) — sha256 recorded but raw content not stored"

  else
    echo "  [-] Unexpected status: ${DL_CODE}"
    echo "  Response: $(echo "$DL_CONTENT" | head -c 200)"
  fi
done

echo ""
echo "════════════════════════════════════════════════════════"
echo "Also checking: can we download the /latest/meta-data/ 404 body?"
echo "This was confirmed accessible earlier."
CONFIRMED_SHA="cea25c7405b91e51cedd0094aea65a6a3af294e70144812fc63dad9bb3922994"
echo "SHA256: ${CONFIRMED_SHA}"
DL=$(curl -sk --connect-timeout 15 -A "$UA" \
  -H "x-apikey: ${VT_API_KEY}" \
  -w "\n__HTTP_CODE__:%{http_code}" \
  "${BASE}/files/${CONFIRMED_SHA}/download" 2>/dev/null)
DL_CODE=$(echo "$DL" | tail -1 | cut -d: -f2)
DL_BODY=$(echo "$DL" | head -c 3000)
echo "Download status: ${DL_CODE}"
if [ "$DL_CODE" = "200" ]; then
  echo "Body (first 3000 chars):"
  echo "$DL_BODY"
  echo "$DL_BODY" > "$OUT/imds-404-body-confirmed.html"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "Summary: check above for SENSITIVE DATA DETECTED or download=200"
echo "If /computeMetadata/ 200 body contains paths/version info → escalate"
echo "If download=403 → bodies are in corpus but premium-gated (still proves storage)"
echo "════════════════════════════════════════════════════════"
