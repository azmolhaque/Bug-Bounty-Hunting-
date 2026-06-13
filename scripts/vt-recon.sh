#!/usr/bin/env bash
# VirusTotal — Phase 1+2: Recon + Attack Surface Mapping
# No API key needed for Phase 1. Phase 2 needs: VT_API_KEY=<key>
# Run on Pi: bash scripts/vt-recon.sh 2>&1 | tee ~/vt-recon-output.txt

set -euo pipefail
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com"
mkdir -p "$OUT/01-assets" "$OUT/02-surface" "$OUT/evidence"

c() { curl -sk --connect-timeout 12 -A "$UA" "$@"; }
ci() { curl -sI --connect-timeout 12 -A "$UA" "$@"; }

echo "══════════════════════════════════════════════════"
echo "PHASE 1 — Asset Discovery: virustotal.com"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== DNS resolution — known subdomains ==="
SUBS=(
  "www.virustotal.com"
  "api.virustotal.com"
  "developers.virustotal.com"
  "support.virustotal.com"
  "blog.virustotal.com"
  "enterprise.virustotal.com"
  "community.virustotal.com"
  "docs.virustotal.com"
  "static.virustotal.com"
  "cdn.virustotal.com"
  "assets.virustotal.com"
  "feeds.virustotal.com"
  "private.virustotal.com"
  "graph.virustotal.com"
  "premium.virustotal.com"
  "intelligence.virustotal.com"
  "hunting.virustotal.com"
  "retrohunt.virustotal.com"
  "upload.virustotal.com"
  "files.virustotal.com"
  "status.virustotal.com"
  "admin.virustotal.com"
  "beta.virustotal.com"
  "staging.virustotal.com"
  "dev.virustotal.com"
  "test.virustotal.com"
  "old.virustotal.com"
  "legacy.virustotal.com"
  "auth.virustotal.com"
  "login.virustotal.com"
  "accounts.virustotal.com"
  "api2.virustotal.com"
  "api3.virustotal.com"
  "v3.virustotal.com"
  "v2.virustotal.com"
  "gti.virustotal.com"
  "gtidocs.virustotal.com"
  "virustotal-plugins.com"
  "www.virustotal-plugins.com"
  "api.virustotal-plugins.com"
)

echo "Host,IP,CNAME" > "$OUT/01-assets/dns.csv"
for sub in "${SUBS[@]}"; do
  ip=$(dig +short "$sub" A 2>/dev/null | head -1)
  cname=$(dig +short "$sub" CNAME 2>/dev/null | head -1)
  if [ -n "$ip" ] || [ -n "$cname" ]; then
    echo "LIVE  ${sub}  ${ip}  ${cname}"
    echo "${sub},${ip},${cname}" >> "$OUT/01-assets/dns.csv"
  fi
done

echo ""
echo "=== HTTP probe — live hosts ==="
echo "Status,Host,Server,Title" > "$OUT/01-assets/http-probe.csv"
for sub in "${SUBS[@]}"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "https://${sub}/")
  if [ "$code" != "000" ]; then
    server=$(ci "https://${sub}/" | grep -i "^server:" | head -1 | tr -d '\r')
    echo "${code}  ${sub}  ${server}"
    echo "${code},${sub},${server}" >> "$OUT/01-assets/http-probe.csv"
  fi
done

echo ""
echo "=== Wayback Machine — unique path patterns ==="
echo "(querying web.archive.org CDX API for virustotal.com endpoints)"
curl -sk --connect-timeout 15 \
  "http://web.archive.org/cdx/search/cdx?url=virustotal.com/*&output=text&fl=original&collapse=urlkey&limit=200&from=2023&filter=statuscode:200" \
  2>/dev/null | grep -v "\.png\|\.jpg\|\.gif\|\.css\|\.woff\|\.ico" | \
  sort -u | head -80 | tee "$OUT/01-assets/wayback-paths.txt"

echo ""
echo "══════════════════════════════════════════════════"
echo "PHASE 2 — Attack Surface Mapping"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== Main site: www.virustotal.com ==="
ci "https://www.virustotal.com/" | tee "$OUT/02-surface/main-headers.txt" | head -30
echo "--- body snippet ---"
c "https://www.virustotal.com/" | head -c 2000 > "$OUT/02-surface/main-body.html"
head -c 500 "$OUT/02-surface/main-body.html"

echo ""
echo "=== gtidocs.virustotal.com (GTI docs) ==="
ci "https://gtidocs.virustotal.com/" | tee "$OUT/02-surface/gtidocs-headers.txt" | head -20
c "https://gtidocs.virustotal.com/" | head -c 500

echo ""
echo "=== virustotal-plugins.com ==="
ci "https://virustotal-plugins.com/" | head -20
c "https://virustotal-plugins.com/" | head -c 500

echo ""
echo "══════════════════════════════════════════════════"
echo "PHASE 2B — API v3 Endpoint Surface Map"
echo "══════════════════════════════════════════════════"

BASE="https://www.virustotal.com/api/v3"

echo ""
echo "=== Unauthenticated API endpoint discovery ==="
ENDPOINTS=(
  "/"
  "/files"
  "/urls"
  "/domains"
  "/ip_addresses"
  "/analyses"
  "/analyses/test_id"
  "/search"
  "/comments"
  "/votes"
  "/graphs"
  "/graphs/test_id"
  "/collections"
  "/collections/test_id"
  "/feeds"
  "/feeds/files"
  "/hunting_rulesets"
  "/hunting_rulesets/test_id"
  "/retrohunt_jobs"
  "/retrohunt_jobs/test_id"
  "/intelligence/search"
  "/intelligence/file_feedback"
  "/private"
  "/private/files"
  "/private/urls"
  "/users"
  "/users/me"
  "/users/test_id"
  "/groups"
  "/groups/test_id"
  "/monitors"
  "/monitors/test_id"
  "/ioc_stream"
  "/metadata"
  "/ip_addresses/8.8.8.8"
  "/domains/google.com"
)

for ep in "${ENDPOINTS[@]}"; do
  resp=$(curl -sk --connect-timeout 8 -A "$UA" "${BASE}${ep}")
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "${BASE}${ep}")
  # Extract error message if present
  msg=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','') + ' ' + d.get('error',{}).get('message','')[:60])" 2>/dev/null || echo "${resp:0:60}")
  echo "${code}  ${ep}  ${msg}"
done | tee "$OUT/02-surface/api-v3-unauth.txt"

echo ""
echo "=== Legacy API v2 still alive? ==="
for ep in "/vtapi/v2/url/report" "/vtapi/v2/file/report" "/vtapi/v2/url/scan"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://www.virustotal.com${ep}")
  echo "${code}  ${ep}"
done

echo ""
echo "=== Alternate API base URLs ==="
for base in "https://api.virustotal.com" "https://www.virustotal.com/api" "https://www.virustotal.com/api/v2"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "${base}/")
  echo "${code}  ${base}"
done

echo ""
echo "=== GraphQL endpoint probe ==="
for ep in "/graphql" "/api/graphql" "/gql" "/api/v3/graphql"; do
  resp=$(c -X POST "https://www.virustotal.com${ep}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}')
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
    -X POST "https://www.virustotal.com${ep}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}')
  echo "${code}  ${ep}  ${resp:0:80}"
done

echo ""
echo "=== CORS on API — does it trust arbitrary origins? ==="
resp=$(curl -sk --connect-timeout 8 -A "$UA" \
  -H "Origin: https://evil.com" \
  -H "x-apikey: FAKE_KEY_CORS_TEST" \
  -I "${BASE}/files/eicar_test_md5")
echo "$resp" | grep -i "access-control\|vary\|cors"

echo ""
echo "=== Authentication surface ==="
echo "--- /api/v3/users/me (no key) ---"
c "${BASE}/users/me" | python3 -m json.tool 2>/dev/null | head -15

echo ""
echo "--- OAuth / token endpoints ---"
for ep in "/oauth2/token" "/oauth/token" "/auth/token" "/auth/login" "/.well-known/openid-configuration"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "https://www.virustotal.com${ep}")
  echo "${code}  ${ep}"
done

echo ""
echo "=== JS bundle extraction (look for API keys, internal endpoints) ==="
JSURLS=$(c "https://www.virustotal.com/" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//')
echo "Found JS bundles:" && echo "$JSURLS" | head -5
FIRST_JS=$(echo "$JSURLS" | head -1)
if [ -n "$FIRST_JS" ]; then
  BUNDLE_URL="https://www.virustotal.com${FIRST_JS}"
  echo "Scanning ${BUNDLE_URL:0:80}..."
  c "$BUNDLE_URL" | grep -oEi '(apikey|api_key|x-apikey|gcp|metadata|internal|private|secret)[^"'"'"']{0,5}["'"'"'][^"'"'"']{10,80}["'"'"']' | sort -u | head -20
  c "$BUNDLE_URL" | grep -oE 'https?://[a-z0-9._-]+\.(virustotal|google)\.com[^"'"'"' ]{0,80}' | sort -u | head -20
fi

echo ""
echo "=== Web routes probe (SPA route enumeration) ==="
for path in \
  "/gui" "/gui/file" "/gui/home" "/gui/search" \
  "/gui/intelligence" "/gui/hunting" "/gui/retrohunt" \
  "/gui/graph" "/gui/collections" "/gui/feeds" \
  "/gui/admin" "/admin" "/internal" \
  "/swagger.json" "/openapi.json" "/api-docs" \
  "/.well-known/security.txt" "/security.txt"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "https://www.virustotal.com${path}")
  echo "${code}  ${path}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "PHASE 2C — Upload + Scan Mechanism"
echo "══════════════════════════════════════════════════"

echo ""
echo "=== File upload endpoint (no auth) ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -X POST "${BASE}/files" \
  -F "file=@/dev/null;type=text/plain")
echo "POST /api/v3/files (no key): ${code}"

echo ""
echo "=== URL submission endpoint (no auth) ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -X POST "${BASE}/urls" \
  -d "url=https://example.com")
resp=$(c -X POST "${BASE}/urls" -d "url=https://example.com")
echo "POST /api/v3/urls (no key): ${code} | ${resp:0:100}"

echo ""
echo "=== Large file upload URL (no auth) ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  "${BASE}/files/upload_url")
resp=$(c "${BASE}/files/upload_url")
echo "GET /api/v3/files/upload_url (no key): ${code} | ${resp:0:100}"

echo ""
echo "Done. Results in $OUT/"
echo "Next step: VT_API_KEY=<key> bash scripts/vt-attack.sh"
