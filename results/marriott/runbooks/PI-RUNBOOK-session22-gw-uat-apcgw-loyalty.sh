#!/usr/bin/env bash
# PI-RUNBOOK-session22-gw-uat-apcgw-loyalty.sh
#
# SESSION 22 — gatewaydsapuat2 probe + apcgateway probe + loyalty chunk + _app deep-mine
#
# CONTEXT (Session 21 findings — COMPLETE):
#   A: 21 chunks downloaded. _app = 2,296,307B (2.3MB).
#   B: GraphQL endpoint NOT found in any browser JS — it's server-side proxied.
#      Key hostnames from _app:
#        gatewaydsapuat2.marriott.com     ← IN-SCOPE via gateway*.marriott.com
#        upl-gateway-green-uat-experiencelayer-uat2.ose-perf39-vxbyr.cloud.marriott.com
#        phoenix-bookdev1.ose-dev39-red.aws-use1.cloud.marriott.com  (OOS)
#        www.dev-cdn.marriott.com
#   C: _buildManifest rewrites: /mi/account/api/getNextProps → /api/getNextProps
#      (server-side proxy — backend URL never in browser JS)
#      App routes: /loyalty, /loyalty/createAccount/*, /loyalty/findReservationList, etc.
#   D: gateway-apc.marriott.com = uniform 404/261B on ALL paths — wrong host entirely.
#   E: auth-apc all non-/login paths = 000 (CDN firewall, no bypass)
#
# NEW IN-SCOPE TARGETS:
#   M024: gatewaydsapuat2.marriott.com (gateway*.marriott.com in_scope wildcard)
#   apcgateway.marriott.com (explicitly in scope, returned 503 in Session 1)
#
# SCOPE GUARD:
#   gatewaydsapuat2.marriott.com   = IN-SCOPE (gateway*.marriott.com)
#   apcgateway.marriott.com        = IN-SCOPE (explicit)
#   upl-gateway-green-uat-*.cloud.marriott.com = OUT-OF-SCOPE (*.marriott.com OOS)
#   phoenix-*.cloud.marriott.com   = OUT-OF-SCOPE
#
# PHASES:
#   A  — Probe gatewaydsapuat2.marriott.com (SAP DSP UAT gateway)
#   B  — Probe apcgateway.marriott.com (APC gateway — 503 in Session 1)
#   C  — Download + mine pages/loyalty-556d805f1e98d02b.js (main auth page = GraphQL calls)
#   D  — Deep-mine _app bundle: relative URL patterns, fetch() calls, graphql keyword
#   E  — Parse __NEXT_DATA__ from login HTML for publicRuntimeConfig API URL
#   F  — Decision gate

set -euo pipefail
OUTDIR=/tmp/s22
S21DIR=/tmp/s21
S18DIR=/tmp/s18
mkdir -p "$OUTDIR" "$OUTDIR/chunks"
exec > >(tee "$OUTDIR/session22.log") 2>&1

SCOPE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/config/marriott-scope.yaml"
SCOPE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/scripts/scope-check.sh"

scope_check() {
  local host="$1"
  result=$(SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$host" 2>&1) || true
  echo "scope[$host] => $result"
  if ! echo "$result" | grep -q "^IN-SCOPE"; then
    echo "SKIP: $host is OUT-OF-SCOPE."
    return 1
  fi
  return 0
}

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
ASSET_PREFIX="https://auth-apc.marriott.com/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static"

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE A — Probe gatewaydsapuat2.marriott.com (M024)"
echo "================================================================"

scope_check "gatewaydsapuat2.marriott.com" || { echo "SKIP Phase A"; }

GW_UAT="https://gatewaydsapuat2.marriott.com"

echo "--- A1: Root fingerprint ---"
curl -sv --max-time 20 \
  -A "$UA" \
  -D "$OUTDIR/gw-uat-root-headers.txt" \
  "${GW_UAT}/" \
  -o "$OUTDIR/gw-uat-root-body.html" 2>&1 | \
  grep -E "HTTP/|< [Ss]erver|< [Xx]-[Pp]owered|< [Cc]ontent|< [Ll]ocation|< [Ss]et-[Cc]ookie|< [Ww][Ww][Ww]" | head -15 || true
UAT_CODE=$(grep -m1 "^HTTP" "$OUTDIR/gw-uat-root-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
UAT_SIZE=$(wc -c < "$OUTDIR/gw-uat-root-body.html" 2>/dev/null || echo 0)
echo "A1: root: $UAT_CODE (${UAT_SIZE}B)"
head -c 500 "$OUTDIR/gw-uat-root-body.html" 2>/dev/null || true
sleep 2

echo ""
echo "--- A2: Standard API discovery paths ---"
for path in \
  "/actuator" "/actuator/health" "/actuator/env" "/actuator/mappings" \
  "/swagger-ui.html" "/swagger-ui/index.html" \
  "/v2/api-docs" "/v3/api-docs" "/openapi.json" \
  "/health" "/api/health" "/api/v1/health" \
  "/graphql" "/api/graphql" \
  "/sap/opu/odata/" "/sap/bc/" \
  "/api/v1" "/api/v2" \
  "/admin" "/console"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" "${GW_UAT}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  # Flag anything not matching the gatewaydsapdev2 uniform 404/261B pattern
  if [[ "$code" == "404" ]] && [[ "$size" == "261" ]]; then
    echo "A2 ${path}: ${code}/${size}B (uniform Akamai 404)"
  else
    echo "A2 ${path}: ${code}/${size}B *** DIFFERENTIAL ***"
  fi
  sleep 1
done

echo ""
echo "--- A3: OData / REST with JSON Accept header ---"
for path in \
  "/sap/opu/odata/sap/ZMM_HOTEL_SRV" \
  "/api/v1/properties" "/api/v1/rates" "/api/v1/reservations" \
  "/api/odata/v1/" \
  "/api/graphql"
do
  resp=$(curl -s -o "$OUTDIR/a3-$(echo "$path" | tr '/' '-').json" \
    -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" \
    -H "Accept: application/json" \
    "${GW_UAT}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "A3 ${path}: ${code}/${size}B"
  if [[ "$code" != "404" ]] && [[ "$code" != "000" ]] && [[ "$size" != "261" ]]; then
    head -c 400 "$OUTDIR/a3-$(echo "$path" | tr '/' '-').json" 2>/dev/null || true
  fi
  sleep 1
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B — Probe apcgateway.marriott.com"
echo "================================================================"

scope_check "apcgateway.marriott.com" || { echo "SKIP Phase B"; }

APCGW="https://apcgateway.marriott.com"

echo "--- B1: Root + fingerprint ---"
curl -sv --max-time 20 \
  -A "$UA" \
  -D "$OUTDIR/apcgw-root-headers.txt" \
  "${APCGW}/" \
  -o "$OUTDIR/apcgw-root-body.html" 2>&1 | \
  grep -E "HTTP/|< [Ss]erver|< [Xx]-[Pp]owered|< [Cc]ontent|< [Ll]ocation|< [Ss]et-[Cc]ookie" | head -15 || true
APCGW_CODE=$(grep -m1 "^HTTP" "$OUTDIR/apcgw-root-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
APCGW_SIZE=$(wc -c < "$OUTDIR/apcgw-root-body.html" 2>/dev/null || echo 0)
echo "B1: apcgateway root: $APCGW_CODE (${APCGW_SIZE}B)"
head -c 500 "$OUTDIR/apcgw-root-body.html" 2>/dev/null || true
sleep 2

echo ""
echo "--- B2: API paths on apcgateway ---"
for path in \
  "/graphql" "/api/graphql" "/phoenix/graphql" \
  "/actuator/health" "/actuator" \
  "/swagger-ui.html" "/v2/api-docs" "/v3/api-docs" \
  "/health" "/api/health" \
  "/api/v1" "/api/v2" "/api" \
  "/account" "/account/graphql" \
  "/loyalty" "/loyalty/graphql" \
  "/bonvoy" "/bonvoy/graphql"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" "${APCGW}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "B2 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- B3: POST /graphql introspection on apcgateway ---"
curl -sv --max-time 20 \
  -A "$UA" \
  -H "Content-Type: application/json" \
  -H "Origin: https://auth-apc.marriott.com" \
  -X POST \
  -d '{"query":"{__typename}"}' \
  -D "$OUTDIR/apcgw-graphql-headers.txt" \
  "${APCGW}/graphql" \
  -o "$OUTDIR/apcgw-graphql-body.json" 2>&1 | \
  grep -E "HTTP/|< [Cc]ontent|< [Ss]erver" | head -5 || true
APCGW_GQL_CODE=$(grep -m1 "^HTTP" "$OUTDIR/apcgw-graphql-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
APCGW_GQL_SIZE=$(wc -c < "$OUTDIR/apcgw-graphql-body.json" 2>/dev/null || echo 0)
echo "B3: POST /graphql: $APCGW_GQL_CODE (${APCGW_GQL_SIZE}B)"
head -c 400 "$OUTDIR/apcgw-graphql-body.json" 2>/dev/null || true
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — Download + mine loyalty page chunk (main auth page)"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase C"; }

echo "--- C1: Download loyalty page chunk ---"
LOYALTY_CHUNK="${ASSET_PREFIX}/chunks/pages/loyalty-556d805f1e98d02b.js"
curl -s --max-time 30 \
  -A "$UA" \
  -H "Referer: https://auth-apc.marriott.com/login" \
  "$LOYALTY_CHUNK" \
  -o "$OUTDIR/chunks/loyalty-556d805f1e98d02b.js" 2>/dev/null || true
LOYALTY_SIZE=$(wc -c < "$OUTDIR/chunks/loyalty-556d805f1e98d02b.js" 2>/dev/null || echo 0)
echo "C1: loyalty chunk: ${LOYALTY_SIZE}B"
sleep 2

echo ""
echo "--- C2: Download additional page chunks from buildManifest ---"
# Additional page chunks discovered from _buildManifest.js
for chunk_rel in \
  "chunks/pages/activate-cb939d7e47415c93.js" \
  "chunks/pages/changePassword-15db943840db6210.js" \
  "chunks/pages/enroll-45e6cbf4ebfdc5b0.js" \
  "chunks/pages/forgotPassword-86430ac73616cad1.js"
do
  fname=$(basename "$chunk_rel")
  dest="$OUTDIR/chunks/$fname"
  if [ -f "$dest" ] && [ "$(wc -c < "$dest")" -gt 200 ]; then
    echo "C2: $fname: cached"
    continue
  fi
  curl -s --max-time 20 \
    -A "$UA" \
    -H "Referer: https://auth-apc.marriott.com/login" \
    "${ASSET_PREFIX}/${chunk_rel}" \
    -o "$dest" 2>/dev/null || true
  size=$(wc -c < "$dest" 2>/dev/null || echo 0)
  if [ "$size" -gt 100 ]; then
    echo "C2: $fname: ${size}B OK"
  else
    echo "C2: $fname: FAILED (${size}B)"
    rm -f "$dest"
  fi
  sleep 1
done

echo ""
echo "--- C3: Mine all page chunks for GraphQL endpoint ---"
python3 - <<'PYEOF' 2>&1 | tee "$OUTDIR/page-chunk-mine.txt"
import re, os, glob

outdir = "/tmp/s22"
chunk_dirs = [f"{outdir}/chunks", "/tmp/s21/chunks", "/tmp/s18/apc-chunks"]

all_files = []
for d in chunk_dirs:
    all_files.extend(glob.glob(f"{d}/*.js"))
all_files = list(set(all_files))

print(f"Scanning {len(all_files)} files...\n")

results = {}
for fpath in sorted(all_files):
    fname = os.path.basename(fpath)
    try:
        js = open(fpath, errors='replace').read()
    except Exception as e:
        continue

    hits = []

    # 1. Relative URLs with /api/ containing graphql
    for m in re.finditer(r'["\x60](/api/[^\n"` ]{2,150})["\x60]', js):
        val = m.group(1)
        if 'graphql' in val.lower() or 'gql' in val.lower():
            hits.append(('relative_gql_path', val))

    # 2. Any string containing 'graphql' (not .graphql source files)
    for m in re.finditer(r'["\x60]([^"\x60\n]{0,80}graphql[^"\x60\n]{0,80})["\x60]', js, re.IGNORECASE):
        val = m.group(1)
        if not val.endswith('.graphql') and 'fragments/' not in val and 'queries/' not in val:
            if len(val) < 200:
                hits.append(('graphql_string', val))

    # 3. uri: with relative path
    for m in re.finditer(r'\buri\s*[=:]\s*["\x60](/[^\n"` ]{3,200})["\x60]', js, re.IGNORECASE):
        hits.append(('uri_relative', m.group(1)))

    # 4. fetch() calls
    for m in re.finditer(r'\bfetch\s*\(\s*["\x60](https?://[^\n"` ]{5,300}|/[^\n"` ]{3,200})["\x60]', js):
        val = m.group(1)
        if 'graphql' in val.lower() or 'api' in val.lower() or 'marriott' in val.lower():
            hits.append(('fetch_url', val))

    # 5. getNextProps / get-model — what are they?
    for kw in ['getNextProps', 'get-model', 'getNextData']:
        for m in re.finditer(r'.{0,100}' + re.escape(kw) + r'.{0,100}', js):
            ctx = m.group(0)
            if 'http' in ctx or 'fetch' in ctx.lower() or 'uri' in ctx.lower():
                hits.append(('proxy_route', ctx[:200]))
                break

    # 6. Apollo / GraphQL client configuration blocks
    for m in re.finditer(r'(?:ApolloClient|createApolloClient|makeClient|initApollo)\s*[({][^)}{]{5,600}', js, re.DOTALL):
        block = m.group(0)
        if len(block) < 700:
            hits.append(('apollo_block', block[:400]))

    if hits:
        results[fname] = hits

print(f"Files with hits: {len(results)}\n")
for fname, hits in sorted(results.items()):
    print(f"\n=== {fname} ({len(hits)} hits) ===")
    seen = set()
    for kind, val in hits:
        key = val[:80]
        if key not in seen:
            seen.add(key)
            print(f"  [{kind}] {val[:200]}")

if not results:
    print("No hits found. GraphQL endpoint is server-side only.")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — Parse __NEXT_DATA__ from login page for API config"
echo "================================================================"

LOGIN_HTML="/tmp/s19/apc-login.html"
if [ ! -f "$LOGIN_HTML" ] || [ "$(wc -c < "$LOGIN_HTML")" -lt 10000 ]; then
  echo "D0: Re-fetching login page..."
  scope_check "auth-apc.marriott.com" || { echo "SKIP Phase D"; }
  curl -s --max-time 20 \
    -A "$UA" \
    "https://auth-apc.marriott.com/login" \
    -o "$OUTDIR/apc-login.html" 2>/dev/null || true
  LOGIN_HTML="$OUTDIR/apc-login.html"
fi
echo "D0: Login HTML: $(wc -c < "$LOGIN_HTML")B"

echo ""
echo "--- D1: Extract full __NEXT_DATA__ JSON ---"
python3 - <<PYEOF 2>&1 | tee "$OUTDIR/next-data-parse.txt"
import re, json

html = open("$LOGIN_HTML", errors='replace').read()

# Extract __NEXT_DATA__ JSON
m = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(\{.*?\})\s*</script>', html, re.DOTALL)
if not m:
    # Try without id attribute constraint
    m = re.search(r'<script[^>]*type=["\']application/json["\'][^>]*>(\{.*?\})\s*</script>', html, re.DOTALL)

if not m:
    print("__NEXT_DATA__ not found in HTML")
    print("Searching for any JSON-like config blocks...")
    # Look for window.__CONFIG__ or similar
    for pat in [r'window\.__CONFIG__\s*=\s*(\{[^;]{20,2000}\})', r'window\.MI_CONFIG\s*=\s*(\{[^;]{20,2000}\})']:
        mc = re.search(pat, html)
        if mc:
            print(f"Found config: {mc.group(1)[:500]}")
else:
    raw = m.group(1)
    print(f"__NEXT_DATA__ found: {len(raw)}B")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}")
        print(f"Raw (first 500B): {raw[:500]}")
        data = None

    if data:
        # Check build ID
        print(f"buildId: {data.get('buildId', 'NOT FOUND')}")
        print(f"page: {data.get('page', 'NOT FOUND')}")

        # Check runtimeConfig
        rc = data.get('runtimeConfig', {})
        prc = rc.get('publicRuntimeConfig', rc)
        if prc:
            print(f"\npublicRuntimeConfig ({len(prc)} keys):")
            for k, v in sorted(prc.items()):
                if isinstance(v, str) and ('url' in k.lower() or 'api' in k.lower() or 'graphql' in k.lower() or 'endpoint' in k.lower() or 'host' in k.lower()):
                    print(f"  API KEY: {k} = {v}")
                elif isinstance(v, str) and len(v) < 200:
                    print(f"  {k} = {v}")

        # Check props/pageProps for API config
        props = data.get('props', {})
        page_props = props.get('pageProps', {})
        print(f"\npageProps keys: {list(page_props.keys())[:20]}")

        # Look for any URL-like values recursively
        def find_urls(obj, path='', depth=0):
            if depth > 5: return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    if isinstance(v, str) and ('http' in v or v.startswith('/api') or 'graphql' in v.lower()):
                        if 1 < len(v) < 300:
                            print(f"  URL found: {new_path} = {v}")
                    else:
                        find_urls(v, new_path, depth+1)
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:5]):
                    find_urls(item, f"{path}[{i}]", depth+1)

        print("\nURL-like values in __NEXT_DATA__:")
        find_urls(data)
PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — Parse full _buildManifest.js routes"
echo "================================================================"

BM_FILE="$S21DIR/chunks/_buildManifest.js"
if [ ! -f "$BM_FILE" ]; then
  BM_FILE="$OUTDIR/chunks/_buildManifest.js"
fi
echo "E0: buildManifest: $(wc -c < "$BM_FILE" 2>/dev/null || echo 0)B"

python3 - <<PYEOF 2>&1 | tee "$OUTDIR/buildmanifest-routes.txt"
import re

try:
    content = open("$BM_FILE").read()
    print(f"Build manifest size: {len(content)}B")

    # Extract all route paths — they appear as "/routeName": [...] in the manifest
    routes = re.findall(r'"(/[^"]+)":\s*\[', content)
    routes = [r for r in routes if not r.startswith('/static/') and r != '/__rewrites']

    print(f"Total routes: {len(routes)}")
    print("\n=== All App Routes ===")
    for r in sorted(routes):
        print(f"  {r}")

    # Extract all chunk filenames referenced
    chunk_files = re.findall(r'"(static/chunks/pages/[^"]+\.js)"', content)
    print(f"\n=== Page Chunk Files ({len(chunk_files)}) ===")
    for c in sorted(set(chunk_files)):
        fname = c.split('/')[-1]
        print(f"  {fname}")

    # Extract rewrite rules
    rewrites = re.findall(r'source:"([^"]+)",destination:"([^"]+)"', content)
    if rewrites:
        print(f"\n=== Next.js Rewrites ({len(rewrites)}) ===")
        for src, dst in rewrites:
            print(f"  {src} -> {dst}")

except Exception as e:
    print(f"Error: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE F — Decision Gate"
echo "================================================================"

python3 - <<'PYEOF' 2>&1
import os, re

outdir = "/tmp/s22"
print("=== SESSION 22 DECISION GATE ===\n")

# Phase A: gatewaydsapuat2
uat_body = open(f"{outdir}/gw-uat-root-body.html").read() if os.path.exists(f"{outdir}/gw-uat-root-body.html") else ""
uat_headers = open(f"{outdir}/gw-uat-root-headers.txt").read() if os.path.exists(f"{outdir}/gw-uat-root-headers.txt") else ""
uat_code = next((l.strip() for l in uat_headers.splitlines() if l.startswith("HTTP")), "000")
uat_size = len(uat_body)
print(f"A (gatewaydsapuat2): {uat_code} ({uat_size}B)")
if uat_size == 261 and '404' in uat_code:
    print("  → Same uniform Akamai 404 as gatewaydsapdev2 — WAF-locked")
elif '000' in uat_code:
    print("  → Timeout/unreachable — internal only")
else:
    print(f"  → DIFFERENTIAL! Body: {uat_body[:200]}")

# Check for differentials in A2 output
log = open(f"{outdir}/session22.log").read() if os.path.exists(f"{outdir}/session22.log") else ""
a2_diffs = re.findall(r'A2 ([^\n]+DIFFERENTIAL[^\n]*)', log)
if a2_diffs:
    print(f"  A2 DIFFERENTIALS FOUND: {len(a2_diffs)}")
    for d in a2_diffs[:5]:
        print(f"    {d.strip()}")

# Phase B: apcgateway
apcgw_body = open(f"{outdir}/apcgw-root-body.html").read() if os.path.exists(f"{outdir}/apcgw-root-body.html") else ""
apcgw_headers = open(f"{outdir}/apcgw-root-headers.txt").read() if os.path.exists(f"{outdir}/apcgw-root-headers.txt") else ""
apcgw_code = next((l.strip() for l in apcgw_headers.splitlines() if l.startswith("HTTP")), "000")
apcgw_size = len(apcgw_body)
print(f"\nB (apcgateway.marriott.com): {apcgw_code} ({apcgw_size}B)")
if apcgw_size > 0 and '404' not in apcgw_code and '000' not in apcgw_code:
    print(f"  LIVE: {apcgw_body[:300]}")
elif '000' in apcgw_code:
    print("  → Timeout (internal or firewalled)")
else:
    print("  → 404/error")

# Check B2 differentials
b2_lines = re.findall(r'B2 ([^\n]+)', log)
b2_diffs = [l for l in b2_lines if '000' not in l and '404' not in l and '261' not in l]
if b2_diffs:
    print(f"  B2 INTERESTING PATHS: {b2_diffs}")

# Phase C: page chunk mining
chunk_mine = open(f"{outdir}/page-chunk-mine.txt").read() if os.path.exists(f"{outdir}/page-chunk-mine.txt") else ""
if 'uri_relative' in chunk_mine or 'fetch_url' in chunk_mine or 'apollo_block' in chunk_mine:
    print(f"\nC (chunk mining): !!! HITS FOUND — check page-chunk-mine.txt !!!")
    for line in chunk_mine.split('\n'):
        if '[' in line and ']' in line:
            print(f"  {line.strip()}")
elif 'No hits found' in chunk_mine:
    print(f"\nC (chunk mining): No endpoint found — confirmed server-side proxy")
else:
    print(f"\nC (chunk mining): {len(chunk_mine)}B results — check manually")

# Phase D: __NEXT_DATA__
next_data = open(f"{outdir}/next-data-parse.txt").read() if os.path.exists(f"{outdir}/next-data-parse.txt") else ""
if 'API KEY' in next_data:
    print(f"\nD (__NEXT_DATA__): !!! API URL FOUND IN RUNTIME CONFIG !!!")
    for line in next_data.split('\n'):
        if 'API KEY' in line:
            print(f"  {line.strip()}")
elif 'URL found' in next_data:
    print(f"\nD (__NEXT_DATA__): URL-like values found — check next-data-parse.txt")
else:
    print(f"\nD (__NEXT_DATA__): No API URL in runtime config")

# Phase E: routes
routes_file = open(f"{outdir}/buildmanifest-routes.txt").read() if os.path.exists(f"{outdir}/buildmanifest-routes.txt") else ""
route_count = len(re.findall(r'^\s+/', routes_file, re.MULTILINE))
print(f"\nE (buildManifest): {route_count} routes extracted")

print("\n=== PRIORITY ACTIONS ===")
print("1. If gatewaydsapuat2 DIFFERENTIAL → probe that path for API access (actuator/swagger)")
print("2. If apcgateway LIVE + API paths → test GraphQL endpoint immediately")
print("3. If chunk mining finds endpoint → test unauthenticated IDOR")
print("4. If __NEXT_DATA__ has apiUrl → that IS the proxy target URL")
print("5. If all negative → CREATE Marriott Bonvoy test account + capture browser GraphQL traffic")
print("   OR → pivot to Saviynt M006 / homes-and-villas / M004 franchise JS bundle")

PYEOF

echo ""
echo "================================================================"
echo "SESSION 22 COMPLETE"
echo "Key files:"
echo "  $OUTDIR/gw-uat-root-body.html    — gatewaydsapuat2 response"
echo "  $OUTDIR/apcgw-root-body.html     — apcgateway response"
echo "  $OUTDIR/page-chunk-mine.txt      — chunk mining results"
echo "  $OUTDIR/next-data-parse.txt      — __NEXT_DATA__ analysis"
echo "  $OUTDIR/buildmanifest-routes.txt — full app route list"
echo "================================================================"
