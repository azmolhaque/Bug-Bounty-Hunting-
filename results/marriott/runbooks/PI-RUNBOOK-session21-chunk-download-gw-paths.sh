#!/usr/bin/env bash
# PI-RUNBOOK-session21-chunk-download-gw-paths.sh
#
# SESSION 21 — Full chunk download + GraphQL endpoint hunt
#
# CONTEXT (Session 20 findings):
#   A1: Build ID = wUhD83hKBJXisF6R7xbum (extracted from _buildManifest.js script src pattern)
#   A2: 28 chunks listed — but A3 download failed (heredoc+$() regex bug → empty PRIORITY_CHUNKS)
#   B:  Only scanned S18 chunks; graphql-chunk fragment paths ≠ HTTP endpoint URLs
#   C:  gateway-apc.marriott.com returns 404/261B uniform (Jetty error) for all 12 paths tested
#       → same Akamai WAF pattern as gatewaydsapdev2. Server live but wrong path prefix.
#   E:  UAT hosts (micmt.uat.marriott.com) → 403 + cdn-cache:HIT + Akamai ref #18 (IP ACL)
#       → IP-blocked by Akamai; residential Pi IP not in corporate allowlist. CLOSED.
#
# HYPOTHESIS: Apollo Client uri is in pages/_app or clientVendor chunk.
#   Once downloaded, grep for: 'uri:', 'endpoint:', 'graphqlUri', 'GRAPHQL_URL',
#   'bonvoy', 'gateway', 'marriott.com/graphql'.
#
# SCOPE GUARD:
#   extranetcloud.marriott.com = OUT-OF-SCOPE
#   gateway-apc.marriott.com   = IN-SCOPE (matches *gateway-apc.marriott.com wildcard)
#   auth-apc.marriott.com      = IN-SCOPE
#
# PHASES:
#   A  — Download ALL 28 auth-apc chunks directly (hardcoded URLs from S20 A2 output)
#   B  — Mine ALL downloaded chunks for GraphQL endpoint URL + Apollo config
#   C  — Download _buildManifest.js (Build ID known) + extract all app routes
#   D  — Probe gateway-apc.marriott.com with expanded path prefixes (/mi-account, /phoenix, /bonvoy)
#   E  — Try auth-apc.marriott.com post-login paths with Accept: application/json
#   F  — Decision gate

set -euo pipefail
OUTDIR=/tmp/s21
S18DIR=/tmp/s18
mkdir -p "$OUTDIR" "$OUTDIR/chunks"
exec > >(tee "$OUTDIR/session21.log") 2>&1

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

BASE_APC="https://auth-apc.marriott.com"
ASSET_PREFIX="${BASE_APC}/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static"
BUILD_ID="wUhD83hKBJXisF6R7xbum"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE A — Download all auth-apc chunks (hardcoded from S20 A2 output)"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase A"; exit 1; }

# All chunk URLs from Session 20 A2 output — exact filenames with hashes.
# Priority order: _app first (contains Apollo Client init), then vendors, then numbered.
declare -a CHUNKS=(
  "chunks/pages/_app-28a03d1bf69a65d4.js"
  "chunks/main-4c5e9f87a477047b.js"
  "chunks/webpack-c6fb6a1372caf896.js"
  "chunks/framework-4d641e3b1d0b3068.js"
  "chunks/clientVendor-5309c39c290319bc.js"
  "chunks/spClientVendor-957beb1d8c583658.js"
  "chunks/uiVendor-f5b89ff05de64d79.js"
  "chunks/13449-ba6af5295630255d.js"
  "chunks/36394-50c475f98cfa1d23.js"
  "chunks/69ea16bc-69275134c89eb3ee.js"
  "chunks/77945-045eb461b56c6fda.js"
  "chunks/95669-b456226df0addd98.js"
  "chunks/db9fdea0-e729a59f8b9d38dd.js"
  "chunks/brightcoveJs-309503af1f8ae32c.js"
  "chunks/dayJsVenor-cf4a2ef9e611d88f.js"
  "chunks/imageVendor-4333eaf7cbb2ef56.js"
  "chunks/reactCarousel-d8f6e9382720a670.js"
  "chunks/reactDayPicker-9965b6347f0a3268.js"
  "chunks/splideJs-d03d4f5a2a0ac5db.js"
  "chunks/polyfills-42372ed130431b0a.js"
  "chunks/pages/login-a583f1a8bc8e696c.js"
  "${BUILD_ID}/_buildManifest.js"
  "${BUILD_ID}/_ssgManifest.js"
)

echo "A0: Downloading ${#CHUNKS[@]} chunks..."
for chunk_rel in "${CHUNKS[@]}"; do
  fname=$(basename "$chunk_rel")
  dest="$OUTDIR/chunks/$fname"

  # Skip if already downloaded and substantial
  if [ -f "$dest" ] && [ "$(wc -c < "$dest")" -gt 100 ]; then
    echo "A: $fname: already cached ($(wc -c < "$dest")B)"
    continue
  fi

  url="${ASSET_PREFIX}/${chunk_rel}"
  curl -s --max-time 30 \
    -A "$UA" \
    -H "Referer: https://auth-apc.marriott.com/login" \
    "$url" \
    -o "$dest" 2>/dev/null || true

  size=$(wc -c < "$dest" 2>/dev/null || echo 0)
  if [ "$size" -gt 100 ]; then
    echo "A: $fname: ${size}B OK"
  else
    echo "A: $fname: ${size}B FAILED (404 or empty)"
    rm -f "$dest"
  fi
  sleep 2
done

echo ""
echo "A: Download summary:"
ls -la "$OUTDIR/chunks/" 2>/dev/null || echo "  (no files)"
TOTAL=$(ls "$OUTDIR/chunks/"*.js "$OUTDIR/chunks/"*.json 2>/dev/null | wc -l || echo 0)
echo "A: $TOTAL JS/JSON files downloaded"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B — Mine ALL downloaded chunks for GraphQL endpoint"
echo "================================================================"

python3 - <<'PYEOF' 2>&1 | tee "$OUTDIR/endpoint-hunt-s21.txt"
import re, os, glob

outdir = "/tmp/s21"
s18dir = "/tmp/s18/apc-chunks"

all_files = glob.glob(f"{outdir}/chunks/*.js") + glob.glob(f"{s18dir}/*.js")
all_files = list(set(all_files))

print(f"Scanning {len(all_files)} chunk files...\n")

found_endpoints = []
found_apollo    = []
found_hosts     = []
found_env_vars  = []
found_runtime   = []

for fpath in sorted(all_files):
    try:
        js = open(fpath, errors='replace').read()
        fname = os.path.basename(fpath)
        size = len(js)

        # 1. Direct GraphQL URL patterns (http/https with graphql path)
        patterns = [
            r'["\x60](https?://[^"` \n]{5,100}/(?:graphql|gql|phoenix)[^"` \n]{0,60})["\x60]',
            r'uri\s*[=:]\s*["\x60](https?://[^"` \n]{5,100})["\x60]',
            r'(?:graphqlUri|graphqlEndpoint|gqlEndpoint|GRAPHQL_URL|GQL_URL)\s*[=:]\s*["\x60]([^"` \n]{10,200})["\x60]',
            r'(?:apiUrl|API_URL|apiEndpoint|API_ENDPOINT|baseURL|BASE_URL)\s*[=:]\s*["\x60](https?://[^"` \n]{10,200})["\x60]',
        ]
        for pat in patterns:
            hits = re.findall(pat, js, re.IGNORECASE)
            for h in hits:
                if 'marriott' in h.lower() or 'bonvoy' in h.lower() or 'gateway' in h.lower():
                    found_endpoints.append((fname, h))

        # 2. Apollo Client initialization — look for ApolloClient constructor
        apollo_init = re.findall(
            r'new\s+(?:ApolloClient|InMemoryCache|ApolloLink)[^{]{0,200}\{([^}]{20,500})\}',
            js, re.DOTALL)
        for init in apollo_init:
            uri_m = re.search(r'uri\s*[=:]\s*["\x60]([^"` \n]{5,300})["\x60]', init)
            if uri_m:
                found_apollo.append((fname, f'ApolloClient uri: {uri_m.group(1)}'))

        # 3. HttpLink (common Apollo pattern)
        httplink = re.findall(
            r'(?:new\s+HttpLink|createHttpLink)\s*\(\s*\{([^}]{10,400})\}',
            js, re.DOTALL)
        for h in httplink:
            uri_m = re.search(r'uri\s*[=:]\s*["\x60]([^"` \n]{5,300})["\x60]', h)
            if uri_m:
                found_apollo.append((fname, f'HttpLink uri: {uri_m.group(1)}'))

        # 4. Any marriott/bonvoy hostname references
        hosts = re.findall(r'https?://([a-z0-9][a-z0-9.-]+\.(?:marriott|bonvoy)\.com)', js, re.IGNORECASE)
        for h in hosts:
            if h.lower() not in ('www.marriott.com', 'marriott.com', 'bonvoy.marriott.com'):
                found_hosts.append((fname, h.lower()))

        # 5. Environment variable references for GraphQL/API URL
        env_refs = re.findall(
            r'process\.env\.([A-Z_]{3,}(?:GRAPHQL|GQL|API|ENDPOINT|URL)[A-Z_]*)',
            js)
        for e in env_refs:
            found_env_vars.append((fname, e))

        # 6. Next.js publicRuntimeConfig / serverRuntimeConfig
        runtime = re.findall(
            r'(?:publicRuntimeConfig|runtimeConfig)\s*[=:]\s*\{([^}]{10,600})\}',
            js, re.DOTALL)
        for r_cfg in runtime:
            if 'api' in r_cfg.lower() or 'url' in r_cfg.lower() or 'graphql' in r_cfg.lower():
                found_runtime.append((fname, r_cfg[:400]))

        # 7. String literals containing gateway paths
        gw_patterns = re.findall(
            r'["\x60](/(?:mi-account|phoenix|bonvoy|apc|account)/(?:graphql|api|v\d)[^"` \n]{0,100})["\x60]',
            js, re.IGNORECASE)
        for g in gw_patterns:
            found_endpoints.append((fname, f'GW path: {g}'))

    except Exception as ex:
        print(f"  ERROR reading {os.path.basename(fpath)}: {ex}")

print(f"=== GraphQL/API Endpoint Candidates ({len(found_endpoints)}) ===")
seen = set()
for fname, ep in found_endpoints:
    key = ep[:120]
    if key not in seen:
        seen.add(key)
        print(f"  [{fname}] {ep[:150]}")

print(f"\n=== Apollo Client Config ({len(found_apollo)}) ===")
for fname, cfg in found_apollo:
    print(f"  [{fname}] {cfg}")

print(f"\n=== Marriott/Bonvoy Hostnames ({len(set(h for _,h in found_hosts))}) ===")
unique_hosts = {}
for fname, h in found_hosts:
    if h not in unique_hosts:
        unique_hosts[h] = fname
for h, fname in sorted(unique_hosts.items()):
    print(f"  {h} (in: {fname})")

print(f"\n=== Environment Variable References ({len(set(e for _,e in found_env_vars))}) ===")
for fname, e in sorted(set(found_env_vars)):
    print(f"  [{fname}] {e}")

print(f"\n=== Runtime Config Fragments ({len(found_runtime)}) ===")
for fname, cfg in found_runtime:
    print(f"  [{fname}] {cfg[:300]}")

PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — Download _buildManifest.js + extract all app routes"
echo "================================================================"

echo "--- C1: Download _buildManifest.js ---"
BUILD_MANIFEST_URL="${ASSET_PREFIX}/${BUILD_ID}/_buildManifest.js"
curl -s --max-time 20 \
  -A "$UA" \
  -H "Referer: https://auth-apc.marriott.com/login" \
  "$BUILD_MANIFEST_URL" \
  -o "$OUTDIR/buildManifest.js" 2>/dev/null || true
BM_SIZE=$(wc -c < "$OUTDIR/buildManifest.js" 2>/dev/null || echo 0)
echo "C1: _buildManifest.js: ${BM_SIZE}B"
head -c 2000 "$OUTDIR/buildManifest.js" 2>/dev/null || true

echo ""
echo "--- C2: Extract all app routes from _buildManifest.js ---"
python3 - <<'PYEOF' 2>&1
import re, json

try:
    content = open("/tmp/s21/buildManifest.js").read()
    size = len(content)
    print(f"Build manifest size: {size}B")

    if size < 50:
        print("File too small — manifest not downloaded or 404.")
        exit()

    # Next.js build manifest format:
    # self.__BUILD_MANIFEST = {"__rewrites":...,"sortedPages":["/login","/profile",...]}
    m = re.search(r'sortedPages["\s]*:\s*(\[[^\]]+\])', content)
    if m:
        pages_json = m.group(1)
        pages = json.loads(pages_json)
        print(f"\n=== All App Routes ({len(pages)}) ===")
        for p in sorted(pages):
            print(f"  {p}")
    else:
        print("\nsortedPages not found in manifest. Raw content:")
        print(content[:500])

    # Also extract any API routes
    api_routes = re.findall(r'"(/api/[^"]+)"', content)
    if api_routes:
        print(f"\n=== API Routes ({len(api_routes)}) ===")
        for r in sorted(set(api_routes)):
            print(f"  {r}")

except Exception as e:
    print(f"Error: {e}")
PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — Probe gateway-apc.marriott.com with expanded path prefixes"
echo "================================================================"

scope_check "gateway-apc.marriott.com" || { echo "SKIP Phase D"; }

GW_BASE="https://gateway-apc.marriott.com"

echo "--- D1: Expanded path prefix probe ---"
# S20 found uniform 404/261B for root + 12 common paths.
# Product name hints: "MI Account", "phoenix", "bonvoy", "apc"
# Try prefix + /graphql and prefix + /api
for path in \
  "/mi-account/graphql" \
  "/mi-account/api/graphql" \
  "/mi-account/v1/graphql" \
  "/phoenix/v1/graphql" \
  "/phoenix/api/graphql" \
  "/bonvoy/account/graphql" \
  "/bonvoy/graphql" \
  "/apc/graphql" \
  "/account-apc/graphql" \
  "/account/v1/graphql" \
  "/loyalty/graphql" \
  "/member/graphql" \
  "/v2/graphql" \
  "/v3/graphql" \
  "/gql" \
  "/query" \
  "/api/query" \
  "/graphql/v1" \
  "/graphql/phoenix" \
  "/mi-account" \
  "/mi-account/health" \
  "/actuator/health"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" \
    "${GW_BASE}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  # 261B = Jetty uniform 404 (no match). Anything else is interesting.
  if [[ "$size" != "261" ]] || [[ "$code" != "404" ]]; then
    echo "D1 ${path}: ${code}/${size}B *** DIFFERENTIAL — NOT UNIFORM 404 ***"
  else
    echo "D1 ${path}: ${code}/${size}B (uniform 404)"
  fi
  sleep 1
done

echo ""
echo "--- D2: POST /graphql with expanded paths + Authorization header ---"
# Some GraphQL gateways require auth token to even route the request.
# Try with a dummy Bearer token to see if behavior changes (not a bypass, just probing routing).
for path in "/graphql" "/mi-account/graphql" "/phoenix/v1/graphql"; do
  resp=$(curl -s -o "$OUTDIR/d2-post-$(echo "$path" | tr '/' '-').json" \
    -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "$UA" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer probe" \
    -H "Origin: https://auth-apc.marriott.com" \
    -X POST \
    -d '{"query":"{__typename}"}' \
    "${GW_BASE}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "D2 POST ${path} (with Bearer): ${code}/${size}B"
  if [[ "$size" != "261" ]] || [[ "$code" != "404" ]]; then
    head -c 300 "$OUTDIR/d2-post-$(echo "$path" | tr '/' '-').json" 2>/dev/null || true
  fi
  sleep 1
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — Probe auth-apc.marriott.com with Accept: application/json"
echo "================================================================"
# auth-apc returns 000 for all non-/login paths via curl.
# Test if Accept: application/json header changes routing (some CDN configs allow API paths through).
# Also test with X-Requested-With: XMLHttpRequest (AJAX header may have different routing).

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase E"; }

echo "--- E1: auth-apc.marriott.com — API paths with JSON Accept header ---"
for path in \
  "/api/graphql" \
  "/api/v1/graphql" \
  "/graphql" \
  "/api/me" \
  "/api/user" \
  "/api/profile" \
  "/api/account" \
  "/api/health" \
  "/mi-account/graphql"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" \
    -H "Accept: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    "${BASE_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "E1 auth-apc ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- E2: auth-apc.marriott.com — next.js API routes ---"
# Next.js API routes live at /api/* — check if any are reachable
for path in \
  "/api/auth/session" \
  "/api/auth/csrf" \
  "/_next/data/${BUILD_ID}/login.json" \
  "/_next/data/${BUILD_ID}/profile.json"
do
  url="${BASE_APC}${path}"
  # Substitute build ID in path
  url=$(echo "$url" | sed "s|BUILD_ID|${BUILD_ID}|g")
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
    -A "$UA" \
    "${BASE_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "E2 ${path}: ${code}/${size}B"
  sleep 1
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE F — Decision Gate"
echo "================================================================"

python3 - <<'PYEOF' 2>&1
import os, re, json, glob

outdir = "/tmp/s21"
print("=== SESSION 21 DECISION GATE ===\n")

# Phase A: chunks downloaded?
chunks = glob.glob(f"{outdir}/chunks/*.js")
print(f"A (chunk download): {len(chunks)} JS files downloaded")
key_chunks = ['_app', 'clientVendor', 'spClientVendor', 'main-', 'webpack-']
for k in key_chunks:
    found = [c for c in chunks if k in os.path.basename(c)]
    status = "OK" if found else "MISSING"
    print(f"  {k}: {status}")

# Phase B: endpoint found?
ep_file = f"{outdir}/endpoint-hunt-s21.txt"
ep_content = open(ep_file).read() if os.path.exists(ep_file) else ""
has_endpoint = bool(re.search(r'https?://[^\s]+\.marriott\.com[^\s]*(?:graphql|api)', ep_content, re.IGNORECASE))
has_apollo = bool(re.search(r'(?:ApolloClient|HttpLink)\s+uri', ep_content, re.IGNORECASE))
has_hosts = bool(re.search(r'Marriott/Bonvoy Hostnames \([^0]', ep_content))

if has_endpoint:
    print(f"\nB (endpoint hunt): !!! ENDPOINT FOUND — check endpoint-hunt-s21.txt !!!")
    # Print the actual endpoints
    for line in ep_content.split('\n'):
        if 'marriott.com' in line.lower() and ('graphql' in line.lower() or 'api' in line.lower()):
            print(f"  {line.strip()}")
elif has_apollo:
    print(f"\nB (endpoint hunt): Apollo config found — check for uri value")
elif has_hosts:
    print(f"\nB (endpoint hunt): Marriott hostnames found — check for API hostnames")
else:
    print(f"\nB (endpoint hunt): No endpoint URL found in chunks")

# Phase C: buildManifest routes?
bm = f"{outdir}/buildManifest.js"
if os.path.exists(bm) and os.path.getsize(bm) > 100:
    content = open(bm).read()
    m = re.search(r'sortedPages["\s]*:\s*(\[[^\]]+\])', content)
    if m:
        pages = json.loads(m.group(1))
        print(f"\nC (buildManifest): {len(pages)} routes found: {pages[:10]}")
    else:
        print(f"\nC (buildManifest): Downloaded ({os.path.getsize(bm)}B) but no sortedPages found")
else:
    print(f"\nC (buildManifest): Not downloaded or empty")

# Phase D: gateway-apc differentials?
# Scan D1 output from log for non-261B responses
log_file = f"{outdir}/session21.log"
if os.path.exists(log_file):
    log = open(log_file).read()
    differentials = re.findall(r'D1 ([^\n]+NOT UNIFORM)', log)
    if differentials:
        print(f"\nD (gateway-apc): !!! {len(differentials)} DIFFERENTIAL PATHS FOUND !!!")
        for d in differentials:
            print(f"  {d.strip()}")
    else:
        print(f"\nD (gateway-apc): All paths returned uniform 404/261B — no differentials")

print("\n=== PRIORITY ACTIONS ===")
print("1. If endpoint found in B → test unauthenticated IDOR immediately (GetProfileDetails)")
print("2. If gateway differential in D → probe that path with POST introspection")
print("3. If buildManifest routes include /api/* → probe those on auth-apc with JSON Accept")
print("4. If all negative → browser session capture: log in + DevTools Network tab → find GraphQL URL")
print("5. Fallback: M006 (Saviynt 500), M004 (franchisetx JS bundle), CT enum expansion")

PYEOF

echo ""
echo "================================================================"
echo "SESSION 21 COMPLETE"
echo "Key files:"
echo "  $OUTDIR/chunks/          — downloaded JS chunks"
echo "  $OUTDIR/endpoint-hunt-s21.txt — GraphQL endpoint search results"
echo "  $OUTDIR/buildManifest.js — Next.js route manifest"
echo "  $OUTDIR/session21.log    — full session log"
echo "================================================================"
