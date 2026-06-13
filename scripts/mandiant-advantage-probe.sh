#!/usr/bin/env bash
# mandiant-advantage-probe.sh
# Deep probe of advantage.mandiant.com and its backend APIs discovered in CSP.
#
# CSP reveals real backends:
#   advantage-api.mandiant.com      — primary API backend
#   api.intelligence.mandiant.com   — threat intelligence API
#   api.intelligence.fireeye.com    — legacy FireEye intel API
#
# Run: bash scripts/mandiant-advantage-probe.sh
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

OUT="results/mandiant/advantage"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[FOUND]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

echo ""
echo -e "${CYAN}═══ Mandiant Advantage Deep Probe ═══${NC}"
echo ""

# ── 1. Verify advantage.mandiant.com API 200s are JSON or SPA shell ──────────
info "1. Checking if advantage.mandiant.com API paths return JSON or SPA HTML..."
echo ""
for EP in /api/me /api/users /api/v1 /api/v4 /graphql /v4/indicator /v4/actor; do
  RESP=$(curl -sk -w "\n__CODE__:%{http_code}\n__CT__:%{content_type}" \
    --max-time 10 --max-redirs 3 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    "https://advantage.mandiant.com${EP}" 2>/dev/null)
  CODE=$(echo "$RESP" | grep "__CODE__:" | cut -d: -f2)
  CT=$(echo "$RESP" | grep "__CT__:" | cut -d: -f2)
  # First 150 chars of body
  BODY=$(echo "$RESP" | grep -v "^__" | head -c 150 | tr -d '\n')

  if echo "$CT" | grep -q "application/json\|application/graphql"; then
    hit "REAL API: ${EP} → HTTP $CODE | $CT"
    hit "Body: $BODY"
    echo "advantage_real_api=$EP status=$CODE body=${BODY:0:100}" >> "$OUT/findings.txt"
  elif echo "$BODY" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    hit "JSON RESPONSE (no JSON content-type): $EP → HTTP $CODE"
    hit "Body: $BODY"
    echo "advantage_json_body=$EP status=$CODE body=${BODY:0:100}" >> "$OUT/findings.txt"
  else
    # SPA shell — check if it's actually HTML
    IS_HTML=$(echo "$BODY" | grep -c "<!doctype\|<html\|<head\|<title" || true)
    if [ "$IS_HTML" -gt 0 ]; then
      ok "SPA shell (HTML): $EP → $CODE | ${BODY:0:60}"
    else
      warn "Unknown response: $EP → HTTP $CODE | CT: $CT | ${BODY:0:80}"
    fi
  fi
done
echo ""

# ── 2. Probe advantage-api.mandiant.com (real backend) ───────────────────────
info "2. advantage-api.mandiant.com — direct backend API probes"
echo ""
for EP in / /api /api/v1 /api/v4 /graphql /api/me /api/user \
          /api/users /api/auth /api/collections /api/indicators \
          /api/actors /api/reports /api/vulnerabilities \
          /api/v1/user /api/v1/me /api/v4/indicator \
          /health /status /version /api/health; do
  RESP=$(curl -sk -w "\n__CODE__:%{http_code}\n__CT__:%{content_type}" \
    --max-time 10 --max-redirs 3 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    -H "Origin: https://advantage.mandiant.com" \
    -H "Referer: https://advantage.mandiant.com/" \
    "https://advantage-api.mandiant.com${EP}" 2>/dev/null)
  CODE=$(echo "$RESP" | grep "__CODE__:" | cut -d: -f2)
  CT=$(echo "$RESP" | grep "__CT__:" | cut -d: -f2)
  BODY=$(echo "$RESP" | grep -v "^__" | head -c 200 | tr -d '\n')

  echo "  ${EP} → HTTP $CODE | ${CT:0:30} | ${BODY:0:100}"

  # Flag anything that's not 401/403/404
  if [ "$CODE" = "200" ]; then
    hit "HTTP 200 on advantage-api: $EP"
    echo "advantage_api_200=$EP ct=$CT body=${BODY}" >> "$OUT/findings.txt"
    # Save full response
    curl -sk --max-time 10 -H "User-Agent: $UA" -H "Accept: application/json" \
      -H "Origin: https://advantage.mandiant.com" \
      "https://advantage-api.mandiant.com${EP}" 2>/dev/null > "$OUT/advantage-api-${EP//\//_}.json"
  fi
done
echo ""

# ── 3. Probe api.intelligence.mandiant.com (Threat Intel API) ────────────────
info "3. api.intelligence.mandiant.com — threat intelligence API (no auth?)"
echo ""
for EP in / /v4/indicator /v4/actor /v4/malware /v4/vulnerability \
          /v4/report /v4/attack-pattern /v4/course-of-action \
          /v4/identity /v4/infrastructure /v4/intrusion-set \
          /v4/tool /v4/malware-family /v4/threat-actor \
          /v1/indicator /v1/actor /v1/report \
          /api /api/v4 /health; do
  RESP=$(curl -sk -w "\n__CODE__:%{http_code}\n__CT__:%{content_type}" \
    --max-time 10 --max-redirs 3 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    "https://api.intelligence.mandiant.com${EP}" 2>/dev/null)
  CODE=$(echo "$RESP" | grep "__CODE__:" | cut -d: -f2)
  CT=$(echo "$RESP" | grep "__CT__:" | cut -d: -f2)
  BODY=$(echo "$RESP" | grep -v "^__" | head -c 200 | tr -d '\n')

  echo "  ${EP} → HTTP $CODE | ${BODY:0:100}"

  if [ "$CODE" = "200" ]; then
    hit "UNAUTHENTICATED ACCESS: api.intelligence.mandiant.com${EP}"
    echo "intel_api_200=$EP body=${BODY}" >> "$OUT/findings.txt"
    curl -sk --max-time 10 -H "User-Agent: $UA" -H "Accept: application/json" \
      "https://api.intelligence.mandiant.com${EP}" 2>/dev/null > "$OUT/intel-api-${EP//\//_}.json"
  fi
done
echo ""

# ── 4. Probe api.intelligence.fireeye.com (legacy FireEye API) ──────────────
info "4. api.intelligence.fireeye.com — legacy FireEye intelligence API"
echo ""
for EP in / /v4/indicator /v4/actor /v1/report /health /api; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    -H "User-Agent: $UA" -H "Accept: application/json" \
    "https://api.intelligence.fireeye.com${EP}" 2>/dev/null)
  echo "  ${EP} → HTTP $CODE"
done
echo ""

# ── 5. GraphQL introspection on advantage.mandiant.com/graphql ───────────────
info "5. GraphQL introspection (if endpoint is real, not SPA)"
echo ""
GRAPHQL_RESP=$(curl -sk --max-time 15 \
  -X POST \
  -H "User-Agent: $UA" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Origin: https://advantage.mandiant.com" \
  -d '{"query":"{ __schema { types { name kind } } }"}' \
  "https://advantage.mandiant.com/graphql" 2>/dev/null | head -c 2000)
echo "  Introspection response: ${GRAPHQL_RESP:0:300}"
if echo "$GRAPHQL_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('SCHEMA_OK')" 2>/dev/null; then
  hit "GraphQL INTROSPECTION ENABLED on advantage.mandiant.com/graphql"
  echo "$GRAPHQL_RESP" > "$OUT/graphql-introspection.json"
fi
echo ""

# Also try advantage-api/graphql
GRAPHQL_RESP2=$(curl -sk --max-time 15 \
  -X POST \
  -H "User-Agent: $UA" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Origin: https://advantage.mandiant.com" \
  -d '{"query":"{ __schema { types { name kind } } }"}' \
  "https://advantage-api.mandiant.com/graphql" 2>/dev/null | head -c 2000)
echo "  advantage-api/graphql introspection: ${GRAPHQL_RESP2:0:200}"
if echo "$GRAPHQL_RESP2" | python3 -c "import sys,json; d=json.load(sys.stdin); print('SCHEMA_OK')" 2>/dev/null; then
  hit "GraphQL INTROSPECTION ENABLED on advantage-api.mandiant.com/graphql"
  echo "$GRAPHQL_RESP2" > "$OUT/graphql-api-introspection.json"
fi
echo ""

# ── 6. Download portal-ng bundles (fixed regex for defer="defer") ────────────
info "6. portal-ng.mandiant.com — JS bundle download (fixed)"
echo ""
PORTAL_INDEX=$(curl -sk -H "User-Agent: $UA" "https://portal-ng.mandiant.com/" 2>/dev/null)
# Fixed: match src="scripts/..." with or without defer
BUNDLES=$(echo "$PORTAL_INDEX" | python3 -c "
import sys, re
html = sys.stdin.read()
# Match all script src attributes
bundles = re.findall(r'src=\"((?:scripts/|/scripts/)[^\"]+\.js[^\"]*)\"', html)
for b in bundles:
    print(b if b.startswith('/') else '/' + b)
" 2>/dev/null)
echo "  Bundles found:"
echo "$BUNDLES"
echo ""

MAIN_BUNDLE=$(echo "$BUNDLES" | grep -i "main" | head -1)
if [ -n "$MAIN_BUNDLE" ]; then
  info "  Downloading main bundle: $MAIN_BUNDLE"
  curl -sk -H "User-Agent: $UA" \
    "https://portal-ng.mandiant.com${MAIN_BUNDLE}" 2>/dev/null \
    > "$OUT/portal-ng-main.js"
  SIZE=$(wc -c < "$OUT/portal-ng-main.js")
  echo "  Size: $SIZE bytes"

  if [ "$SIZE" -gt 1000 ]; then
    info "  Extracting API endpoints from bundle..."
    python3 << 'PY'
import re
try:
    with open('results/mandiant/advantage/portal-ng-main.js', 'r', errors='ignore') as f:
        content = f.read()

    print("  API paths:")
    paths = set(re.findall(r'"(/(?:api|v[0-9]+|graphql|rest|socket|ws)[^"]{2,80})"', content))
    for p in sorted(paths)[:50]:
        print(f'    {p}')

    print("\n  Mandiant/Google backend domains:")
    domains = set(re.findall(r'"(https?://[a-zA-Z0-9._-]+\.(?:mandiant|fireeye|google)\.(?:com|io)[^"]{0,60})"', content))
    for d in sorted(domains)[:20]:
        print(f'    {d}')

    print("\n  Auth/client config:")
    auth = re.findall(r'"(clientId|client_id|audience|domain|issuer|apiKey|authDomain)":\s*"([^"]{3,80})"', content)
    for k, v in auth[:10]:
        print(f'    {k}: {v}')

    print("\n  GraphQL operations:")
    gql = set(re.findall(r'operationName["\s:=]+["\x27]([A-Za-z][A-Za-z0-9_]{4,49})["\x27]', content))
    for op in sorted(gql)[:30]:
        print(f'    {op}')

    print("\n  Potential secrets (non-hash 32+ char strings):")
    import hashlib
    tokens = set(re.findall(r'["\x27]([A-Za-z0-9_\-]{32,})["\x27]', content))
    interesting = [t for t in tokens
                   if not re.match(r'^[0-9a-f]{32,}$', t)  # not hex hash
                   and not re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', t)  # not b64 noise
                   and len(t) > 35
                   and any(kw in t.lower() for kw in ['key', 'token', 'secret', 'api', 'auth', 'id'])]
    for t in interesting[:10]:
        print(f'    {t[:80]}')
except Exception as e:
    print(f'  Error: {e}')
PY
  else
    warn "  Bundle too small ($SIZE bytes) — likely blocked or wrong path"
  fi
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Summary ═══${NC}"
if [ -s "$OUT/findings.txt" ]; then
  hit "Findings saved to $OUT/findings.txt:"
  cat "$OUT/findings.txt"
else
  echo "  No unauthenticated endpoints found."
  echo "  Key insight: advantage.mandiant.com API 200s are likely SPA shell (Angular)."
  echo "  Real APIs are at advantage-api.mandiant.com and api.intelligence.mandiant.com."
fi
echo ""
echo "  Next: If any API returned real JSON, probe for IDOR:"
echo "    /api/me      — whose identity is returned without auth?"
echo "    /v4/indicator — threat data accessible without auth?"
echo "    /graphql     — full schema dump if introspection enabled?"
