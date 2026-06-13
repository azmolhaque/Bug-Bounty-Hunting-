#!/usr/bin/env bash
# digitaltrust-probe.sh — Deep investigation of digitaltrust.wiz.io
# Runs on Pi; remote env is network-gated.
set -uo pipefail

TARGET="digitaltrust.wiz.io"
ROUTING="routing.digitaltrust.wiz.io"
OUT_DIR="results/wiz.io/evidence/digitaltrust"
mkdir -p "$OUT_DIR"

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
hit()  { echo -e "${GRN}[HIT]${NC} $*"; }
info() { echo -e "${BLU}[INF]${NC} $*"; }
warn() { echo -e "${YLW}[WRN]${NC} $*"; }
crit() { echo -e "${RED}[!!!]${NC} $*"; }

_fetch() {
  local url="$1"
  curl -sk --max-time 12 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -H "Accept: text/html,application/xhtml+xml,application/json,*/*" \
    -D /tmp/dt_headers.txt \
    "$url" 2>/dev/null
}

_code() {
  curl -sk --max-time 12 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -o /dev/null -w "%{http_code}" "$1" 2>/dev/null
}

_headers() {
  curl -sk --max-time 12 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -I "$1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════"
echo " PHASE A — Full homepage + headers"
echo "════════════════════════════════════════════════════"

info "Fetching https://$TARGET/ ..."
BODY=$(_fetch "https://$TARGET/")
echo "$BODY" | head -c 4000 > "$OUT_DIR/homepage.html"

echo "[Response headers:]"
cat /tmp/dt_headers.txt 2>/dev/null

echo ""
echo "[Page title & meta]"
echo "$BODY" | grep -Eo '<title>[^<]+</title>' | head -5
echo "$BODY" | grep -Eo '<meta[^>]+>' | head -20

echo ""
echo "[JS bundles referenced]"
echo "$BODY" | grep -Eo 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'

echo ""
echo "[Link/stylesheet hrefs]"
echo "$BODY" | grep -Eo 'href="[^"]+\.(css|js)[^"]*"' | head -20

# Extract CSP from headers
echo ""
echo "[CSP / Security headers]"
cat /tmp/dt_headers.txt | grep -i "content-security-policy\|x-frame\|strict-transport\|set-cookie" || true

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE B — Endpoint surface scan"
echo "════════════════════════════════════════════════════"

ENDPOINTS=(
  "/" "/api" "/api/v1" "/api/v2" "/graphql" "/gql"
  "/login" "/signin" "/signup" "/register" "/auth"
  "/health" "/healthz" "/status" "/ping" "/version"
  "/admin" "/dashboard" "/console" "/internal"
  "/api/me" "/api/user" "/api/users" "/api/organizations" "/api/orgs"
  "/api/projects" "/api/repos" "/api/packages" "/api/sbom"
  "/api/vulnerabilities" "/api/findings" "/api/assets"
  "/api/integrations" "/api/connect" "/api/trust"
  "/metrics" "/actuator" "/actuator/health" "/actuator/info"
  "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server"
  "/swagger" "/swagger-ui" "/swagger-ui.html" "/openapi.json" "/openapi.yaml"
  "/api-docs" "/docs" "/redoc"
  "/__graphql" "/graphql/schema.json"
  "/v1" "/v2" "/v3"
)

info "Scanning ${#ENDPOINTS[@]} endpoints on $TARGET ..."
for _EP in "${ENDPOINTS[@]}"; do
  CODE=$(_code "https://$TARGET${_EP}")
  CT=$(curl -sk --max-time 8 -o /dev/null -w "%{content_type}" \
       -H "User-Agent: Mozilla/5.0" "https://$TARGET${_EP}" 2>/dev/null)
  case "$CODE" in
    200) hit "$CODE [$CT] https://$TARGET${_EP}" ;;
    201|202|204) hit "$CODE [$CT] https://$TARGET${_EP}" ;;
    301|302|307|308)
      REDIR=$(curl -sk --max-time 8 -o /dev/null -w "%{redirect_url}" \
              -H "User-Agent: Mozilla/5.0" "https://$TARGET${_EP}" 2>/dev/null)
      info "$CODE → $REDIR https://$TARGET${_EP}" ;;
    401) warn "401 REQUIRES_AUTH https://$TARGET${_EP}" ;;
    403) warn "403 FORBIDDEN https://$TARGET${_EP}" ;;
    404) : ;; # silent
    *) info "$CODE https://$TARGET${_EP}" ;;
  esac
done

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE C — routing.digitaltrust.wiz.io probe"
echo "════════════════════════════════════════════════════"

info "Fetching https://$ROUTING/ ..."
ROUTING_BODY=$(_fetch "https://$ROUTING/")
echo "$ROUTING_BODY" | head -c 2000 > "$OUT_DIR/routing-homepage.html"
echo "[Routing homepage (first 1500 chars):]"
echo "$ROUTING_BODY" | head -c 1500

echo ""
echo "[Routing headers:]"
cat /tmp/dt_headers.txt 2>/dev/null

ROUTING_ENDPOINTS=("/" "/health" "/api" "/login" "/register" "/signup" "/status")
info "Scanning routing subdomain endpoints..."
for _EP in "${ROUTING_ENDPOINTS[@]}"; do
  CODE=$(_code "https://$ROUTING${_EP}")
  if [[ "$CODE" != "000" && "$CODE" != "404" ]]; then
    info "$CODE https://$ROUTING${_EP}"
  fi
done

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE D — JS bundle extraction + API config"
echo "════════════════════════════════════════════════════"

# Find JS bundle URLs from homepage
BUNDLE_URLS=$(echo "$BODY" | grep -Eo 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' | head -5)

if [[ -z "$BUNDLE_URLS" ]]; then
  # Try finding any script tags
  BUNDLE_URLS=$(echo "$BODY" | grep -Eo '"[^"]+\.js[^"]*"' | tr -d '"' | grep -v 'node_modules' | head -5)
fi

if [[ -n "$BUNDLE_URLS" ]]; then
  echo "$BUNDLE_URLS" | while read -r BUNDLE_PATH; do
    # Handle relative vs absolute
    if [[ "$BUNDLE_PATH" == http* ]]; then
      BUNDLE_URL="$BUNDLE_PATH"
    else
      BUNDLE_URL="https://$TARGET/$BUNDLE_PATH"
    fi
    info "Downloading bundle: $BUNDLE_URL"
    BUNDLE_FILE="$OUT_DIR/$(basename "$BUNDLE_PATH" | tr '/' '_')"
    curl -sk --max-time 30 -H "User-Agent: Mozilla/5.0" "$BUNDLE_URL" -o "$BUNDLE_FILE" 2>/dev/null
    BUNDLE_SIZE=$(wc -c < "$BUNDLE_FILE" 2>/dev/null || echo 0)
    info "Bundle size: ${BUNDLE_SIZE} bytes → $BUNDLE_FILE"

    if [[ "$BUNDLE_SIZE" -gt 1000 ]]; then
      echo "[API/domain config extraction:]"
      # API endpoints
      strings "$BUNDLE_FILE" 2>/dev/null | grep -Eo '"[^"]*(/api/|/graphql|wiz\.io|digitaltrust)[^"]*"' | sort -u | head -30
      # Auth URLs
      strings "$BUNDLE_FILE" 2>/dev/null | grep -Eo '"[^"]*/(auth|oauth|token|authorize|login|oidc)[^"]*"' | sort -u | head -20
      # Env vars / config
      strings "$BUNDLE_FILE" 2>/dev/null | grep -Eo '"[A-Z_]{4,}":"[^"]{3,}"' | sort -u | head -30
    fi
  done
else
  warn "No JS bundles found in homepage HTML"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE E — Auth surface + self-registration"
echo "════════════════════════════════════════════════════"

# Check if there's any sign of OAuth/OIDC metadata
info "Checking OIDC discovery..."
for _OIDC in "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server"; do
  OIDC_BODY=$(_fetch "https://$TARGET${_OIDC}")
  OIDC_CODE=$(_code "https://$TARGET${_OIDC}")
  if [[ "$OIDC_CODE" == "200" ]]; then
    hit "OIDC metadata at $TARGET${_OIDC}:"
    echo "$OIDC_BODY" | python3 -m json.tool 2>/dev/null | head -30
    echo "$OIDC_BODY" > "$OUT_DIR/oidc-config.json"
  fi
done

# Try GraphQL introspection unauthenticated
info "Testing GraphQL introspection (unauthenticated)..."
GQL_RESULT=$(curl -sk --max-time 12 \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  "https://$TARGET/graphql" 2>/dev/null)
GQL_CODE=$(_code "https://$TARGET/graphql")
if [[ "$GQL_CODE" == "200" ]]; then
  hit "GraphQL 200 on $TARGET/graphql"
  echo "$GQL_RESULT" | head -c 1000
fi
GQL_RESULT2=$(curl -sk --max-time 12 \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  "https://$TARGET/api/graphql" 2>/dev/null)
GQL_CODE2=$(_code "https://$TARGET/api/graphql")
if [[ "$GQL_CODE2" == "200" ]]; then
  hit "GraphQL 200 on $TARGET/api/graphql"
  echo "$GQL_RESULT2" | head -c 1000
fi

# Test self-registration (check for form/API endpoint)
info "Checking for self-registration endpoints..."
for _PATH in "/signup" "/register" "/api/register" "/api/signup" "/users/sign_up" "/api/v1/register"; do
  REG_CODE=$(_code "https://$TARGET${_PATH}")
  if [[ "$REG_CODE" != "000" && "$REG_CODE" != "404" ]]; then
    hit "Registration endpoint $REG_CODE: https://$TARGET${_PATH}"
    REG_BODY=$(_fetch "https://$TARGET${_PATH}")
    echo "$REG_BODY" | grep -Eo '(email|password|csrf|token|_method)[^<"]*' | head -10
  fi
done

# Test POST to /api/register
info "Testing POST to /api/register (registration probe)..."
REG_RESP=$(curl -sk --max-time 10 \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -w "\n[HTTP %{http_code}]" \
  -d '{"email":"probe@example.com","password":"TestP@ssw0rd123"}' \
  "https://$TARGET/api/register" 2>/dev/null)
echo "POST /api/register: $REG_RESP" | head -c 500

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE F — DNS & additional subdomain check"
echo "════════════════════════════════════════════════════"

info "DNS records for digitaltrust.wiz.io..."
dig +short A digitaltrust.wiz.io
dig +short CNAME digitaltrust.wiz.io
dig +short MX digitaltrust.wiz.io

info "DNS records for routing.digitaltrust.wiz.io..."
dig +short A routing.digitaltrust.wiz.io
dig +short CNAME routing.digitaltrust.wiz.io

info "Checking common subdomains of digitaltrust.wiz.io..."
for _SUB in api auth login app admin staging dev staging portal api-docs; do
  _HOST="${_SUB}.digitaltrust.wiz.io"
  IP=$(dig +short A "$_HOST" 2>/dev/null | head -1)
  if [[ -n "$IP" ]]; then
    CODE=$(_code "https://$_HOST/")
    hit "Found: $_HOST → $IP (HTTP $CODE)"
  fi
done

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " PHASE G — CORS / Access-Control test"
echo "════════════════════════════════════════════════════"

info "CORS test: Origin: https://evil.com on /api endpoints..."
for _EP in "/" "/api" "/api/v1" "/graphql"; do
  CORS_RESP=$(curl -sk --max-time 10 \
    -H "Origin: https://evil.com" \
    -H "User-Agent: Mozilla/5.0" \
    -I "https://$TARGET${_EP}" 2>/dev/null)
  ACAO=$(echo "$CORS_RESP" | grep -i "access-control-allow-origin" | head -1)
  if [[ -n "$ACAO" ]]; then
    hit "CORS header on ${_EP}: $ACAO"
  fi
done

# ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " SUMMARY"
echo "════════════════════════════════════════════════════"
echo "Evidence saved to: $OUT_DIR/"
echo "Files:"
ls -la "$OUT_DIR/" 2>/dev/null || true
echo ""
echo "Next: Review $OUT_DIR/homepage.html for JS bundles, auth providers, and API surface."
