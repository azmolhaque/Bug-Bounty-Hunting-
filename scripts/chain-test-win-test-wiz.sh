#!/usr/bin/env bash
# chain-test-win-test-wiz.sh
# Chain elevation testing for F001 — win-test.wiz.io subdomain takeover.
#
# Run this BEFORE submitting the standalone report. A positive result on
# any chain here upgrades severity from High (8.2) to Critical (9.3+).
#
# All tests are PASSIVE (read-only HTTP observation). No domain is claimed.
# Run from Pi: bash scripts/chain-test-win-test-wiz.sh
set -euo pipefail

APP="https://app.wiz.io"
WWW="https://www.wiz.io"
COM="https://community.wiz.io"
TARGET="win-test.wiz.io"
OUT="results/wiz.io/chain-tests"
mkdir -p "$OUT"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
hit()  { echo -e "${RED}[CHAIN HIT]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[?]${NC} $*"; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  F001 Chain Elevation Tests — win-test.wiz.io             ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ─── Baseline: confirm still claimable ─────────────────────────────────────
info "Baseline: confirming win-test.wiz.io still claimable..."
CNAME=$(dig CNAME win-test.wiz.io +short 2>/dev/null)
BODY=$(curl -sk "https://$TARGET/" 2>/dev/null)
if echo "$BODY" | grep -q "DEPLOYMENT_NOT_FOUND"; then
  ok "Still claimable — DEPLOYMENT_NOT_FOUND confirmed"
else
  echo "CNAME: $CNAME"
  echo "Body: $BODY" | head -3
  warn "Unexpected response — confirm manually before proceeding"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN A — Cookie Domain Scope
# Impact if positive: session hijacking → Critical (CVSS 9.1+)
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN A — Cookie Domain Scope (app.wiz.io)"
echo "--- Set-Cookie headers ---"
COOKIES_HEADER=$(curl -sk "$APP/" -D - -o /dev/null 2>/dev/null | grep -i "set-cookie" || true)
echo "$COOKIES_HEADER" | tee "$OUT/chain-a-cookies.txt"
echo ""

if echo "$COOKIES_HEADER" | grep -qi "Domain=\.wiz\.io"; then
  hit "CHAIN A POSITIVE — Domain=.wiz.io cookie found"
  hit "win-test.wiz.io will RECEIVE these cookies if claimed"
  hit "This elevates F001 to Critical — includes cookie names above in report"
elif echo "$COOKIES_HEADER" | grep -qi "__Host-\|__Secure-"; then
  ok "Cookie uses __Host-/__Secure- prefix — domain-locked, NOT sent to win-test.wiz.io"
else
  warn "No Domain=.wiz.io found. Check cookie jar for SameSite settings:"
fi

echo "--- Full cookie jar (includes SameSite) ---"
curl -sk "$APP/" -c /tmp/wiz-cookiejar.txt -o /dev/null 2>/dev/null
cat /tmp/wiz-cookiejar.txt | tee -a "$OUT/chain-a-cookies.txt"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN B — Content Security Policy
# Impact if positive: win-test in script-src → arbitrary JS in portal → Critical 9.3
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN B — CSP Audit (app.wiz.io, www.wiz.io, community.wiz.io)"
for url in "$APP/" "$WWW/" "$COM/"; do
  echo "--- $url ---"
  CSP=$(curl -sk "$url" -D - -o /dev/null 2>/dev/null | grep -i "content-security-policy" || true)
  echo "$CSP" | tee -a "$OUT/chain-b-csp.txt"
  if echo "$CSP" | grep -qi "win-test"; then
    hit "CHAIN B CRITICAL — win-test.wiz.io found in CSP of $url"
    hit "Arbitrary script injection possible → admin session theft"
  elif echo "$CSP" | grep -qiE "\*\.wiz\.io"; then
    hit "CHAIN B HIGH — Wildcard *.wiz.io in CSP of $url — claimed subdomain is trusted"
  else
    ok "win-test.wiz.io not in CSP"
  fi
done
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN C — CORS Allowlist
# Impact if positive: cross-origin API read from claimed subdomain → High
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN C — CORS Probe (Origin: https://win-test.wiz.io)"
for endpoint in "/" "/api" "/api/v1" "/api/graphql" "/graphql" "/auth"; do
  echo "--- $APP$endpoint ---"
  CORS=$(curl -sk -X OPTIONS \
    -H "Origin: https://$TARGET" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: Authorization,Content-Type" \
    "$APP$endpoint" -D - -o /dev/null 2>/dev/null \
    | grep -iE "(access-control-allow-origin|access-control-allow-cred)" || true)
  echo "$CORS" | tee -a "$OUT/chain-c-cors.txt"
  if echo "$CORS" | grep -qi "win-test.wiz.io"; then
    hit "CHAIN C HIGH — CORS allows win-test.wiz.io on $endpoint"
    hit "Claimed subdomain can make credentialed cross-origin API requests"
  elif echo "$CORS" | grep -qiE "allow-credentials: true" && echo "$CORS" | grep -qiE "\*"; then
    hit "CHAIN C HIGH — ACAO: * with credentials:true on $endpoint (exploitable)"
  fi
done
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN D — OAuth Provider Discovery
# Impact if positive: win-test in redirect_uri → auth code theft → Critical
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN D — OAuth Provider Discovery"
echo "--- Detecting Auth0 tenant and client_id ---"
# Get login page to find OAuth params
curl -sk -L "$APP/login" -D - -o "$OUT/chain-d-login.html" 2>/dev/null | grep -iE "(location:|www-auth)" | head -5 || true

# Extract OAuth config from the login page JS
echo ""
echo "OAuth params found in login page:"
grep -oE '"clientId"\s*:\s*"[^"]*"' "$OUT/chain-d-login.html" 2>/dev/null | head -3 | tee -a "$OUT/chain-d-oauth.txt" || true
grep -oE '"domain"\s*:\s*"[^.]*\.auth0\.com[^"]*"' "$OUT/chain-d-login.html" 2>/dev/null | head -3 | tee -a "$OUT/chain-d-oauth.txt" || true
grep -oE 'client_id=[A-Za-z0-9_-]+' "$OUT/chain-d-login.html" 2>/dev/null | head -3 | tee -a "$OUT/chain-d-oauth.txt" || true
grep -oE 'redirect_uri=[^&"'"'"' ]+' "$OUT/chain-d-login.html" 2>/dev/null | head -5 | tee -a "$OUT/chain-d-oauth.txt" || true

echo ""
echo "--- Auth0/SSO tenant probe ---"
for auth_domain in "auth0.demo.wiz.io" "auth0.e2e.wiz.io" "auth.wiz.io" "login.wiz.io" "sso.wiz.io"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$auth_domain/.well-known/openid-configuration" 2>/dev/null)
  echo "$auth_domain → HTTP $STATUS"
  if [ "$STATUS" = "200" ]; then
    hit "Found OIDC config at $auth_domain — extracting issuer..."
    curl -sk "https://$auth_domain/.well-known/openid-configuration" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | grep -E '"(issuer|authorization_endpoint)"' \
      | tee -a "$OUT/chain-d-oauth.txt"
  fi
done | tee -a "$OUT/chain-d-oauth.txt"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN E — OAuth redirect_uri Allowlist Test
# Reads client_id + auth domain from Chain D output
# Impact if positive: auth code → account takeover → Critical (CVSS 10)
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN E — OAuth redirect_uri Allowlist Test"
CLIENT_ID=$(grep -oE '"clientId"\s*:\s*"([^"]+)"' "$OUT/chain-d-login.html" 2>/dev/null | head -1 | grep -oE '"[^"]*"$' | tr -d '"' || true)
AUTH_DOMAIN=$(grep -oE '[A-Za-z0-9_-]+\.auth0\.com' "$OUT/chain-d-login.html" 2>/dev/null | head -1 || true)

if [ -n "$CLIENT_ID" ] && [ -n "$AUTH_DOMAIN" ]; then
  info "Found client_id=$CLIENT_ID auth_domain=$AUTH_DOMAIN"
  echo "--- Testing redirect_uri=https://win-test.wiz.io/callback ---"
  RESPONSE=$(curl -sk -D - -o /dev/null \
    "https://$AUTH_DOMAIN/authorize?client_id=$CLIENT_ID&redirect_uri=https%3A%2F%2Fwin-test.wiz.io%2Fcallback&response_type=code&scope=openid" \
    2>/dev/null | grep -i "location:" || true)
  echo "$RESPONSE" | tee "$OUT/chain-e-oauth-test.txt"
  if echo "$RESPONSE" | grep -qi "win-test.wiz.io"; then
    hit "CHAIN E CRITICAL — OAuth redirects to win-test.wiz.io"
    hit "win-test.wiz.io IS in the Auth0 redirect_uri allowlist"
    hit "Attacker can send: https://$AUTH_DOMAIN/authorize?..&redirect_uri=https://win-test.wiz.io/callback"
    hit "Victim clicks link → Auth0 sends authorization code to ATTACKER → account takeover"
  elif echo "$RESPONSE" | grep -qi "callback_url_mismatch\|redirect_uri\|error"; then
    ok "redirect_uri NOT in allowlist — Auth0 rejected win-test.wiz.io"
  else
    warn "Ambiguous response — manual verification needed"
    echo "$RESPONSE"
  fi
else
  warn "Could not extract client_id/auth_domain from login page — run manually:"
  echo "  1. Open https://app.wiz.io/login in browser DevTools → Network tab"
  echo "  2. Find the OAuth authorize request — copy client_id and auth domain"
  echo "  3. Re-run this script or run Chain E manually"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN F — win-test.wiz.io Referenced in App Source
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN F — Searching app source for win-test references"
for url in "$APP/" "$WWW/"; do
  echo "--- $url ---"
  curl -sk "$url" 2>/dev/null | grep -i "win-test" | head -5 || true
done
# Also check main JS bundles
echo "--- JS bundle URLs ---"
curl -sk "$APP/" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | head -10
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN G — SameSite=None cookies accessible cross-site
# Impact: Supplement to Chain A — SameSite=None means cookie sent in cross-site reqs
# ═══════════════════════════════════════════════════════════════════════════
info "CHAIN G — SameSite=None Cookie Check"
SAMESITE_NONE=$(curl -sk "$APP/" -D - -o /dev/null 2>/dev/null \
  | grep -i "set-cookie" | grep -i "samesite=none" || true)
if [ -n "$SAMESITE_NONE" ]; then
  hit "CHAIN G — SameSite=None cookies found:"
  echo "$SAMESITE_NONE"
  hit "These are sent in cross-site requests — a claimed win-test.wiz.io receives them"
else
  ok "No SameSite=None cookies found"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Chain Test Summary                                        ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved to: $OUT/"
echo ""
echo "DECISION TREE:"
echo "  A positive (Domain=.wiz.io cookie)        → Critical — claim + cookie theft PoC"
echo "  B positive (win-test in CSP script-src)   → Critical — claim + XSS in portal"
echo "  C positive (CORS allows win-test)          → High     — claim + cross-origin API read"
echo "  E positive (OAuth redirect_uri accepted)   → Critical — account takeover chain"
echo "  None positive                              → Submit High (8.2) standalone — still valid"
echo ""
echo "NEXT STEP:"
echo "  If any chain is positive: run scripts/claim-vercel-poc.sh (creates minimal PoC project)"
echo "  If no chain: submit results/wiz.io/findings/F001-win-test-subdomain-takeover.md as-is"
