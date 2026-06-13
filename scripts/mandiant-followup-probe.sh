#!/usr/bin/env bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
OUT="results/mandiant/deep-probe"
mkdir -p "$OUT"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[FOUND]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

echo ""
echo -e "${CYAN}═══ Mandiant Follow-up Probe ═══${NC}"
echo ""

# ── 1. Sign-up page analysis ────────────────────────────────────────────────
info "1. app.validation.mandiant.com/users/sign_up — form analysis"
SIGNUP=$(curl -sk -H "User-Agent: $UA" \
  -c /tmp/msv_cookies.txt \
  "https://app.validation.mandiant.com/users/sign_up" 2>/dev/null)
echo "$SIGNUP" | python3 -c "
import sys, re
html = sys.stdin.read()
# Check what fields exist in the form
fields = re.findall(r'<input[^>]+name=\"([^\"]+)\"', html)
print('  Form fields:', fields)
# Check form action
action = re.findall(r'<form[^>]+action=\"([^\"]+)\"', html)
print('  Form action:', action)
# Check for domain restriction hints
restricted = re.findall(r'(?:mandiant|google|allowlist|domain|corporate)[^<]{0,100}', html, re.IGNORECASE)
for r in restricted[:3]:
    print('  Hint:', r[:120])
# CSRF token
csrf = re.findall(r'name=\"authenticity_token\"[^>]*value=\"([^\"]+)\"', html)
if csrf:
    print('  CSRF:', csrf[0][:30], '...')
    print('CSRF_TOKEN=' + csrf[0])
" 2>/dev/null
echo ""

# ── 2. Attempt self-registration with a test email ──────────────────────────
info "2. Attempting self-registration..."
# First get CSRF token
SIGNUP_PAGE=$(curl -sk -H "User-Agent: $UA" -c /tmp/msv_cookies.txt \
  "https://app.validation.mandiant.com/users/sign_up" 2>/dev/null)
CSRF=$(echo "$SIGNUP_PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"authenticity_token\"[^>]*value=\"([^\"]+)\"', html)
if m: print(m.group(1))
" 2>/dev/null || echo "")

if [ -n "$CSRF" ]; then
  echo "  CSRF token obtained: ${CSRF:0:20}..."
  # Try registering with a test@test.com address
  REGISTER_RESP=$(curl -sk -v --max-redirs 5 \
    -H "User-Agent: $UA" \
    -b /tmp/msv_cookies.txt -c /tmp/msv_cookies.txt \
    -X POST \
    --data-urlencode "authenticity_token=${CSRF}" \
    --data-urlencode "user[email]=pentest_bounty_$(date +%s)@gmail.com" \
    --data-urlencode "user[password]=TestPw@$$12345" \
    --data-urlencode "user[password_confirmation]=TestPw@$$12345" \
    "https://app.validation.mandiant.com/users" 2>&1)
  REG_CODE=$(echo "$REGISTER_RESP" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
  REG_LOC=$(echo "$REGISTER_RESP" | grep -ioE "< location: [^\r\n]+" | head -1 | awk '{print $3}')
  REG_BODY=$(echo "$REGISTER_RESP" | tail -30 | grep -v "^[<>*]" | head -10)
  echo "  Registration response: HTTP $REG_CODE"
  echo "  Location: $REG_LOC"
  echo "  Body snippet: ${REG_BODY:0:200}"
  echo "  Body clues:$(echo "$REGISTER_RESP" | tail -30 | python3 -c "
import sys, re
text = sys.stdin.read()
for kw in ['error', 'invalid', 'success', 'confirm', 'activation', 'welcome', 'domain', 'allowed', 'corporate']:
    if kw.lower() in text.lower():
        print(f' [{kw}]', end='')
print()
" 2>/dev/null)"
else
  echo "  Could not get CSRF token for sign_up"
fi
echo ""

# ── 3. Password reset email enumeration ─────────────────────────────────────
info "3. Email enumeration via password reset"
RESET_PAGE=$(curl -sk -H "User-Agent: $UA" -c /tmp/msv_reset_cookies.txt \
  "https://app.validation.mandiant.com/users/password/new" 2>/dev/null)
RESET_CSRF=$(echo "$RESET_PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"authenticity_token\"[^>]*value=\"([^\"]+)\"', html)
if m: print(m.group(1))
" 2>/dev/null || echo "")

if [ -n "$RESET_CSRF" ]; then
  for TEST_EMAIL in "test@mandiant.com" "nonexist_zzz_8675309@mandiant.com" "test@gmail.com"; do
    RESP=$(curl -sk -v --max-redirs 5 \
      -H "User-Agent: $UA" \
      -b /tmp/msv_reset_cookies.txt -c /tmp/msv_reset_cookies.txt \
      -X POST \
      --data-urlencode "authenticity_token=${RESET_CSRF}" \
      --data-urlencode "user[email]=${TEST_EMAIL}" \
      "https://app.validation.mandiant.com/users/password" 2>&1)
    CODE=$(echo "$RESP" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
    LOC=$(echo "$RESP" | grep -ioE "< location: [^\r\n]+" | head -1 | awk '{print $3}')
    FLASH=$(echo "$RESP" | grep -iE "notice|alert|error|email" | grep -v "^[<>*]" | head -2)
    echo "  $TEST_EMAIL → HTTP $CODE | Redirect: $LOC"
    [ -n "$FLASH" ] && echo "    Flash: $FLASH"
  done
else
  echo "  Could not get CSRF for password reset"
fi
echo ""

# ── 4. portal-ng.mandiant.com — JS bundle extraction ───────────────────────
info "4. portal-ng.mandiant.com — JS bundle API extraction"
INDEX=$(curl -sk -H "User-Agent: $UA" "https://portal-ng.mandiant.com/" 2>/dev/null)
SCRIPTS=$(echo "$INDEX" | python3 -c "
import sys, re
html = sys.stdin.read()
bundles = re.findall(r'src=\"(/(?:scripts|main|chunk|vendor)[^\"]+\.js(?:\?[^\"]*)?)\"', html)
for b in bundles[:10]:
    print(b)
" 2>/dev/null || echo "")
echo "  Found bundles:"
echo "$SCRIPTS" | head -10

MAIN=$(echo "$SCRIPTS" | grep -E "main|app" | head -1)
if [ -z "$MAIN" ]; then
  MAIN=$(echo "$SCRIPTS" | head -1)
fi

if [ -n "$MAIN" ]; then
  echo "  Downloading: $MAIN"
  curl -sk -H "User-Agent: $UA" "https://portal-ng.mandiant.com${MAIN}" 2>/dev/null \
    > "$OUT/main-bundle.js"
  SIZE=$(wc -c < "$OUT/main-bundle.js")
  echo "  Size: $SIZE bytes"
  echo ""
  echo "  API paths found:"
  python3 << 'PY'
import re
try:
    with open('results/mandiant/deep-probe/main-bundle.js', 'r', errors='ignore') as f:
        content = f.read()
    # API paths
    paths = set(re.findall(r'"(/(?:api|v[0-9]+|graphql|rest|ws|socket)[^"]{2,80})"', content))
    for p in sorted(paths)[:40]:
        print(f'    {p}')
    # Embedded domains
    print("\n  Embedded domains:")
    domains = set(re.findall(r'"(https?://[a-zA-Z0-9._-]+\.(?:mandiant|google|fireeye)\.(?:com|io)[^"]{0,60})"', content))
    for d in sorted(domains)[:20]:
        print(f'    {d}')
    # Auth config
    print("\n  Auth/client config:")
    auth = re.findall(r'"(clientId|client_id|audience|domain|issuer|scope)":\s*"([^"]{3,80})"', content)
    for k, v in auth[:10]:
        print(f'    {k}: {v}')
    # GraphQL ops
    gql = set(re.findall(r'operationName["\s:]+([A-Za-z]{5,50})', content))
    if gql:
        print("\n  GraphQL operations:", list(gql)[:20])
except Exception as e:
    print(f'  Error: {e}')
PY
else
  echo "  No main bundle found in index"
  echo "  Raw index preview:"
  echo "$INDEX" | head -20
fi
echo ""

# ── 5. advantage.mandiant.com — full surface ─────────────────────────────────
info "5. advantage.mandiant.com — API surface"
ADV_HEADERS=$(curl -sk -I -H "User-Agent: $UA" "https://advantage.mandiant.com/" 2>/dev/null)
echo "$ADV_HEADERS" | grep -iE "content-security-policy|x-frame|server|set-cookie|x-powered" | head -10
echo ""
echo "  API endpoints:"
for EP in /api /api/v1 /api/v4 /graphql /api/auth /v4/indicator /v4/actor \
          /v4/malware /v4/vulnerability /api/collections /api/users /api/me; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 3 --max-time 8 \
    -H "User-Agent: $UA" -H "Accept: application/json" \
    "https://advantage.mandiant.com${EP}" 2>/dev/null)
  echo "  ${EP} → HTTP $CODE"
done
echo ""

# ── 6. md.mandiant.com — try with JSON accept ─────────────────────────────
info "6. md.mandiant.com — probing with portal-ng origin header"
for EP in /api/v1/me /api/user /graphql /api/incidents /api/alerts /api/health /api/ping; do
  RESP=$(curl -sk -w "\n%{http_code}" --max-redirs 3 --max-time 8 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    -H "Origin: https://portal-ng.mandiant.com" \
    -H "Referer: https://portal-ng.mandiant.com/" \
    "https://md.mandiant.com${EP}" 2>/dev/null)
  CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -3 | tr -d '\n')
  echo "  ${EP} → HTTP $CODE | ${BODY:0:100}"
done
echo ""

echo -e "${CYAN}═══ Done ═══${NC}"
echo "Bundle saved to: $OUT/main-bundle.js"
