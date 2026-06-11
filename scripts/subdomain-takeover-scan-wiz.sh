#!/usr/bin/env zsh
# Subdomain takeover scanner — wiz.io full DNS list
# Checks all resolved subdomains for dangling CNAME fingerprints
# Run on Pi after DNS scan is complete
# Usage: zsh ~/bug-bounty-hunting-/scripts/subdomain-takeover-scan-wiz.sh [dns-results-file]

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

DNS_FILE="${1:-$HOME/bug-bounty-hunting-/results/wiz.io/01-assets/resolved.txt}"
RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns
mkdir -p "$RESULTS"

# Takeover fingerprints — service → HTTP body fingerprint
# Source: can-i-take-over-xyz
declare -A FINGERPRINTS
FINGERPRINTS=(
  [vercel]="DEPLOYMENT_NOT_FOUND"
  [github_pages]="There isn't a GitHub Pages site here"
  [netlify]="Not Found - Request ID"
  [s3_bucket]="NoSuchBucket"
  [azure_cdn]="ErrorCode: AccessDenied|InvalidQueryParameterValue"
  [azure_app]="404 Web Site not found"
  [heroku]="No such app|herokucdn.com"
  [fastly]="Fastly error: unknown domain"
  [surge_sh]="project not found"
  [ghost_io]="Domain does not exist|ghost.io"
  [helpscout]="No settings were found for this company"
  [zendesk]="Help Center Closed|this help center no longer exists"
  [wordpress_com]="Do you want to register"
  [shopify]="Sorry, this shop is currently unavailable"
  [fly_io]="404 - Hmm\|We couldn't find the app"
  [render]="not found on Render"
  [railway]="Application not found"
)

echo "[*] Subdomain takeover scan — wiz.io"
echo "[*] Input: $DNS_FILE"

if [ ! -f "$DNS_FILE" ]; then
  echo "[!] DNS file not found: $DNS_FILE"
  echo "    Try: find ~/bug-bounty-hunting-/results/wiz.io/ -name 'resolved*' | head -5"
  echo ""
  echo "    Running CNAME check on known hosts instead..."
  # Fallback: check known Fastly/Vercel-adjacent hosts
  DNS_HOSTS=(
    win.wiz.io
    win-test.wiz.io
    unity.wiz.io
    whatsnew.wiz.io
    www.peach.wiz.io
    wizcli.app.wiz.io
    wizcli.e2e.wiz.io
    wizcli.test.wiz.io
    wizcli.stage.wiz.io
    wizcli.demo.wiz.io
    wizcli.integration.wiz.io
    app.wiz.io
  )
else
  # Read hostnames from DNS results file
  # Expected format: one hostname per line (or dnsx JSON output)
  if head -1 "$DNS_FILE" | grep -q '^{'; then
    # dnsx JSON format
    DNS_HOSTS=($(jq -r '.host' "$DNS_FILE" 2>/dev/null | sort -u))
  else
    DNS_HOSTS=($(sort -u "$DNS_FILE"))
  fi
fi

echo "[*] Checking ${#DNS_HOSTS[@]} hosts..."

TAKEOVER_CANDIDATES=()

check_host() {
  local host="$1"

  # Get CNAME chain
  cname=$(dig CNAME "$host" +short 2>/dev/null | tail -1)
  [ -z "$cname" ] && return  # No CNAME → not a typical takeover target

  # Check for known dangling CNAME patterns
  is_interesting=0
  service=""

  case "$cname" in
    *vercel-dns*|*vercel.com*)  service="vercel"; is_interesting=1 ;;
    *github.io*)                service="github_pages"; is_interesting=1 ;;
    *netlify.app*|*netlify.com*) service="netlify"; is_interesting=1 ;;
    *.s3.amazonaws.com*|*.s3-website*)  service="s3_bucket"; is_interesting=1 ;;
    *.azurewebsites.net*)       service="azure_app"; is_interesting=1 ;;
    *.azureedge.net*)           service="azure_cdn"; is_interesting=1 ;;
    *herokuapp.com*|*heroku.com*) service="heroku"; is_interesting=1 ;;
    *surge.sh*)                  service="surge_sh"; is_interesting=1 ;;
    *.ghost.io*)                 service="ghost_io"; is_interesting=1 ;;
    *helpscoutdocs.com*)         service="helpscout"; is_interesting=1 ;;
    *zendesk.com*)               service="zendesk"; is_interesting=1 ;;
    *wordpress.com*)             service="wordpress_com"; is_interesting=1 ;;
    *myshopify.com*)             service="shopify"; is_interesting=1 ;;
    *.fly.dev*)                  service="fly_io"; is_interesting=1 ;;
    *.onrender.com*)             service="render"; is_interesting=1 ;;
    *.up.railway.app*)           service="railway"; is_interesting=1 ;;
  esac

  [ "$is_interesting" = "0" ] && return

  # Confirm dangling: fetch the host and check for fingerprint
  fingerprint="${FINGERPRINTS[$service]:-}"
  body=$(curl -sk --connect-timeout 8 --max-time 12 "https://${host}/" 2>/dev/null | head -c 1000)

  if [ -n "$fingerprint" ] && echo "$body" | grep -qE "$fingerprint"; then
    echo "[TAKEOVER] $host → CNAME: $cname → SERVICE: $service"
    echo "  FINGERPRINT CONFIRMED: $(echo "$body" | grep -oE "$fingerprint" | head -1)"
    echo "$host|$cname|$service" >> "$RESULTS/takeover-confirmed.txt"
    TAKEOVER_CANDIDATES+=("$host")
  elif [ -n "$fingerprint" ]; then
    # CNAME to known service but fingerprint not matched — might be active
    status=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://${host}/" 2>/dev/null)
    echo "[CNAME-CHECK] $host → $cname → $service (status: $status, no takeover fingerprint)"
    echo "$host|$cname|$service|$status" >> "$RESULTS/cname-external.txt"
  fi
}

# Run checks (concurrency: 10 parallel)
echo "${DNS_HOSTS[@]}" | tr ' ' '\n' | while read -r host; do
  [ -n "$host" ] || continue
  check_host "$host" &
  # Limit parallelism
  while [ "$(jobs -r | wc -l)" -ge 10 ]; do sleep 0.1; done
done
wait

echo ""
echo "[*] === SUMMARY ==="
echo "[*] Confirmed takeovers: ${#TAKEOVER_CANDIDATES[@]}"
if [ -f "$RESULTS/takeover-confirmed.txt" ]; then
  cat "$RESULTS/takeover-confirmed.txt"
fi
echo "[*] CNAME to external services (review): $(wc -l < "$RESULTS/cname-external.txt" 2>/dev/null || echo 0)"
echo ""
echo "[*] Results in $RESULTS/"

# Special: probe win.wiz.io directly (same IP range as win-test)
echo ""
echo "=== SPECIAL: win.wiz.io direct probe (same Fastly block as win-test) ==="
echo "CNAME: $(dig CNAME win.wiz.io +short 2>/dev/null)"
echo "A: $(dig A win.wiz.io +short 2>/dev/null)"
echo "RESPONSE:"
curl -sk --connect-timeout 10 "https://win.wiz.io/" | head -c 300
echo ""
echo "HEADERS:"
curl -sI --connect-timeout 10 "https://win.wiz.io/" 2>/dev/null | head -15
