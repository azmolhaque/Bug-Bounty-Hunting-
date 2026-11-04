#!/usr/bin/env bash
# unicef-recon.sh — Phase 1+2 recon pipeline for UNICEF (unicef.org)
#
# Scope: *.unicef.org (all subdomains, cloud infra, APIs)
# Program: UNICEF Responsible Vulnerability Disclosure
#          infosecurity@unicef.org
#
# Phases covered:
#   1. Passive subdomain enumeration (subfinder + crt.sh + gau + wayback)
#   2. DNS resolution + CNAME extraction (dnsx)
#   3. Live host probing + tech fingerprinting (httpx)
#   4. Subdomain takeover pre-screen (subzy or manual CNAME fingerprinting)
#   5. Drupal instance identification
#   6. JS file inventory (for mining in Phase 3)
#   7. Priority target map
#
# Run: bash scripts/unicef-recon.sh
# Options:
#   --passive-only   skip active httpx/katana/naabu steps
#   --fast           skip amass (slow), use subfinder + crt.sh only
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export SCOPE_FILE="$ROOT_DIR/config/scope-unicef.yaml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[unicef-recon]${NC} $*"; }
warn() { echo -e "${YELLOW}[unicef-recon]${NC} $*"; }
err()  { echo -e "${RED}[unicef-recon]${NC} $*" >&2; }
info() { echo -e "${CYAN}[unicef-recon]${NC} $*"; }

TARGET="unicef.org"
PASSIVE_ONLY=false
FAST_MODE=false
for arg in "$@"; do
  [ "$arg" = "--passive-only" ] && PASSIVE_ONLY=true
  [ "$arg" = "--fast" ]         && FAST_MODE=true
done

# Rate limits — conservative for humanitarian infra
RATE="${RATE:-20}"
THREADS="${THREADS:-15}"
NAABU_RATE="${NAABU_RATE:-100}"

# ── Scope gate ────────────────────────────────────────────────────────────────
SCOPE_OUT="$("$SCRIPT_DIR/scope-check.sh" "$TARGET" 2>&1 || true)"
case "$SCOPE_OUT" in
  IN-SCOPE*) log "Scope OK: $SCOPE_OUT" ;;
  *)
    err "Scope check failed: $SCOPE_OUT"
    err "Ensure config/scope-unicef.yaml exists and lists unicef.org"
    exit 2
    ;;
esac

STAMP=$(date -u +%Y%m%d-%H%M)
OUT="$ROOT_DIR/results/unicef.org"
mkdir -p "$OUT/01-assets" "$OUT/02-surface" "$OUT/03-candidates"

LOG="$OUT/recon-${STAMP}.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== UNICEF RECON — $STAMP ==="
echo "Rate: ${RATE} req/s | Threads: ${THREADS} | Passive: ${PASSIVE_ONLY} | Fast: ${FAST_MODE}"
echo ""

have() { command -v "$1" >/dev/null 2>&1; }

# ── Phase 1: Subdomain enumeration ───────────────────────────────────────────
log "Phase 1: subdomain enumeration..."
: > "$OUT/01-assets/subdomains.txt"

# subfinder — fastest, broadest
if have subfinder; then
  log "  subfinder..."
  subfinder -d "$TARGET" -all -silent 2>/dev/null \
    | anew "$OUT/01-assets/subdomains.txt" >/dev/null || warn "subfinder failed"
else
  warn "subfinder not found — install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

# crt.sh — certificate transparency (no tool needed, just curl + jq)
log "  crt.sh certificate transparency..."
curl -sk --max-time 30 \
  "https://crt.sh/?q=%.unicef.org&output=json" \
  | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for e in data:
        for name in e.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if name.endswith('unicef.org') and name not in seen:
                seen.add(name)
                print(name)
except Exception as ex:
    sys.stderr.write(f'crt.sh parse error: {ex}\n')
" 2>/dev/null | anew "$OUT/01-assets/subdomains.txt" >/dev/null || warn "crt.sh failed"

# waybackurls / gau — historical subdomains
log "  historical URLs (gau + waybackurls)..."
{
  have gau && gau --threads "$THREADS" "$TARGET" 2>/dev/null || true
  have waybackurls && waybackurls "$TARGET" 2>/dev/null || true
} | python3 -c "
import sys, re
seen = set()
for line in sys.stdin:
    m = re.search(r'https?://([^/\s:?]+)', line)
    if m:
        h = m.group(1).lower()
        if h.endswith('unicef.org') and h not in seen:
            seen.add(h)
            print(h)
" 2>/dev/null | anew "$OUT/01-assets/subdomains.txt" >/dev/null || true

# Save historical URLs separately for endpoint mining
{
  have gau && gau --threads "$THREADS" "$TARGET" 2>/dev/null || true
  have waybackurls && waybackurls "$TARGET" 2>/dev/null || true
} | sort -u > "$OUT/01-assets/historical-urls.txt" 2>/dev/null || true

# amass — deeper, slower (skip in fast mode)
if ! $FAST_MODE && ! $PASSIVE_ONLY && have amass; then
  log "  amass passive (slow — skip with --fast)..."
  amass enum -passive -d "$TARGET" -timeout 15 2>/dev/null \
    | anew "$OUT/01-assets/subdomains.txt" >/dev/null || warn "amass failed"
fi

# github-subdomains (if installed)
if have github-subdomains; then
  log "  github-subdomains..."
  github-subdomains -d "$TARGET" -raw 2>/dev/null \
    | anew "$OUT/01-assets/subdomains.txt" >/dev/null || true
fi

# Ensure apex is included
echo "$TARGET" | anew "$OUT/01-assets/subdomains.txt" >/dev/null

TOTAL_SUBS=$(wc -l < "$OUT/01-assets/subdomains.txt")
log "Phase 1: $TOTAL_SUBS unique subdomains"

# ── Phase 1b: DNS resolution + CNAME extraction ───────────────────────────────
log "Phase 1b: resolving subdomains (dnsx)..."
if have dnsx; then
  dnsx -l "$OUT/01-assets/subdomains.txt" -silent -t "$THREADS" \
    -a -cname -resp \
    -o "$OUT/01-assets/resolved.txt" 2>/dev/null || warn "dnsx failed"

  # Extract CNAME records separately — needed for takeover screening
  dnsx -l "$OUT/01-assets/subdomains.txt" -silent -t "$THREADS" \
    -cname -resp-only \
    -o "$OUT/01-assets/cnames.txt" 2>/dev/null || warn "dnsx CNAME pass failed"

  TOTAL_RESOLVED=$(wc -l < "$OUT/01-assets/resolved.txt" 2>/dev/null || echo 0)
  TOTAL_CNAMES=$(wc -l < "$OUT/01-assets/cnames.txt" 2>/dev/null || echo 0)
  log "  $TOTAL_RESOLVED resolving | $TOTAL_CNAMES have CNAMEs"
else
  warn "dnsx not found — skipping DNS resolution"
  cp "$OUT/01-assets/subdomains.txt" "$OUT/01-assets/resolved.txt"
fi

# Extract just the hostnames that resolved (no annotations)
awk '{print $1}' "$OUT/01-assets/resolved.txt" 2>/dev/null \
  | sort -u > "$OUT/01-assets/resolved-hosts.txt" || true

# ── Phase 2: Live host probing ────────────────────────────────────────────────
log "Phase 2: probing live hosts (httpx, rate=$RATE)..."
if have httpx; then
  httpx -l "$OUT/01-assets/resolved-hosts.txt" -silent \
    -rate-limit "$RATE" -threads "$THREADS" \
    -status-code -title -tech-detect -web-server -ip -cdn \
    -follow-redirects \
    -json -o "$OUT/02-surface/httpx.jsonl" 2>/dev/null || warn "httpx failed"

  # Live URLs
  python3 -c "
import sys, json
for line in open('$OUT/02-surface/httpx.jsonl'):
    try:
        d = json.loads(line)
        print(d.get('url',''))
    except: pass
" 2>/dev/null | sort -u > "$OUT/02-surface/live.txt" || true

  LIVE=$(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)
  log "  $LIVE live hosts"

  # Tech summary
  python3 -c "
import sys, json, collections
tech_count = collections.Counter()
for line in open('$OUT/02-surface/httpx.jsonl'):
    try:
        d = json.loads(line)
        for t in d.get('tech', []):
            tech_count[t] += 1
    except: pass
print('=== Technology Distribution ===')
for tech, count in tech_count.most_common(20):
    print(f'  {count:4d}  {tech}')
" 2>/dev/null
else
  warn "httpx not found — skipping live probe"
fi

# ── Phase 2b: Drupal instance identification ──────────────────────────────────
log "Phase 2b: identifying Drupal instances..."
if [ -s "$OUT/02-surface/live.txt" ]; then
  python3 -c "
import sys, json
drupal = []
for line in open('$OUT/02-surface/httpx.jsonl'):
    try:
        d = json.loads(line)
        tech = [t.lower() for t in d.get('tech', [])]
        server = (d.get('webserver','') or '').lower()
        url = d.get('url','')
        if any('drupal' in t for t in tech):
            drupal.append(url)
    except: pass
for u in sorted(set(drupal)):
    print(u)
" 2>/dev/null > "$OUT/02-surface/drupal-instances.txt" || true

  DRUPAL_COUNT=$(wc -l < "$OUT/02-surface/drupal-instances.txt" 2>/dev/null || echo 0)
  log "  $DRUPAL_COUNT Drupal instances found"
  cat "$OUT/02-surface/drupal-instances.txt" 2>/dev/null | head -20

  # Probe JSON:API availability on each Drupal instance (unauthenticated)
  log "  Probing JSON:API on Drupal instances..."
  touch "$OUT/02-surface/drupal-jsonapi-live.txt"
  while IFS= read -r DURL; do
    [ -z "$DURL" ] && continue
    DHOST="${DURL%/}"
    # Check /jsonapi endpoint
    RESP=$(curl -sk --max-time 10 \
      -H "Accept: application/vnd.api+json" \
      -w "\n__CODE__%{http_code}" \
      "${DHOST}/jsonapi" 2>/dev/null)
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"
    IS_JSON=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read())
    print('yes' if 'links' in d or 'data' in d or 'jsonapi' in d else 'partial')
except: print('no')
" 2>/dev/null)
    echo "  [${CODE}][json=${IS_JSON}] ${DHOST}/jsonapi"
    if [ "$CODE" = "200" ] && [ "$IS_JSON" != "no" ]; then
      echo "${DHOST}" >> "$OUT/02-surface/drupal-jsonapi-live.txt"
    fi
  done < "$OUT/02-surface/drupal-instances.txt"
fi

# ── Phase 2c: Subdomain takeover pre-screen (CNAME dangling) ─────────────────
log "Phase 2c: subdomain takeover pre-screen..."

# Known takeover-vulnerable CNAME fingerprints
TAKEOVER_PATTERNS=(
  "github.io"
  "netlify.app"
  "netlify.com"
  "azurewebsites.net"
  "cloudapp.azure.com"
  "blob.core.windows.net"
  "azureedge.net"
  "trafficmanager.net"
  "herokudns.com"
  "herokussl.com"
  "herokuapp.com"
  "shopify.com"
  "myshopify.com"
  "wpengine.com"
  "fastly.net"
  "s3.amazonaws.com"
  "s3-website"
  "bitbucket.io"
  "ghost.io"
  "gitbook.io"
  "gitbook.com"
  "surge.sh"
  "webflow.io"
  "vercel.app"
  "render.com"
  "fly.dev"
  "pages.dev"
  "firebaseapp.com"
  "web.app"
)

touch "$OUT/02-surface/takeover-candidates.txt"
if [ -s "$OUT/01-assets/cnames.txt" ]; then
  while IFS= read -r CNAME_LINE; do
    for PAT in "${TAKEOVER_PATTERNS[@]}"; do
      if echo "$CNAME_LINE" | grep -qi "$PAT"; then
        echo "$CNAME_LINE"
        echo "$CNAME_LINE" >> "$OUT/02-surface/takeover-candidates.txt"
        break
      fi
    done
  done < "$OUT/01-assets/cnames.txt"
fi

TAKEOVER_COUNT=$(wc -l < "$OUT/02-surface/takeover-candidates.txt" 2>/dev/null || echo 0)
log "  $TAKEOVER_COUNT potential takeover candidates (verify each manually)"

# Use subzy if available for deeper takeover check
if have subzy && [ -s "$OUT/01-assets/subdomains.txt" ]; then
  log "  Running subzy..."
  subzy run --targets "$OUT/01-assets/subdomains.txt" \
    --output "$OUT/02-surface/subzy-results.txt" 2>/dev/null || warn "subzy failed"
fi

# ── Phase 2d: JS file inventory (for Phase 3 secret/endpoint mining) ──────────
log "Phase 2d: JS endpoint and URL inventory..."
cat "$OUT/01-assets/historical-urls.txt" 2>/dev/null \
  | grep -iE '\.js(\?|$)' \
  | sort -u > "$OUT/02-surface/js-files.txt" || true

JS_COUNT=$(wc -l < "$OUT/02-surface/js-files.txt" 2>/dev/null || echo 0)
log "  $JS_COUNT JS files queued for mining"

# ── Phase 2e: Crawl live hosts (light, rate-capped) ──────────────────────────
if ! $PASSIVE_ONLY && have katana && [ -s "$OUT/02-surface/live.txt" ]; then
  log "Phase 2e: crawling endpoints (katana, depth=1)..."
  katana -list "$OUT/02-surface/live.txt" -silent -d 1 -jc -kf all \
    -rate-limit "$RATE" -c "$THREADS" \
    -exclude-regex '/(blog|news|stories|press|careers|legal|sitemap|changelog)/|\.pdf$|\.png$|\.jpg$|\.svg$|\.woff' \
    -o "$OUT/02-surface/endpoints.txt" 2>/dev/null || warn "katana failed"
fi

# Merge all endpoint sources
cat "$OUT/01-assets/historical-urls.txt" "$OUT/02-surface/endpoints.txt" 2>/dev/null \
  | sort -u > "$OUT/02-surface/all-endpoints.txt" || true

ALL_EP=$(wc -l < "$OUT/02-surface/all-endpoints.txt" 2>/dev/null || echo 0)
log "  $ALL_EP total endpoints"

# ── Phase 2f: Priority target map ────────────────────────────────────────────
log "Phase 2f: building priority map..."
{
  echo "# Priority Targets — unicef.org"
  echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "## Takeover Candidates (verify immediately)"
  echo ""
  cat "$OUT/02-surface/takeover-candidates.txt" 2>/dev/null | head -30 || echo "  (none found)"
  echo ""
  echo "## Drupal JSON:API Live (probe for unauth data)"
  echo ""
  cat "$OUT/02-surface/drupal-jsonapi-live.txt" 2>/dev/null | head -20 || echo "  (none found)"
  echo ""
  echo "## Non-prod / High-priority Subdomains"
  echo ""
  echo "| Host | Signal | Priority |"
  echo "|------|--------|----------|"
  if [ -s "$OUT/02-surface/live.txt" ]; then
    grep -iE '(dev|test|staging|internal|admin|api|qa|uat|beta|rde|debug|partner|extranet|supply|agora|jobs|data)\.' \
      "$OUT/02-surface/live.txt" 2>/dev/null | head -40 | while IFS= read -r URL; do
      H="${URL#*://}"; H="${H%%/*}"
      echo "| ${H} | non-prod keyword | P0 |"
    done || true
  fi
  echo ""
  echo "## All Live Hosts"
  echo ""
  cat "$OUT/02-surface/live.txt" 2>/dev/null | head -100
} > "$OUT/02-surface/priority.md"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== UNICEF RECON COMPLETE — $STAMP ==="
echo ""
echo "Subdomains enumerated : $(wc -l < "$OUT/01-assets/subdomains.txt" 2>/dev/null || echo 0)"
echo "Resolving             : $(wc -l < "$OUT/01-assets/resolved-hosts.txt" 2>/dev/null || echo 0)"
echo "Live hosts            : $(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)"
echo "Drupal instances      : $(wc -l < "$OUT/02-surface/drupal-instances.txt" 2>/dev/null || echo 0)"
echo "JSON:API live         : $(wc -l < "$OUT/02-surface/drupal-jsonapi-live.txt" 2>/dev/null || echo 0)"
echo "Takeover candidates   : $(wc -l < "$OUT/02-surface/takeover-candidates.txt" 2>/dev/null || echo 0)"
echo "JS files              : $(wc -l < "$OUT/02-surface/js-files.txt" 2>/dev/null || echo 0)"
echo "Total endpoints       : $(wc -l < "$OUT/02-surface/all-endpoints.txt" 2>/dev/null || echo 0)"
echo "Log                   : $LOG"
echo ""
echo "NEXT STEPS:"
echo "  1. Review priority targets:    cat results/unicef.org/02-surface/priority.md"
echo "  2. Verify takeover candidates: cat results/unicef.org/02-surface/takeover-candidates.txt"
echo "  3. Probe JSON:API instances:   cat results/unicef.org/02-surface/drupal-jsonapi-live.txt"
echo "  4. Run Phase 3 hunt:           bash scripts/unicef-hunt.sh"
echo ""
echo "FASTEST WINS TO CHECK FIRST:"
echo "  1. Any line in takeover-candidates.txt with 'netlify' or 'github.io' = verify + claim"
echo "  2. Any drupal-jsonapi-live.txt entry = probe /jsonapi/user/user and /jsonapi/node/*"
