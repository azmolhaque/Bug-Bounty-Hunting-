#!/usr/bin/env bash
# subdomain-monitor-cron.sh — Nightly subdomain diff + takeover scan
#
# Runs at 03:00 daily via setup-cron.sh.
# For each active target in config/scope.yaml:
#   1. Run subfinder to get current subdomains
#   2. Diff against previous run (detect new assets)
#   3. Run subzy on all CNAMEs for takeover fingerprints
#   4. Notify Discord if new subdomains or takeover candidates found
#
# Output: results/<target>/recon/subdomains/

set -uo pipefail

BB="${HOME}/bug-bounty-hunting-"
SCOPE_FILE="${BB}/config/scope.yaml"
DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%S)

log()  { echo "[${TIMESTAMP}] $*"; }
die()  { echo "[${TIMESTAMP}] ERROR: $*" >&2; exit 1; }

# Load Discord webhook if available
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
notify_discord() {
  local msg="$1"
  [ -z "$DISCORD_WEBHOOK_URL" ] && return 0
  curl -sS -X POST "$DISCORD_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"[Pi5 Monitor] $msg\"}" >/dev/null 2>&1 || true
}

# Load secrets for API keys
[ -f "${HOME}/.secrets.zsh" ] && source "${HOME}/.secrets.zsh" 2>/dev/null || true

# ─── Validate tools ────────────────────────────────────────────────
for tool in subfinder httpx subzy; do
  command -v "$tool" >/dev/null 2>&1 || { log "WARNING: $tool not found — skipping dependent steps"; }
done

[ -f "$SCOPE_FILE" ] || die "scope.yaml not found: $SCOPE_FILE"

# ─── Extract domains from scope.yaml ──────────────────────────────
# Parse root domains from the scope file (lines starting with spaces under domains:)
TARGETS=$(python3 -c "
import yaml, sys
try:
    with open('${SCOPE_FILE}') as f:
        data = yaml.safe_load(f)
    targets = data.get('targets', {})
    for name, info in targets.items():
        if isinstance(info, dict) and info.get('active', True):
            for domain in info.get('domains', []):
                # Strip wildcard prefix
                d = domain.lstrip('*.')
                if d and '/' not in d:
                    print(d)
except Exception as e:
    sys.exit(f'YAML parse error: {e}')
" 2>/dev/null) || { log "WARNING: Could not parse scope.yaml — check Python yaml module"; TARGETS=""; }

if [ -z "$TARGETS" ]; then
  log "No active targets found in scope.yaml"
  exit 0
fi

log "Starting subdomain monitor for: $(echo $TARGETS | tr '\n' ' ')"
TOTAL_NEW=0
TOTAL_TAKEOVER=0

# ─── Per-target processing ─────────────────────────────────────────
while IFS= read -r target; do
  [ -z "$target" ] && continue
  log "--- $target ---"

  RECON_DIR="${BB}/results/${target}/recon/subdomains"
  mkdir -p "$RECON_DIR"

  CURRENT_FILE="${RECON_DIR}/current.txt"
  PREV_FILE="${RECON_DIR}/previous.txt"
  NEW_FILE="${RECON_DIR}/new-${DATE}.txt"
  HISTORY_FILE="${RECON_DIR}/history.txt"

  # Back up previous run
  [ -f "$CURRENT_FILE" ] && cp "$CURRENT_FILE" "$PREV_FILE"

  # ── Run subfinder ──────────────────────────────────────────────
  if command -v subfinder >/dev/null 2>&1; then
    log "  subfinder: enumerating $target..."
    subfinder -d "$target" -silent -all \
      -o "${CURRENT_FILE}.tmp" 2>/dev/null || true

    if [ -f "${CURRENT_FILE}.tmp" ] && [ -s "${CURRENT_FILE}.tmp" ]; then
      sort -u "${CURRENT_FILE}.tmp" > "$CURRENT_FILE"
      rm -f "${CURRENT_FILE}.tmp"
      COUNT=$(wc -l < "$CURRENT_FILE")
      log "  subfinder: found $COUNT subdomains"
    else
      log "  subfinder: no results for $target"
      continue
    fi
  else
    log "  subfinder not available — skipping $target"
    continue
  fi

  # ── Diff against previous run ──────────────────────────────────
  if [ -f "$PREV_FILE" ]; then
    comm -23 <(sort "$CURRENT_FILE") <(sort "$PREV_FILE") > "$NEW_FILE" 2>/dev/null || true
    NEW_COUNT=$(wc -l < "$NEW_FILE" 2>/dev/null || echo 0)

    if [ "$NEW_COUNT" -gt 0 ]; then
      log "  NEW subdomains detected: $NEW_COUNT"
      cat "$NEW_FILE" | while read -r sub; do log "    + $sub"; done
      TOTAL_NEW=$((TOTAL_NEW + NEW_COUNT))

      # Add to history
      echo "# $DATE — $NEW_COUNT new subdomains for $target" >> "$HISTORY_FILE"
      cat "$NEW_FILE" >> "$HISTORY_FILE"

      # Notify Discord
      NEW_LIST=$(head -10 "$NEW_FILE" | tr '\n' ', ' | sed 's/,$//')
      [ "$NEW_COUNT" -gt 10 ] && NEW_LIST="${NEW_LIST}... (+$((NEW_COUNT-10)) more)"
      notify_discord "🆕 **$target**: $NEW_COUNT new subdomains found: \`$NEW_LIST\`"
    else
      log "  No new subdomains (baseline: $(wc -l < "$CURRENT_FILE"))"
      rm -f "$NEW_FILE"
    fi
  else
    log "  First run — establishing baseline: $(wc -l < "$CURRENT_FILE") subdomains"
    cp "$CURRENT_FILE" "$HISTORY_FILE"
    notify_discord "📋 **$target**: baseline established — $(wc -l < "$CURRENT_FILE") subdomains"
  fi

  # ── Probe new subdomains for live HTTP/S ──────────────────────
  if [ -f "$NEW_FILE" ] && [ -s "$NEW_FILE" ] && command -v httpx >/dev/null 2>&1; then
    log "  httpx: probing new subdomains..."
    LIVE_FILE="${RECON_DIR}/new-live-${DATE}.txt"
    httpx -l "$NEW_FILE" -silent -o "$LIVE_FILE" \
      -title -status-code -follow-redirects \
      -timeout 10 -rate-limit 50 2>/dev/null || true
    LIVE_COUNT=$(wc -l < "$LIVE_FILE" 2>/dev/null || echo 0)
    [ "$LIVE_COUNT" -gt 0 ] && log "  httpx: $LIVE_COUNT live new services" \
                             || log "  httpx: no live services on new subdomains"
  fi

  # ── Subdomain takeover scan (subzy) ───────────────────────────
  if command -v subzy >/dev/null 2>&1; then
    log "  subzy: CNAME takeover scan..."
    TAKEOVER_FILE="${RECON_DIR}/takeover-${DATE}.txt"
    subzy run --targets "$CURRENT_FILE" \
      --output "$TAKEOVER_FILE" \
      --concurrency 20 \
      --https 2>/dev/null || true

    if [ -f "$TAKEOVER_FILE" ] && grep -qi "vulnerable\|VULNERABLE" "$TAKEOVER_FILE" 2>/dev/null; then
      TAKEOVER_COUNT=$(grep -ci "vulnerable" "$TAKEOVER_FILE" 2>/dev/null || echo 0)
      log "  TAKEOVER CANDIDATES: $TAKEOVER_COUNT — see $TAKEOVER_FILE"
      TOTAL_TAKEOVER=$((TOTAL_TAKEOVER + TAKEOVER_COUNT))
      notify_discord "🚨 **$target**: **$TAKEOVER_COUNT TAKEOVER CANDIDATES** found! Check \`${TAKEOVER_FILE}\`"
    else
      log "  subzy: no takeover candidates"
      rm -f "$TAKEOVER_FILE" 2>/dev/null || true
    fi
  fi

done <<< "$TARGETS"

# ─── Final summary ─────────────────────────────────────────────────
log ""
log "=== Monitor complete: $DATE ==="
log "  New subdomains: $TOTAL_NEW"
log "  Takeover candidates: $TOTAL_TAKEOVER"

if [ "$TOTAL_TAKEOVER" -gt 0 ]; then
  notify_discord "⚠️ **Monitor summary**: $TOTAL_NEW new subdomains, **$TOTAL_TAKEOVER takeover candidates**. Check Pi logs."
elif [ "$TOTAL_NEW" -gt 0 ]; then
  notify_discord "✅ **Monitor summary**: $TOTAL_NEW new subdomains, 0 takeovers."
fi

exit 0
