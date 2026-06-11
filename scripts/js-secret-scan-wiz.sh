#!/usr/bin/env zsh
# JS secret scanning — wiz.io
# Input: list of JS file URLs from gau/waybackurls scan
# Output: secrets, internal endpoints, tokens found in JS
# Usage: zsh ~/bug-bounty-hunting-/scripts/js-secret-scan-wiz.sh [js-urls-file]
#
# JS URLs file: one URL per line, expected at:
#   ~/bug-bounty-hunting-/results/wiz.io/02-surface/js-files.txt

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns/js-secrets
JS_LIST="${1:-$HOME/bug-bounty-hunting-/results/wiz.io/02-surface/js-files.txt}"

mkdir -p "$RESULTS"

if [ ! -f "$JS_LIST" ]; then
  echo "JS URL list not found: $JS_LIST"
  echo "Try: find ~/bug-bounty-hunting-/results/wiz.io/ -name '*.txt' | xargs grep -l 'https.*\.js' | head -5"
  exit 1
fi

TOTAL=$(wc -l < "$JS_LIST")
echo "[*] Total JS URLs: $TOTAL"

# Prioritize production app JS files over CDN/vendor
PRIORITY_LIST=$(grep -E "(app\.wiz\.io|api\..*wiz\.io|portal)" "$JS_LIST" | grep -v "node_modules\|vendor\|jquery\|bootstrap\|lodash\|moment\|react\.production" | head -200)
PRIORITY_COUNT=$(echo "$PRIORITY_LIST" | wc -l)
echo "[*] Priority JS files (app.wiz.io / portal): $PRIORITY_COUNT"

# Regex patterns for secrets and internal endpoints
PATTERNS=(
  # API keys / tokens
  'Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}'
  'api[_-]?key["\s:=]+["\x27][A-Za-z0-9_-]{20,}'
  'secret[_-]?key["\s:=]+["\x27][A-Za-z0-9_+/]{20,}'
  'access[_-]?token["\s:=]+["\x27][A-Za-z0-9._-]{20,}'
  # Ghost Content API key (26 hex chars)
  '[a-f0-9]{26}'
  # AWS keys
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  # JWT patterns
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  # Internal endpoints
  'https?://[a-z0-9._-]*(internal|private|admin|dev|localhost)[a-z0-9._/-]*'
  'https?://[a-z0-9._-]*wiz\.io[/a-z0-9._-]{3,}'
  # Client IDs / secrets
  'client_id["\s:=]+["\x27][A-Za-z0-9._-]{10,}'
  'client_secret["\s:=]+["\x27][A-Za-z0-9._-]{10,}'
  # GraphQL introspection hint
  '__schema\|__type\|introspect'
  # Hardcoded credentials pattern
  'password["\s:=]+["\x27][^"\x27\s]{8,}'
)

fetch_and_scan() {
  local url="$1"
  local tmpfile=$(mktemp /tmp/wiz-js-XXXXXX)

  # Fetch with short timeout; skip if > 2MB
  curl -sk --connect-timeout 8 --max-time 15 --max-filesize 2000000 "$url" -o "$tmpfile" 2>/dev/null

  if [ ! -s "$tmpfile" ]; then
    rm -f "$tmpfile"
    return
  fi

  local found=0
  for pattern in "${PATTERNS[@]}"; do
    matches=$(grep -oE "$pattern" "$tmpfile" 2>/dev/null | sort -u | head -5)
    if [ -n "$matches" ]; then
      echo "=== MATCH in $url ==="
      echo "  PATTERN: $pattern"
      echo "$matches" | sed 's/^/  /'
      found=1
    fi
  done

  # Also extract all unique wiz.io URLs found in this JS
  wiz_urls=$(grep -oE 'https?://[a-z0-9._-]*wiz\.io[/a-z0-9._?&=-]*' "$tmpfile" 2>/dev/null | sort -u)
  if [ -n "$wiz_urls" ]; then
    echo "--- wiz.io URLs in $url ---"
    echo "$wiz_urls" | head -20
  fi

  rm -f "$tmpfile"
}

# Scan priority list first
echo ""
echo "[*] Scanning priority JS files..."
{
  echo "$PRIORITY_LIST" | while read -r url; do
    [ -n "$url" ] || continue
    fetch_and_scan "$url"
  done
} | tee "$RESULTS/priority-findings.txt"

# Count hits
HITS=$(grep -c "=== MATCH" "$RESULTS/priority-findings.txt" 2>/dev/null || echo 0)
echo ""
echo "[*] Priority scan complete. Potential secrets found: $HITS"

# If time permits, scan broader list (top 1000 by recency)
if [ "${SCAN_ALL:-0}" = "1" ]; then
  echo ""
  echo "[*] SCAN_ALL=1: scanning all $TOTAL JS files (may take a while)..."
  {
    cat "$JS_LIST" | while read -r url; do
      [ -n "$url" ] || continue
      fetch_and_scan "$url"
    done
  } | tee "$RESULTS/all-findings.txt"
fi

echo ""
echo "[*] Results in: $RESULTS/"
ls -la "$RESULTS/"

# Consolidate all wiz.io internal URLs discovered across JS
echo ""
echo "[*] Unique wiz.io URLs discovered in JS files:"
grep "wiz\.io" "$RESULTS/priority-findings.txt" 2>/dev/null | grep -v "=== MATCH\|PATTERN\|---" \
  | sort -u | grep -v "www\.wiz\.io\|app\.wiz\.io$\|wiz\.io/$" | head -50 \
  | tee "$RESULTS/js-discovered-endpoints.txt"
