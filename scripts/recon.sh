#!/usr/bin/env bash
# recon.sh — Phase 1+2 recon pipeline, Raspberry Pi 5 tuned, scope-gated.
#
# Chains the arm64 toolchain into structured output under results/<target>/.
# Every active step is rate-capped for the Pi and the program's politeness rules.
#
# Usage:
#   ./scripts/recon.sh <target-root> [--passive-only]
#   RATE=100 THREADS=25 ./scripts/recon.sh example.com
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[recon]${NC} $*"; }
warn() { echo -e "${YELLOW}[recon]${NC} $*"; }
err()  { echo -e "${RED}[recon]${NC} $*" >&2; }

TARGET="${1:-}"
[ -n "$TARGET" ] || { err "usage: recon.sh <target-root> [--passive-only]"; exit 1; }
PASSIVE_ONLY=false
[ "${2:-}" = "--passive-only" ] && PASSIVE_ONLY=true

# --- Pi-5-tuned defaults (override via env). Conservative = stays invited. -----
RATE="${RATE:-100}"        # requests/sec ceiling for httpx/nuclei
THREADS="${THREADS:-25}"   # concurrency ceiling
NAABU_RATE="${NAABU_RATE:-300}"
WORDLIST="${WORDLIST:-$HOME/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt}"

# --- Scope gate (HARD). No scope, no recon. -----------------------------------
SCOPE_OUT="$("$SCRIPT_DIR/scope-check.sh" "$TARGET" || true)"
case "$SCOPE_OUT" in
  IN-SCOPE*) log "Scope OK: $SCOPE_OUT" ;;
  *) err "Refusing to run — $SCOPE_OUT"; err "Populate config/scope.yaml and ensure '$TARGET' is in scope."; exit 2 ;;
esac

OUT="$ROOT_DIR/results/$TARGET"
mkdir -p "$OUT/01-assets" "$OUT/02-surface"
log "Output → $OUT"

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Phase 1 — Asset discovery
# ---------------------------------------------------------------------------
log "Phase 1: subdomain enumeration (passive)…"
: > "$OUT/01-assets/subdomains.txt"
have subfinder && subfinder -d "$TARGET" -all -silent 2>/dev/null \
  | anew "$OUT/01-assets/subdomains.txt" >/dev/null || warn "subfinder missing/failed"
have assetfinder && assetfinder --subs-only "$TARGET" 2>/dev/null \
  | anew "$OUT/01-assets/subdomains.txt" >/dev/null || true
if have amass && [ "$PASSIVE_ONLY" = false ]; then
  log "  amass passive (may be slow on Pi)…"
  amass enum -passive -d "$TARGET" -timeout 10 2>/dev/null \
    | anew "$OUT/01-assets/subdomains.txt" >/dev/null || true
fi
echo "$TARGET" | anew "$OUT/01-assets/subdomains.txt" >/dev/null
log "  $(wc -l < "$OUT/01-assets/subdomains.txt") unique subdomains"

log "Phase 1: resolving (dnsx)…"
if have dnsx; then
  dnsx -l "$OUT/01-assets/subdomains.txt" -silent -t "$THREADS" -a -resp \
    -o "$OUT/01-assets/resolved.txt" 2>/dev/null || warn "dnsx failed"
else
  cp "$OUT/01-assets/subdomains.txt" "$OUT/01-assets/resolved.txt"
fi

log "Phase 1: historical URLs (gau/wayback)…"
{ have gau && gau --threads "$THREADS" "$TARGET" 2>/dev/null; \
  have waybackurls && waybackurls "$TARGET" 2>/dev/null; } \
  | sort -u > "$OUT/01-assets/historical-urls.txt" || true

# ---------------------------------------------------------------------------
# Phase 2 — Attack-surface mapping
# ---------------------------------------------------------------------------
log "Phase 2: probing live hosts (httpx, rate=$RATE)…"
if have httpx; then
  httpx -l "$OUT/01-assets/subdomains.txt" -silent \
    -rate-limit "$RATE" -threads "$THREADS" \
    -status-code -title -tech-detect -web-server -ip -cdn \
    -json -o "$OUT/02-surface/httpx.jsonl" 2>/dev/null || warn "httpx failed"
  have jq && jq -r '.url' "$OUT/02-surface/httpx.jsonl" 2>/dev/null \
    | sort -u > "$OUT/02-surface/live.txt" || true
  have jq && jq -s '[.[] | {url, status: .status_code, title, tech: .tech, server: .webserver}]' \
    "$OUT/02-surface/httpx.jsonl" > "$OUT/02-surface/tech.json" 2>/dev/null || true
else
  warn "httpx missing — skipping probe"
fi

if [ "$PASSIVE_ONLY" = false ]; then
  log "Phase 2: crawling for endpoints (katana, rate-capped)…"
  if have katana && [ -s "$OUT/02-surface/live.txt" ]; then
    katana -list "$OUT/02-surface/live.txt" -silent -d 2 -jc -kf all \
      -rate-limit "$RATE" -c "$THREADS" \
      -o "$OUT/02-surface/endpoints.txt" 2>/dev/null || warn "katana failed"
  fi

  log "Phase 2: top-port scan on resolved hosts (naabu)…"
  if have naabu && [ -s "$OUT/01-assets/subdomains.txt" ]; then
    naabu -list "$OUT/01-assets/subdomains.txt" -silent -top-ports 100 \
      -rate "$NAABU_RATE" -o "$OUT/02-surface/ports.txt" 2>/dev/null || warn "naabu failed"
  fi
fi

# Merge historical + crawled endpoints, extract JS for mining
log "Phase 2: consolidating endpoints + JS inventory…"
cat "$OUT/01-assets/historical-urls.txt" "$OUT/02-surface/endpoints.txt" 2>/dev/null \
  | sort -u > "$OUT/02-surface/all-endpoints.txt" || true
grep -iE '\.js(\?|$)' "$OUT/02-surface/all-endpoints.txt" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js-files.txt" || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
cat > "$OUT/02-surface/SUMMARY.txt" <<EOF
Recon summary for $TARGET  ($(date -u +%Y-%m-%dT%H:%M:%SZ))
  subdomains:       $(wc -l < "$OUT/01-assets/subdomains.txt" 2>/dev/null || echo 0)
  resolved:         $(wc -l < "$OUT/01-assets/resolved.txt" 2>/dev/null || echo 0)
  live hosts:       $(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)
  endpoints:        $(wc -l < "$OUT/02-surface/all-endpoints.txt" 2>/dev/null || echo 0)
  js files:         $(wc -l < "$OUT/02-surface/js-files.txt" 2>/dev/null || echo 0)
  historical urls:  $(wc -l < "$OUT/01-assets/historical-urls.txt" 2>/dev/null || echo 0)

Next: the agent should read these, classify anomalous hosts, mine JS, build
02-surface/priority.md, then run /hunt. See methodology/METHODOLOGY.md Phase 3.
EOF
log "Done. Summary:"; cat "$OUT/02-surface/SUMMARY.txt"
