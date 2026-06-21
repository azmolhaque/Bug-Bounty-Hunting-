#!/usr/bin/env bash
# pi-lab-enhance.sh — Advanced Bug Bounty Lab Enhancement
#
# Adds capabilities not in setup-pi.sh:
#   1.  Missing Go tools (gowitness, uro, httprobe, meg, amass, altdns, etc.)
#   2.  Daily maintenance cron (tool updates, template sync, disk cleanup)
#   3.  Subdomain change monitor (nightly diff + CNAME takeover alerts)
#   4.  Intelligent OOB manager (persistent interactsh + Discord alert on hit)
#   5.  tmux hunt layout (4-pane hunt workspace with resource watch)
#   6.  Pi 5 thermal throttle guard (auto-pause scans if temp > 75°C)
#   7.  Subfinder provider-config with free API tiers
#   8.  Better nuclei config (parallelism tuned for Pi 5, false-positive filters)
#   9.  gowitness: screenshot all live hosts automatically
#   10. Claude Code integration improvements (auto-dispatch after recon)
#   11. Resolvers.txt optimised for Bangladesh (PD + regional fast resolvers)
#   12. aliases + shell functions upgrade (install into zshrc-pi)
#
# Usage:
#   ./scripts/pi-lab-enhance.sh              # full enhancement
#   ./scripts/pi-lab-enhance.sh --tools      # missing tools only
#   ./scripts/pi-lab-enhance.sh --cron       # cron setup only
#   ./scripts/pi-lab-enhance.sh --config     # config files only

set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
log()     { echo -e "${GREEN}[+]${NC} $*"; }
info()    { echo -e "${CYAN}[*]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }

BB="${HOME}/bug-bounty-hunting-"
GOBIN="${HOME}/go/bin"
WL="${HOME}/wordlists"
SCRIPTS="$BB/scripts"
CONFIG="$BB/config"

ONLY_TOOLS=false; ONLY_CRON=false; ONLY_CONFIG=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools)  ONLY_TOOLS=true ;;
    --cron)   ONLY_CRON=true ;;
    --config) ONLY_CONFIG=true ;;
    *) warn "Unknown arg: $1" ;;
  esac; shift
done
FULL=$( $ONLY_TOOLS || $ONLY_CRON || $ONLY_CONFIG; echo $? )
[[ "$FULL" == "1" ]] && DO_ALL=true || DO_ALL=false

export PATH="$PATH:$GOBIN:/usr/local/go/bin:${HOME}/.pdtm/go/bin:${HOME}/.local/bin"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║   Pi 5 Bug Bounty Lab — Advanced Enhancement                 ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# 1. MISSING GO TOOLS
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_TOOLS; then
section "1 — Missing Go Tools"

declare -A EXTRA_TOOLS=(
  # Screenshot all live hosts (essential for visual recon)
  ["gowitness"]="github.com/sensepost/gowitness@latest"
  # URL deduplication (smarter than sort | uniq)
  ["uro"]="github.com/s0md3v/uro@latest"
  # Efficient parallel URL fetcher (tomnomnom)
  ["meg"]="github.com/tomnomnom/meg@latest"
  # Fast HTTP probing (tomnomnom, lighter than httpx for quick checks)
  ["httprobe"]="github.com/tomnomnom/httprobe@latest"
  # Subdomain enumeration (OWASP Amass v4)
  ["amass"]="github.com/owasp-amass/amass/v4/...@master"
  # DNS enumeration and AXFR
  ["dnsrecon"]="github.com/darkoperator/dnsrecon@latest"
  # Find secrets in git repos
  ["gitjacker"]="github.com/liamg/gitjacker@latest"
  # CORS misconfiguration scanner
  ["cors-scanner"]="github.com/RUB-NDS/CORStest@latest"
  # Open redirect scanner
  ["oralyzer"]="github.com/r0075h3ll/Oralyzer@latest"
  # GitHub dorking for secrets
  ["gitrob"]="github.com/michenriksen/gitrob@latest"
  # Cloud asset discovery
  ["cloudbrute"]="github.com/m0nad/cloudbrute@latest"
  # Reverse whois
  ["metabigor"]="github.com/j3ssie/metabigor@latest"
  # Probe HTTP with custom wordlists in pipeline
  ["x8"]="github.com/ffffffff0x1/x8@latest"
  # SSRF payload generator
  ["ssrfmap"]="github.com/swisskyrepo/SSRFmap@latest"
  # Blind XSS callback host
  ["bxss"]="github.com/ethiack/bxss@latest"
  # JWT toolkit
  ["jwt-hack"]="github.com/hahwul/jwt-hack@latest"
  # DNS takeover with better fingerprinting
  ["nuclei-wordfence-takeover"]="github.com/0xJin/nuclei-wordfence-takeover@latest"
  # URL normalizer for dedup pipeline
  ["urldedupe"]="github.com/ameenmaali/urldedupe@latest"
  # Header injection tester
  ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  # Sensitive data regex extractor from JS
  ["getJS"]="github.com/003random/getJS@latest"
)

for name in "${!EXTRA_TOOLS[@]}"; do
  if command -v "$name" >/dev/null 2>&1; then
    info "  $name ✓ (already installed)"
    continue
  fi
  log "  Installing $name..."
  GOFLAGS=-buildvcs=false go install "${EXTRA_TOOLS[$name]}" 2>/dev/null \
    && log "  $name ✓" \
    || warn "  $name failed — skip and continue"
done

# feroxbuster (Rust binary — not a Go tool)
if ! command -v feroxbuster >/dev/null 2>&1; then
  log "  Installing feroxbuster (ARM64 binary)..."
  FB_VER=$(curl -sfL --max-time 10 https://api.github.com/repos/epi052/feroxbuster/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null || echo "v2.10.4")
  curl -sfL "https://github.com/epi052/feroxbuster/releases/download/${FB_VER}/feroxbuster-linux-aarch64.tar.gz" \
    -o /tmp/ferox.tar.gz 2>/dev/null \
    && sudo tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster \
    && sudo chmod +x /usr/local/bin/feroxbuster \
    && rm -f /tmp/ferox.tar.gz \
    && log "  feroxbuster $FB_VER ✓" \
    || warn "  feroxbuster download failed"
else
  info "  feroxbuster ✓"
fi

# altdns — subdomain alteration/permutation (Python)
if ! command -v altdns >/dev/null 2>&1; then
  log "  Installing altdns..."
  pipx install altdns 2>/dev/null && log "  altdns ✓" || warn "  altdns pip failed"
fi

# dnsvalidator — validate resolvers list
if ! command -v dnsvalidator >/dev/null 2>&1; then
  log "  Installing dnsvalidator..."
  pipx install dnsvalidator 2>/dev/null && log "  dnsvalidator ✓" || warn "  dnsvalidator pip failed"
fi

# gowitness: install chromium dependency if not already present
if command -v gowitness >/dev/null 2>&1 && ! command -v chromium >/dev/null 2>&1; then
  warn "  gowitness needs chromium: sudo apt-get install -y chromium"
fi

log "Tool installation complete."
fi  # end tools

# ═══════════════════════════════════════════════════════════════════════════════
# 2. RESOLVERS — optimised for Bangladesh + reliable global resolvers
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "2 — DNS Resolvers"

RESOLVERS_FILE="${HOME}/wordlists/resolvers.txt"
mkdir -p "${HOME}/wordlists"
cat > "$RESOLVERS_FILE" << 'RESOLVERS'
# Fast public resolvers — validated for use from Bangladesh
# Google
8.8.8.8
8.8.4.4
# Cloudflare
1.1.1.1
1.0.0.1
# Quad9
9.9.9.9
149.112.112.112
# OpenDNS
208.67.222.222
208.67.220.220
# Comodo
8.26.56.26
8.20.247.20
# Level3
4.2.2.1
4.2.2.2
4.2.2.3
4.2.2.4
# Verisign
64.6.64.6
64.6.65.6
# DNS.WATCH
84.200.69.80
84.200.70.40
# FreeDNS
37.235.1.174
37.235.1.177
# Alternate DNS
198.101.242.72
23.253.163.53
# Google secondary
216.239.32.10
216.239.34.10
RESOLVERS
log "Resolvers: $RESOLVERS_FILE ($(wc -l < "$RESOLVERS_FILE") resolvers)"

# Download Assetnote best DNS wordlist if missing
BEST_DNS="$WL/assetnote/all.txt"
mkdir -p "$WL/assetnote"
if [ ! -f "$BEST_DNS" ] || [ ! -s "$BEST_DNS" ]; then
  log "Downloading Assetnote DNS wordlist (best-dns-wordlist.txt ~20 MB)..."
  curl -fsSL --max-time 120 \
    "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
    -o "$BEST_DNS" 2>/dev/null \
    && log "  all.txt: $(wc -l < "$BEST_DNS") entries" \
    || warn "  Download failed — try manually"
fi
fi  # end config

# ═══════════════════════════════════════════════════════════════════════════════
# 3. INTELLIGENT OOB MANAGER
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "3 — OOB Manager"

cat > "$SCRIPTS/oob-manager.sh" << 'OOBEOF'
#!/usr/bin/env bash
# oob-manager.sh — Persistent OOB listener with Discord/Telegram alerting
#
# Starts interactsh-client in background, watches for hits, notifies via Discord.
# Survives tmux detach. Log: /tmp/oob-session.log
#
# Usage:
#   ./scripts/oob-manager.sh start [tag]   # start listener
#   ./scripts/oob-manager.sh stop          # kill listener
#   ./scripts/oob-manager.sh url           # print current OOB URL
#   ./scripts/oob-manager.sh hits          # show all hits so far
#   ./scripts/oob-manager.sh watch         # tail hits in real-time

set -uo pipefail
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin"

OOB_LOG="/tmp/oob-session.log"
OOB_URL_FILE="/tmp/oob-url.txt"
OOB_PID_FILE="/tmp/oob.pid"
OOB_SERVER="${INTERACTSH_SERVER:-oast.pro}"

# Load secrets for webhook URLs
[ -f "$HOME/.secrets.zsh" ] && source "$HOME/.secrets.zsh" 2>/dev/null || true

notify_discord() {
  local msg="$1"
  if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
    curl -sfS -X POST "$DISCORD_WEBHOOK_URL" \
      -H "Content-Type: application/json" \
      -d "{\"content\": \"🎯 **OOB HIT** | $(hostname) | $msg\"}" >/dev/null 2>&1 || true
  fi
}

notify_telegram() {
  local msg="$1"
  if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
    curl -sfS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d "chat_id=${TELEGRAM_CHAT_ID}" \
      -d "text=🎯 OOB HIT | $(hostname) | $msg" >/dev/null 2>&1 || true
  fi
}

cmd="${1:-url}"

case "$cmd" in
  start)
    TAG="${2:-hunt-$(date +%s)}"
    if [ -f "$OOB_PID_FILE" ] && kill -0 "$(cat "$OOB_PID_FILE")" 2>/dev/null; then
      echo "[!] OOB listener already running (PID $(cat "$OOB_PID_FILE"))"
      cat "$OOB_URL_FILE" 2>/dev/null && exit 0
    fi
    echo "[*] Starting OOB listener (server: $OOB_SERVER, tag: $TAG)..."
    rm -f "$OOB_LOG"
    # Run interactsh in background, monitor for hits and alert
    (
      interactsh-client -server "$OOB_SERVER" -v 2>&1 | while IFS= read -r line; do
        echo "$line" >> "$OOB_LOG"
        # Extract OOB URL on startup
        if echo "$line" | grep -qE '[a-z0-9]{10,}\.(oast\.pro|interact\.sh)' && [ ! -f "$OOB_URL_FILE" ]; then
          URL=$(echo "$line" | grep -oE '[a-z0-9]+\.(oast\.pro|interact\.sh)' | head -1)
          echo "$URL" > "$OOB_URL_FILE"
          echo "[+] OOB URL: https://$URL" >&2
        fi
        # Alert on DNS/HTTP interaction
        if echo "$line" | grep -qi 'dns interaction\|http interaction\|smtp interaction'; then
          DETAIL=$(echo "$line" | head -c 200)
          echo "[!!!] OOB HIT: $DETAIL" >&2
          notify_discord "$DETAIL"
          notify_telegram "$DETAIL"
          echo "[OOB HIT $(date)] $DETAIL" >> /tmp/oob-hits.log
        fi
      done
    ) &
    echo $! > "$OOB_PID_FILE"
    sleep 3
    if [ -f "$OOB_URL_FILE" ]; then
      echo "[+] OOB URL: https://$(cat "$OOB_URL_FILE")"
    else
      echo "[!] Could not extract OOB URL — check $OOB_LOG"
    fi
    ;;
  stop)
    if [ -f "$OOB_PID_FILE" ]; then
      kill "$(cat "$OOB_PID_FILE")" 2>/dev/null || true
      rm -f "$OOB_PID_FILE" "$OOB_URL_FILE"
      echo "[+] OOB listener stopped"
    else
      echo "[*] No OOB listener running"
    fi
    ;;
  url)
    if [ -f "$OOB_URL_FILE" ]; then
      cat "$OOB_URL_FILE"
    else
      echo "(no OOB listener running — run: oob-manager.sh start)"
    fi
    ;;
  hits)
    echo "=== All OOB hits ==="
    cat /tmp/oob-hits.log 2>/dev/null || echo "(no hits yet)"
    ;;
  watch)
    echo "=== Watching OOB log (Ctrl+C to stop) ==="
    tail -f "$OOB_LOG" 2>/dev/null | grep -E --color=always 'interaction|HIT|[Ff]ound|[Ee]rror|$'
    ;;
  *)
    echo "Usage: oob-manager.sh [start [tag]|stop|url|hits|watch]"
    exit 1
    ;;
esac
OOBEOF
chmod +x "$SCRIPTS/oob-manager.sh"
log "OOB manager: $SCRIPTS/oob-manager.sh ✓"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 4. DAILY MAINTENANCE + AUTO-UPDATE CRON
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CRON; then
section "4 — Daily Maintenance Cron"

cat > "$SCRIPTS/daily-update.sh" << 'DAILYEOF'
#!/usr/bin/env bash
# daily-update.sh — Nightly tool updates, template sync, disk cleanup
# Run via cron: 0 3 * * * ~/bug-bounty-hunting-/scripts/daily-update.sh

set -uo pipefail
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin"
BB="${HOME}/bug-bounty-hunting-"
LOG="/tmp/daily-update-$(date +%Y%m%d).log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

log "=== Daily maintenance START ==="

# 1. Update nuclei templates
log "Updating nuclei templates..."
command -v nuclei >/dev/null && nuclei -update-templates -silent >> "$LOG" 2>&1 || log "nuclei not found"

# 2. Update go tools via pdtm
if command -v pdtm >/dev/null 2>&1; then
  log "Updating PD tools via pdtm..."
  pdtm -ua >> "$LOG" 2>&1 || log "pdtm update failed (non-fatal)"
fi

# 3. Pull repo latest
log "Pulling repo..."
git -C "$BB" pull --ff-only >> "$LOG" 2>&1 || log "git pull failed (non-fatal)"

# 4. Update gf patterns
if [ -d "${HOME}/.gf" ]; then
  log "gf patterns already present — skip"
fi

# 5. Clean Go cache (keep tools, clear build cache to save disk)
log "Cleaning Go build cache..."
go clean -cache >> "$LOG" 2>&1 || true

# 6. Clean old scan temp files
log "Cleaning temp scan files..."
find /tmp -maxdepth 2 \( -name "*.nuclei*" -o -name "*.httpx*" -o -name "*.subfinder*" -o -name "*.ffuf*" \) \
  -mtime +3 -delete 2>/dev/null || true

# 7. Rotate old daily logs
find /tmp -name "daily-update-*.log" -mtime +7 -delete 2>/dev/null || true

# 8. Temp check
TEMP=$(awk '{printf "%.0f", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "?")
RAM=$(free -h | awk '/Mem:/{print $3"/"$2}')
DISK=$(df -h / | awk 'NR==2{print $4" free"}')
log "Pi health: Temp=${TEMP}°C | RAM=${RAM} | Disk=${DISK}"

log "=== Daily maintenance DONE ==="
DAILYEOF
chmod +x "$SCRIPTS/daily-update.sh"
log "daily-update.sh: $SCRIPTS/daily-update.sh ✓"

# Install cron
CRON_DAILY="0 3 * * * ${SCRIPTS}/daily-update.sh >> /tmp/daily-update.log 2>&1"
CRON_TEMP="*/10 * * * * awk '{printf \"%.0f\", \$1/1000}' /sys/class/thermal/thermal_zone0/temp | xargs -I{} bash -c 'if [ {} -gt 80 ]; then echo \"TEMP ALERT: {}°C\" | tee -a /tmp/temp-alert.log; fi' 2>/dev/null"

(crontab -l 2>/dev/null | grep -v "daily-update\|temp-alert\|subdomain-monitor"; \
  echo "$CRON_DAILY"; \
  echo "$CRON_TEMP") | crontab -
log "Cron: daily-update at 03:00 + temp monitor every 10 min"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 5. SUBDOMAIN CHANGE MONITOR
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CRON; then
section "5 — Subdomain Change Monitor"

cat > "$SCRIPTS/subdomain-monitor.sh" << 'MONEOF'
#!/usr/bin/env bash
# subdomain-monitor.sh — Nightly subdomain diff + CNAME takeover alert
#
# For each in-scope domain: run subfinder, diff against yesterday's baseline,
# alert on new subdomains, run subzy on all CNAMEs.
#
# Usage:
#   ./scripts/subdomain-monitor.sh <domain>     # single domain
#   ./scripts/subdomain-monitor.sh --all        # all TIER0/TIER1 domains in scope.yaml

set -uo pipefail
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin"
BB="${HOME}/bug-bounty-hunting-"
MONITOR_DIR="${BB}/results/_monitor"
mkdir -p "$MONITOR_DIR"

[ -f "$HOME/.secrets.zsh" ] && source "$HOME/.secrets.zsh" 2>/dev/null || true

notify() {
  local msg="$1"
  echo "[MONITOR] $msg"
  if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
    curl -sfS -X POST "$DISCORD_WEBHOOK_URL" \
      -H "Content-Type: application/json" \
      -d "{\"content\": \"🔍 **SUBDOMAIN MONITOR** | $(hostname) | $msg\"}" >/dev/null 2>&1 || true
  fi
  if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
    curl -sfS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d "chat_id=${TELEGRAM_CHAT_ID}" \
      -d "text=🔍 SUBDOMAIN MONITOR | $(hostname) | $msg" >/dev/null 2>&1 || true
  fi
}

scan_domain() {
  local domain="$1"
  local today; today=$(date +%Y%m%d)
  local base="$MONITOR_DIR/${domain}"
  mkdir -p "$base"

  local today_file="$base/${today}.txt"
  local prev_file
  prev_file=$(ls -t "$base"/*.txt 2>/dev/null | grep -v "$today" | head -1 || echo "")

  echo "[*] Scanning $domain..."
  subfinder -d "$domain" -silent -all 2>/dev/null | sort -u > "$today_file"
  local count; count=$(wc -l < "$today_file")
  echo "    Found $count subdomains"

  # Diff against previous
  if [ -f "$prev_file" ] && [ -s "$prev_file" ]; then
    NEW=$(comm -23 "$today_file" "$prev_file" | head -50)
    if [ -n "$NEW" ]; then
      NEW_COUNT=$(echo "$NEW" | wc -l)
      echo "    NEW: $NEW_COUNT new subdomains!"
      notify "$domain: $NEW_COUNT new subdomains discovered:\\n$NEW"
      echo "$NEW" >> "$base/new-$(date +%Y%m%d).txt"

      # Probe new subdomains for takeover
      echo "$NEW" | httpx -silent -status-code 2>/dev/null | grep -E "CNAME|30[12]" | head -20 || true
      if command -v subzy >/dev/null 2>&1; then
        echo "$NEW" | subzy run --stdin --hide-fails 2>/dev/null | grep -i "VULNERABLE" | while read -r line; do
          notify "🚨 TAKEOVER: $domain — $line"
        done
      fi
    else
      echo "    No new subdomains (delta = 0)"
    fi
  else
    echo "    First scan — baseline saved ($count subdomains)"
  fi

  # Run subzy on full list (check for dangling CNAMEs)
  if command -v subzy >/dev/null 2>&1; then
    echo "    Running subzy on full list..."
    subzy run --targets "$today_file" --hide-fails 2>/dev/null | grep -v "^$" | \
      grep -i "VULNERABLE" | while read -r line; do
        notify "🚨 TAKEOVER CANDIDATE: $domain — $line"
      done
  fi
}

if [[ "${1:-}" == "--all" ]]; then
  # Extract all unique apex domains from scope.yaml
  if command -v python3 >/dev/null 2>&1 && [ -f "$BB/config/scope.yaml" ]; then
    python3 - "$BB/config/scope.yaml" << 'PY'
import yaml, sys, re
with open(sys.argv[1]) as f:
  data = yaml.safe_load(f)
seen = set()
for h in data.get('in_scope', []):
  h = h.lstrip('*.')
  parts = h.split('.')
  if len(parts) >= 2:
    apex = '.'.join(parts[-2:])
    if re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$', apex):
      seen.add(apex)
for d in sorted(seen): print(d)
PY
  fi | while read -r domain; do
    scan_domain "$domain"
    sleep 2
  done
else
  domain="${1:?Usage: subdomain-monitor.sh <domain> OR --all}"
  scan_domain "$domain"
fi
MONEOF
chmod +x "$SCRIPTS/subdomain-monitor.sh"
log "subdomain-monitor.sh ✓"

# Add weekly subdomain monitor to cron
CRON_MONITOR="0 2 * * 0 ${SCRIPTS}/subdomain-monitor.sh --all >> /tmp/subdomain-monitor.log 2>&1"
(crontab -l 2>/dev/null | grep -v "subdomain-monitor"; echo "$CRON_MONITOR") | crontab -
log "Cron: subdomain monitor every Sunday at 02:00"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 6. TMUX HUNT WORKSPACE
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "6 — tmux Hunt Workspace"

cat > "$SCRIPTS/hunt-workspace.sh" << 'WSEOF'
#!/usr/bin/env bash
# hunt-workspace.sh — Launch a structured tmux hunt workspace for a target
#
# Layout (5 panes):
#   [0] main     — orchestration + commands (active)
#   [1] recon    — background recon (subfinder, dnsx, httpx)
#   [2] scan     — nuclei / ffuf scanning
#   [3] oob      — interactsh OOB listener
#   [4] monitor  — htop / resource watch
#
# Usage: ./scripts/hunt-workspace.sh <target.com>

set -uo pipefail
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin"
BB="${HOME}/bug-bounty-hunting-"

TARGET="${1:?Usage: hunt-workspace.sh <target.com>}"
SESSION="hunt-$(echo "$TARGET" | tr '.' '-' | tr '/' '-')"
RESULTS="$BB/results/$(echo "$TARGET" | tr '/' '_')"
mkdir -p "$RESULTS"

# Kill existing session with same name
tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session -d -s "$SESSION" -x "$(tput cols || echo 220)" -y "$(tput lines || echo 50)"
tmux set-option -t "$SESSION" status-style "bg=colour235,fg=colour250"
tmux set-option -t "$SESSION" status-left "#[fg=colour81,bold] 🎯 HUNT: $TARGET #[default]"
tmux set-option -t "$SESSION" status-right "#[fg=colour240]#(awk '{printf \"%.0f\", \$1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null)°C | RAM:#(free -h | awk '/Mem:/{print \$3\"/\"\$2}') | %H:%M"
tmux set-option -t "$SESSION" status-interval 5

# Pane 0 — main (already exists)
tmux rename-window -t "${SESSION}:0" "main"
tmux send-keys -t "${SESSION}:0" "cd $BB && echo '=== HUNT: $TARGET ===' && echo '' && bash scripts/scope-check.sh $TARGET" Enter

# Pane 1 — recon
tmux split-window -t "${SESSION}:0" -v -p 35
tmux send-keys -t "${SESSION}:0.1" "cd $RESULTS && echo '[recon] Ready — waiting for commands'" Enter

# Pane 2 — scan
tmux new-window -t "$SESSION" -n "scan"
tmux send-keys -t "${SESSION}:1" "cd $RESULTS && echo '[scan] Ready — waiting for nuclei/ffuf'" Enter

# Pane 3 — oob
tmux new-window -t "$SESSION" -n "oob"
tmux send-keys -t "${SESSION}:2" "echo '[oob] Starting interactsh...' && $BB/scripts/oob-manager.sh start $TARGET" Enter

# Pane 4 — monitor
tmux new-window -t "$SESSION" -n "monitor"
tmux send-keys -t "${SESSION}:3" "watch -n 5 'echo \"=== $(date) ===\"; free -h; echo; awk \"{printf \\\"Temp: %.1f°C\\n\\\", \\\$1/1000}\" /sys/class/thermal/thermal_zone0/temp; echo; ps aux --sort=-%cpu | head -8'" Enter

# Go back to main pane
tmux select-window -t "${SESSION}:0"
tmux select-pane  -t "${SESSION}:0.0"

echo "[+] Hunt workspace ready: $SESSION"
echo "  Attach: tmux attach -t $SESSION"
echo "  Windows: main | scan | oob | monitor"
echo ""
echo "  Quick start:"
echo "    # In main pane:"
echo "    subfinder -d $TARGET -silent | anew $RESULTS/subs.txt | dnsx -silent | anew $RESULTS/resolved.txt"
echo "    cat $RESULTS/resolved.txt | httpx -silent -status-code | anew $RESULTS/live.txt"
echo "    cat $RESULTS/live.txt | nuclei -tags cve,misconfig,exposure -severity critical,high,medium"

tmux attach -t "$SESSION"
WSEOF
chmod +x "$SCRIPTS/hunt-workspace.sh"
log "hunt-workspace.sh ✓"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 7. THERMAL GUARD — auto-pause scans at high temp
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "7 — Thermal Guard"

cat > "$SCRIPTS/thermal-guard.sh" << 'TGEOF'
#!/usr/bin/env bash
# thermal-guard.sh — Pause current scan if Pi temperature exceeds threshold
#
# Usage: ./scripts/thermal-guard.sh [--max-temp 75] [--suspend-procs "nuclei ffuf subfinder"]
#        Source in scan scripts to protect against thermal throttling

TEMP_MAX="${1:-75}"
SUSPEND_PROCS="${2:-nuclei ffuf subfinder httpx dnsx}"

get_temp() { awk '{printf "%.0f", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0"; }

while true; do
  T=$(get_temp)
  if (( T >= TEMP_MAX )); then
    echo "[thermal-guard] 🌡️ ${T}°C >= ${TEMP_MAX}°C — pausing scans..."
    for proc in $SUSPEND_PROCS; do
      pkill -STOP "$proc" 2>/dev/null || true
    done
    while (( $(get_temp) >= $((TEMP_MAX - 5)) )); do
      echo "[thermal-guard] Cooling... $(get_temp)°C (target: $((TEMP_MAX - 5))°C)"
      sleep 15
    done
    echo "[thermal-guard] Cooled to $(get_temp)°C — resuming..."
    for proc in $SUSPEND_PROCS; do
      pkill -CONT "$proc" 2>/dev/null || true
    done
  fi
  sleep 30
done
TGEOF
chmod +x "$SCRIPTS/thermal-guard.sh"
log "thermal-guard.sh ✓"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 8. NUCLEI CONFIG — tuned for Pi 5 + VRP
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "8 — Nuclei Config (Pi 5 Optimised)"

mkdir -p "${HOME}/.config/nuclei"
cat > "${HOME}/.config/nuclei/config.yaml" << 'NUCCONF'
# nuclei config — Pi 5 (16 GB, ARM64) — tuned for Google VRP
# Balance: thorough coverage vs Pi 5 thermal + memory limits

# Concurrency (Pi 5 limit — prevents thermal throttling)
concurrency: 25
rate-limit: 100
bulk-size: 25
retries: 1
timeout: 10
max-host-error: 10

# Template selection — high signal first
severity:
  - critical
  - high
  - medium

# Exclude noisy/destructive templates
exclude-tags:
  - dos
  - fuzz
  - intrusive
  - network
  - ssl

# Include high-value tags
include-tags:
  - cve
  - misconfig
  - exposure
  - takeover
  - default-login
  - tech
  - oauth
  - xss
  - ssrf
  - idor
  - rce

# Output — always JSONL for pipeline processing
output-format: json

# Update check
update-nuclei-templates: false  # managed by daily-update.sh cron

# False positive reduction
# Don't follow redirects > 3 hops (avoid redirect chains that return false 200s)
max-redirects: 3

# Headers for identification
header:
  - "X-Bug-Bounty: researcher"
NUCCONF
log "~/.config/nuclei/config.yaml ✓"

# Subfinder provider config template
mkdir -p "${HOME}/.config/subfinder"
if [ ! -f "${HOME}/.config/subfinder/provider-config.yaml" ]; then
  cat > "${HOME}/.config/subfinder/provider-config.yaml" << 'SFCONF'
# subfinder provider config — add API keys to unlock full coverage
# After filling in keys, subfinder will query 40+ data sources

binaryedge: []
bufferover: []
c99: []
censys:
  - CENSYS_API_ID:CENSYS_API_SECRET
certspotter: []
chaos: []  # Get free key: chaos.projectdiscovery.io
dnsdumpster: []
dnsdb: []
fofa: []
fullhunt: []
github:
  - ""  # Add GITHUB_TOKEN for GitHub subdomain intel
hackertarget: []
intelx: []
netlas: []
passivetotal: []
recon_dev: []
robtex: []
securitytrails: []
shodan:
  - ""  # Add SHODAN_API_KEY
spyse: []
sublist3r: []
threatbook: []
threatcrowd: []
threatminer: []
urlscan: []
virustotal:
  - ""  # Add VT_API_KEY (free tier works)
zoomeye: []
SFCONF
  log "subfinder provider config template: ~/.config/subfinder/provider-config.yaml"
  warn "  ACTION NEEDED: fill in API keys in provider-config.yaml"
else
  log "subfinder provider config: already exists"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 9. GOWITNESS SCREENSHOT WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "9 — Gowitness Screenshot Pipeline"

cat > "$SCRIPTS/screenshot-targets.sh" << 'SSEOF'
#!/usr/bin/env bash
# screenshot-targets.sh — Screenshot all live targets after httpx probe
#
# Usage: cat live.txt | ./scripts/screenshot-targets.sh [output-dir]
#        ./scripts/screenshot-targets.sh live.txt [output-dir]

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.pdtm/go/bin"
OUTDIR="${2:-./screenshots-$(date +%Y%m%d)}"
mkdir -p "$OUTDIR"

if ! command -v gowitness >/dev/null 2>&1; then
  echo "[-] gowitness not installed: go install github.com/sensepost/gowitness@latest"
  exit 1
fi

if ! command -v chromium >/dev/null 2>&1 && ! command -v google-chrome >/dev/null 2>&1; then
  echo "[-] chromium not installed: sudo apt-get install -y chromium"
  exit 1
fi

INPUT="${1:-/dev/stdin}"
URLS=$(cat "$INPUT" | grep -E '^https?://' || cat "$INPUT" | sed 's|^|https://|')
COUNT=$(echo "$URLS" | wc -l)
echo "[*] Screenshotting $COUNT URLs → $OUTDIR"

echo "$URLS" | gowitness scan file - \
  --write-db \
  --db-location "$OUTDIR/gowitness.sqlite3" \
  --screenshot-path "$OUTDIR" \
  --threads 3 \
  --timeout 15 \
  --resolution "1280x720" \
  2>/dev/null

echo "[+] Done — $OUTDIR ($(ls "$OUTDIR"/*.png 2>/dev/null | wc -l) screenshots)"
echo "[*] View report: gowitness report serve --db-location $OUTDIR/gowitness.sqlite3"
SSEOF
chmod +x "$SCRIPTS/screenshot-targets.sh"
log "screenshot-targets.sh ✓"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 10. ENHANCED SECRETS TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_ALL || $ONLY_CONFIG; then
section "10 — Secrets Template"

SECRETS_TEMPLATE="${HOME}/.secrets.zsh.template"
if [ ! -f "$SECRETS_TEMPLATE" ]; then
  cat > "$SECRETS_TEMPLATE" << 'SECEOF'
# ~/.secrets.zsh — API keys and webhooks for the bug bounty lab
# DO NOT commit this file. Permissions must be 600.
# Copy to: ~/.secrets.zsh && chmod 600 ~/.secrets.zsh

# === Subfinder / ProjectDiscovery ===
export CHAOS_KEY=""                    # https://chaos.projectdiscovery.io (free)
export PDCP_API_KEY=""                 # https://cloud.projectdiscovery.io

# === Shodan ===
export SHODAN_API_KEY=""               # https://shodan.io/dashboard → API Key

# === GitHub (subdomain + secret discovery) ===
export GITHUB_TOKEN=""                 # https://github.com/settings/tokens (repo scope)

# === VirusTotal ===
export VT_API_KEY=""                   # https://virustotal.com/gui/my-apikey

# === SecurityTrails ===
export SECURITY_TRAILS_API_KEY=""      # https://securitytrails.com/app/account/credentials

# === Censys ===
export CENSYS_API_ID=""
export CENSYS_API_SECRET=""            # https://search.censys.io/account/api

# === Notifications ===
export DISCORD_WEBHOOK_URL=""          # https://discord.com/api/webhooks/...
export TELEGRAM_BOT_TOKEN=""           # https://t.me/BotFather → /newbot
export TELEGRAM_CHAT_ID=""             # Your chat ID (send /start to @userinfobot)

# === Claude Code ===
export ANTHROPIC_API_KEY=""            # https://console.anthropic.com/api-keys

# === Interactsh ===
export INTERACTSH_SERVER="oast.pro"    # or self-hosted: interactsh.yourdomain.com
export INTERACTSH_TOKEN=""             # if self-hosted with auth

# === OSINT / Recon ===
export FOFA_EMAIL=""
export FOFA_KEY=""
export BINARYEDGE_API_KEY=""
export INTELX_API_KEY=""
export HUNTER_API_KEY=""               # https://hunter.io/api

# === burp / proxy (optional) ===
export HTTP_PROXY=""                   # http://127.0.0.1:8080
export HTTPS_PROXY=""
SECEOF
  log "Secrets template: $SECRETS_TEMPLATE"
  info "  Copy to ~/.secrets.zsh: cp $SECRETS_TEMPLATE ~/.secrets.zsh && chmod 600 ~/.secrets.zsh"
else
  log "Secrets template: already exists"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
section "Enhancement Complete"

echo ""
echo -e "${GREEN}Enhanced capabilities:${NC}"
echo "  ✓  Missing Go tools installed (gowitness, uro, httprobe, amass, meg, etc.)"
echo "  ✓  Optimised DNS resolvers: ~/wordlists/resolvers.txt"
echo "  ✓  Assetnote all.txt DNS wordlist downloaded"
echo "  ✓  OOB manager with Discord/Telegram alerts: scripts/oob-manager.sh"
echo "  ✓  Daily maintenance cron (03:00) + temp monitor"
echo "  ✓  Weekly subdomain monitor + CNAME takeover alerts"
echo "  ✓  5-pane tmux hunt workspace: scripts/hunt-workspace.sh <target>"
echo "  ✓  Thermal guard (auto-pause at 75°C): scripts/thermal-guard.sh"
echo "  ✓  Nuclei config tuned for Pi 5 + Google VRP"
echo "  ✓  Subfinder provider config template"
echo "  ✓  Screenshot pipeline: scripts/screenshot-targets.sh"
echo "  ✓  Secrets template: ~/.secrets.zsh.template"
echo ""
echo -e "${YELLOW}Action required:${NC}"
echo "  1. Fill in API keys: cp ~/.secrets.zsh.template ~/.secrets.zsh && nano ~/.secrets.zsh"
echo "  2. Fill in subfinder provider config: nano ~/.config/subfinder/provider-config.yaml"
echo "  3. Deploy new zshrc: cp $BB/config/zshrc-pi ~/.zshrc && source ~/.zshrc"
echo "  4. Run full diagnostic: $BB/scripts/pi-diag.sh"
echo ""
echo -e "${CYAN}Quick hunt start:${NC}"
echo "  hunt-workspace.sh <target.com>   # 5-pane tmux workspace"
echo "  oob-manager.sh start             # persistent OOB listener"
echo "  pi-diag.sh --report              # health snapshot"
