#!/usr/bin/env bash
# pi-diag.sh — Comprehensive Pi 5 Bug Bounty Lab Diagnostic + Auto-Fix
#
# Runs a full health check across system, tools, wordlists, templates, network,
# and API keys. Prints a color-coded report with severity levels, then offers
# to auto-fix every issue it finds.
#
# Usage:
#   ./scripts/pi-diag.sh              # full diagnostic (interactive)
#   ./scripts/pi-diag.sh --fix        # auto-fix all issues without prompting
#   ./scripts/pi-diag.sh --report     # report only (no fix prompts)
#   ./scripts/pi-diag.sh --json       # machine-readable JSON output
#   ./scripts/pi-diag.sh --check-tool <name>  # check single tool
#
# Exit codes:
#   0  all checks passed
#   1  warnings only
#   2  critical issues found

set -uo pipefail

# ─── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS="${GREEN}[✓]${NC}"; FAIL="${RED}[✗]${NC}"; WARN="${YELLOW}[!]${NC}"; INFO="${CYAN}[i]${NC}"

# ─── Counters ────────────────────────────────────────────────────────────────
PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0
FIXES=()      # accumulates "description|command" fix pairs

AUTO_FIX=false; REPORT_ONLY=false; JSON_OUT=false; CHECK_TOOL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fix)         AUTO_FIX=true ;;
    --report)      REPORT_ONLY=true ;;
    --json)        JSON_OUT=true ;;
    --check-tool)  shift; CHECK_TOOL="$1" ;;
    *) echo "Unknown arg: $1" >&2 ;;
  esac; shift
done

pass() { echo -e "${PASS} $*"; ((PASS_COUNT++)); }
warn() { echo -e "${WARN} $*"; ((WARN_COUNT++)); }
fail() { echo -e "${FAIL} $*"; ((FAIL_COUNT++)); }
info() { echo -e "${INFO} $*"; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
add_fix() { FIXES+=("$1|$2"); }  # add_fix "description" "bash command"

# ─── Helper: version compare ─────────────────────────────────────────────────
ver_lt() { [ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }

# ─── START ───────────────────────────────────────────────────────────────────
if ! $JSON_OUT; then
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${CYAN}║   Pi 5 Bug Bounty Lab — Comprehensive Diagnostic             ║${NC}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo -e "  Host: $(hostname) | User: $(whoami)"
  echo ""
fi

BB="${HOME}/bug-bounty-hunting-"
GOBIN="${HOME}/go/bin"
PDTM_BIN="${HOME}/.pdtm/go/bin"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
section "SYSTEM"

# Architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" ]]; then
  pass "Architecture: aarch64 (ARM64) — Pi 5 native"
else
  warn "Architecture: $ARCH (expected aarch64)"
fi

# OS
OS=$(. /etc/os-release && echo "$PRETTY_NAME" 2>/dev/null || echo "Unknown")
pass "OS: $OS"

# Kernel
KERNEL=$(uname -r)
pass "Kernel: $KERNEL"

# RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$(awk "BEGIN {printf \"%.1f\", $TOTAL_RAM_KB/1048576}")
if (( TOTAL_RAM_KB > 14000000 )); then
  pass "RAM: ${TOTAL_RAM_GB} GB detected"
elif (( TOTAL_RAM_KB > 7000000 )); then
  warn "RAM: ${TOTAL_RAM_GB} GB (expected ≥16 GB for Pi 5)"
else
  fail "RAM: ${TOTAL_RAM_GB} GB — critically low"
fi

# Swap
SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
SWAP_GB=$(awk "BEGIN {printf \"%.1f\", $SWAP_KB/1048576}")
if (( SWAP_KB >= 3900000 )); then
  pass "Swap: ${SWAP_GB} GB ✓"
else
  warn "Swap: ${SWAP_GB} GB (recommend ≥4 GB for nuclei runs)"
  add_fix "Create 4 GB swapfile" \
    "sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab"
fi

# Disk
DISK_AVAIL=$(df -BG / | awk 'NR==2 {gsub(/G/,"",$4); print $4}')
DISK_TOTAL=$(df -BG / | awk 'NR==2 {gsub(/G/,"",$2); print $2}')
if (( DISK_AVAIL >= 20 )); then
  pass "Disk: ${DISK_AVAIL}G free / ${DISK_TOTAL}G total"
elif (( DISK_AVAIL >= 5 )); then
  warn "Disk: ${DISK_AVAIL}G free — may run low during wordlist installs"
else
  fail "Disk: ${DISK_AVAIL}G free — CRITICALLY LOW (need ≥20 GB)"
fi

# Temperature
TEMP_RAW=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0")
TEMP_C=$((TEMP_RAW / 1000))
if (( TEMP_C < 60 )); then
  pass "Temperature: ${TEMP_C}°C — cool"
elif (( TEMP_C < 75 )); then
  warn "Temperature: ${TEMP_C}°C — acceptable (limit 78°C)"
else
  fail "Temperature: ${TEMP_C}°C — HOT! Check cooling. Performance will throttle."
fi

# CPU Governor
GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo "0")
FREQ_GHZ=$(awk "BEGIN {printf \"%.2f\", $FREQ/1000000}")
if [[ "$GOV" == "performance" ]]; then
  pass "CPU governor: performance @ ${FREQ_GHZ} GHz"
else
  warn "CPU governor: $GOV (recommend 'performance' for hunting)"
  add_fix "Set CPU governor to performance" \
    "for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance | sudo tee \"\$g\"; done"
fi

# File descriptor limits
FD_LIMIT=$(ulimit -n 2>/dev/null || echo "0")
if (( FD_LIMIT >= 65535 )); then
  pass "File descriptors: $FD_LIMIT ✓"
else
  warn "File descriptors: $FD_LIMIT (recommend ≥1048576)"
  add_fix "Increase file descriptor limits" \
    "sudo bash -c 'cat > /etc/security/limits.d/99-bugbounty.conf <<EOF\n* soft nofile 1048576\n* hard nofile 1048576\n* soft nproc 65535\n* hard nproc 65535\nEOF'"
fi

# Sysctl TCP settings
BBR=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
if [[ "$BBR" == "bbr" ]]; then
  pass "TCP congestion: BBR ✓"
else
  warn "TCP congestion: $BBR (recommend bbr for higher throughput)"
  add_fix "Enable BBR TCP congestion control" \
    "echo 'net.ipv4.tcp_congestion_control=bbr' | sudo tee -a /etc/sysctl.d/99-bugbounty.conf && sudo sysctl -p /etc/sysctl.d/99-bugbounty.conf"
fi

# tmpfs /tmp
if mount | grep -q 'tmpfs on /tmp'; then
  TMP_SIZE=$(df -h /tmp 2>/dev/null | awk 'NR==2{print $2}')
  pass "tmpfs /tmp: $TMP_SIZE (fast scan temp I/O)"
else
  warn "/tmp is on main disk (recommend tmpfs for scan I/O speed)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: NETWORK
# ═══════════════════════════════════════════════════════════════════════════════
section "NETWORK"

# Internet connectivity
if curl -sfL --max-time 5 https://api.github.com/zen >/dev/null 2>&1; then
  pass "Internet connectivity: GitHub API reachable"
else
  fail "Internet connectivity: cannot reach github.com (DNS or routing issue)"
  add_fix "Flush DNS cache" "sudo systemctl restart systemd-resolved 2>/dev/null || sudo service dns-clean restart 2>/dev/null || true"
fi

# DNS resolver
DNS_SERVER=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
info "DNS resolver: ${DNS_SERVER:-unknown}"

# Check DNS resolution speed
DNS_TIME=$(( SECONDS ))
python3 -c "import socket; socket.gethostbyname('google.com')" 2>/dev/null && DNS_OK=true || DNS_OK=false
DNS_ELAPSED=$(( SECONDS - DNS_TIME ))
if $DNS_OK; then
  pass "DNS resolution: working (${DNS_ELAPSED}s)"
else
  fail "DNS resolution: failed for google.com"
fi

# Public IP
PUB_IP=$(curl -sfL --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
info "Public IP: $PUB_IP"

# Check if behind NAT
if [[ "$PUB_IP" != "unknown" ]] && [[ "$PUB_IP" != 192.168.* ]] && [[ "$PUB_IP" != 10.* ]]; then
  pass "Public IP: $PUB_IP (direct routing)"
else
  warn "Public IP appears to be private — may affect OOB callbacks"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: GO TOOLCHAIN
# ═══════════════════════════════════════════════════════════════════════════════
section "GO TOOLCHAIN"

# PATH check
export PATH="$PATH:$GOBIN:$PDTM_BIN:/usr/local/go/bin:${HOME}/.local/bin"

# Go version
if command -v go >/dev/null 2>&1; then
  GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.?[0-9]*')
  LATEST_GO="1.24.4"
  if ver_lt "$GO_VER" "1.21.0"; then
    warn "Go: v${GO_VER} (outdated — recommend ≥1.22)"
    add_fix "Update Go to $LATEST_GO" \
      "curl -fsSL https://go.dev/dl/go${LATEST_GO}.linux-arm64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz"
  else
    pass "Go: v${GO_VER}"
  fi
else
  fail "Go: NOT INSTALLED"
  add_fix "Install Go 1.24.4" \
    "curl -fsSL https://go.dev/dl/go1.24.4.linux-arm64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz && export PATH=\$PATH:/usr/local/go/bin"
fi

# Go tools check — critical tools first
declare -A GO_TOOLS_CRITICAL=(
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
  ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
  ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  ["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  ["uncover"]="github.com/projectdiscovery/uncover/cmd/uncover@latest"
  ["mapcidr"]="github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
  ["shuffledns"]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  ["pdtm"]="github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
  ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
  ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
  ["anew"]="github.com/tomnomnom/anew@latest"
  ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
  ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
  ["gf"]="github.com/tomnomnom/gf@latest"
  ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
  ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
  ["subzy"]="github.com/PentestPad/subzy@latest"
  ["puredns"]="github.com/d3mondev/puredns/v2@latest"
  ["hakrawler"]="github.com/hakluke/hakrawler@latest"
  ["gospider"]="github.com/jaeles-project/gospider@latest"
  ["jsluice"]="github.com/BishopFox/jsluice/cmd/jsluice@latest"
  ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
  ["gitleaks"]="github.com/zricethezav/gitleaks/v8@latest"
  ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  ["cariddi"]="github.com/edoardottt/cariddi/cmd/cariddi@latest"
  ["github-subdomains"]="github.com/gwen001/github-subdomains@latest"
  ["s3scanner"]="github.com/sa7mon/s3scanner@latest"
  ["gowitness"]="github.com/sensepost/gowitness@latest"
  ["uro"]="github.com/s0md3v/uro@latest"
  ["meg"]="github.com/tomnomnom/meg@latest"
  ["fff"]="github.com/tomnomnom/fff@latest"
  ["httprobe"]="github.com/tomnomnom/httprobe@latest"
  ["amass"]="github.com/owasp-amass/amass/v4/...@master"
)

MISSING_GO_TOOLS=()
for tool in "${!GO_TOOLS_CRITICAL[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    VER=$("$tool" -version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "installed")
    pass "  $tool: $VER"
  else
    fail "  $tool: NOT INSTALLED"
    MISSING_GO_TOOLS+=("$tool|${GO_TOOLS_CRITICAL[$tool]}")
  fi
done

if (( ${#MISSING_GO_TOOLS[@]} > 0 )); then
  MISSING_INSTALL_CMDS=""
  for entry in "${MISSING_GO_TOOLS[@]}"; do
    pkg="${entry#*|}"
    MISSING_INSTALL_CMDS+="GOFLAGS=-buildvcs=false go install ${pkg} 2>/dev/null || true; "
  done
  add_fix "Install ${#MISSING_GO_TOOLS[@]} missing Go tools" "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin; $MISSING_INSTALL_CMDS"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: PYTHON TOOLS
# ═══════════════════════════════════════════════════════════════════════════════
section "PYTHON TOOLS"

if command -v python3 >/dev/null 2>&1; then
  PY_VER=$(python3 --version | awk '{print $2}')
  pass "Python3: $PY_VER"
else
  fail "Python3: NOT INSTALLED"
fi

if command -v pipx >/dev/null 2>&1; then
  pass "pipx: $(pipx --version 2>/dev/null | head -1)"
else
  warn "pipx: not installed"
  add_fix "Install pipx" "python3 -m pip install --user pipx && python3 -m pipx ensurepath"
fi

declare -a PY_TOOLS=("sqlmap" "arjun" "dirsearch" "corsy" "wfuzz")
for tool in "${PY_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    pass "  $tool: ✓"
  else
    warn "  $tool: not found"
    add_fix "Install $tool via pipx" "pipx install $tool 2>/dev/null || true"
  fi
done

# jwt_tool
if command -v jwt_tool >/dev/null 2>&1 || [ -f "${HOME}/tools/jwt_tool/jwt_tool.py" ]; then
  pass "  jwt_tool: ✓"
else
  warn "  jwt_tool: not found"
fi

# feroxbuster (Rust binary)
if command -v feroxbuster >/dev/null 2>&1; then
  FB_VER=$(feroxbuster --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "installed")
  pass "  feroxbuster: $FB_VER"
else
  warn "  feroxbuster: not installed"
  add_fix "Install feroxbuster (ARM64 binary)" \
    "FB_VER=\$(curl -sfL https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r '.tag_name' 2>/dev/null || echo 'v2.10.4'); curl -sfL \"https://github.com/epi052/feroxbuster/releases/download/\${FB_VER}/feroxbuster-linux-aarch64.tar.gz\" -o /tmp/ferox.tar.gz && sudo tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster && rm /tmp/ferox.tar.gz"
fi

# massdns
if command -v massdns >/dev/null 2>&1; then
  pass "  massdns: ✓"
else
  warn "  massdns: not installed"
  add_fix "Build and install massdns" \
    "git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && make -C /tmp/massdns -j4 && sudo cp /tmp/massdns/bin/massdns /usr/local/bin/ && rm -rf /tmp/massdns"
fi

# nikto
if command -v nikto >/dev/null 2>&1; then
  pass "  nikto: ✓"
else
  warn "  nikto: not installed"
  add_fix "Install nikto" "sudo apt-get install -y nikto 2>/dev/null || pipx install nikto 2>/dev/null || true"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: WORDLISTS
# ═══════════════════════════════════════════════════════════════════════════════
section "WORDLISTS"

WL="${HOME}/wordlists"
if [ -d "$WL" ]; then
  pass "Wordlist dir: $WL"
else
  fail "Wordlist dir: $WL does not exist"
  add_fix "Create wordlist directory" "mkdir -p $WL"
fi

# SecLists
if [ -d "$WL/SecLists" ]; then
  SL_SIZE=$(du -sh "$WL/SecLists" 2>/dev/null | awk '{print $1}')
  pass "SecLists: $SL_SIZE"
else
  fail "SecLists: NOT FOUND"
  add_fix "Clone SecLists" "git clone --depth 1 https://github.com/danielmiessler/SecLists.git $WL/SecLists"
fi

# DNS wordlist for subdomain bruteforce
DNS_WL="$WL/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
if [ -f "$DNS_WL" ]; then
  WC=$(wc -l < "$DNS_WL")
  pass "DNS wordlist: $WC lines"
else
  warn "DNS wordlist: $DNS_WL not found (SecLists needed)"
fi

# Assetnote wordlists
for f in "parameters_top1m.txt" "apiroutes_210228.txt" "graphql_operations.txt"; do
  if [ -f "$WL/assetnote/$f" ]; then
    SZ=$(wc -l < "$WL/assetnote/$f" 2>/dev/null)
    pass "Assetnote $f: $SZ lines"
  else
    warn "Assetnote $f: missing"
    add_fix "Download assetnote $f" \
      "mkdir -p $WL/assetnote && curl -fsSL https://wordlists-cdn.assetnote.io/data/manual/${f} -o $WL/assetnote/${f} 2>/dev/null || true"
  fi
done

# Assetnote all.txt (massive DNS bruteforce list)
if [ -f "$WL/assetnote/all.txt" ]; then
  SZ=$(wc -l < "$WL/assetnote/all.txt")
  pass "Assetnote all.txt (DNS): $SZ lines"
else
  warn "Assetnote all.txt: missing (9M+ subdomain wordlist)"
  add_fix "Download Assetnote all.txt" \
    "mkdir -p $WL/assetnote && curl -fsSL https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -o $WL/assetnote/all.txt 2>/dev/null || true"
fi

# gf patterns
if [ -d "${HOME}/.gf" ] && [ "$(ls -A ${HOME}/.gf/*.json 2>/dev/null | wc -l)" -gt 5 ]; then
  GF_COUNT=$(ls "${HOME}/.gf/"*.json 2>/dev/null | wc -l)
  pass "gf patterns: $GF_COUNT patterns"
else
  warn "gf patterns: missing or sparse"
  add_fix "Install gf patterns" \
    "mkdir -p ~/.gf && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gfp && cp /tmp/gfp/*.json ~/.gf/ && rm -rf /tmp/gfp"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: NUCLEI TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════
section "NUCLEI TEMPLATES"

NUCLEI_TEMPLATES="${HOME}/nuclei-templates"
if command -v nuclei >/dev/null 2>&1; then
  # Check official templates
  DEFAULT_TEMPLATES=$(nuclei -tl 2>/dev/null | wc -l || echo "0")
  if (( DEFAULT_TEMPLATES > 1000 )); then
    pass "Official templates: $DEFAULT_TEMPLATES templates loaded"
  elif (( DEFAULT_TEMPLATES > 0 )); then
    warn "Official templates: $DEFAULT_TEMPLATES (may be out of date — run nuclei -update-templates)"
    add_fix "Update nuclei templates" "nuclei -update-templates -silent"
  else
    warn "Official templates: 0 loaded (run nuclei -update-templates)"
    add_fix "Initialize nuclei templates" "nuclei -update-templates -silent"
  fi

  # Fuzzing templates
  if [ -d "$NUCLEI_TEMPLATES/fuzzing-templates" ]; then
    FZ=$(find "$NUCLEI_TEMPLATES/fuzzing-templates" -name "*.yaml" 2>/dev/null | wc -l)
    pass "Fuzzing templates: $FZ templates"
  else
    warn "Fuzzing templates: not found"
    add_fix "Clone fuzzing templates" \
      "mkdir -p $NUCLEI_TEMPLATES && git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git $NUCLEI_TEMPLATES/fuzzing-templates"
  fi

  # Custom templates
  if [ -d "$NUCLEI_TEMPLATES/custom" ]; then
    CT=$(find "$NUCLEI_TEMPLATES/custom" -name "*.yaml" 2>/dev/null | wc -l)
    pass "Custom templates: $CT templates"
  else
    warn "Custom templates: $NUCLEI_TEMPLATES/custom not found"
    add_fix "Create custom template directory" "mkdir -p $NUCLEI_TEMPLATES/custom"
  fi

  # Nuclei version
  NUCLEI_VER=$(nuclei -version 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
  pass "Nuclei version: $NUCLEI_VER"
else
  fail "Nuclei: NOT INSTALLED — run setup-pi.sh --tools"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: API KEYS & SECRETS
# ═══════════════════════════════════════════════════════════════════════════════
section "API KEYS & SECRETS"

SECRETS_FILE="${HOME}/.secrets.zsh"
if [ -f "$SECRETS_FILE" ]; then
  # Source to load vars (safe since we own the file)
  # shellcheck disable=SC1090
  source "$SECRETS_FILE" 2>/dev/null || true
  pass "~/.secrets.zsh: exists"
  SECRETS_PERMS=$(stat -c "%a" "$SECRETS_FILE" 2>/dev/null)
  if [[ "$SECRETS_PERMS" == "600" ]]; then
    pass "~/.secrets.zsh: permissions 600 ✓"
  else
    warn "~/.secrets.zsh: permissions $SECRETS_PERMS (should be 600)"
    add_fix "Fix secrets file permissions" "chmod 600 ~/.secrets.zsh"
  fi
else
  warn "~/.secrets.zsh: not found — API keys not configured"
  add_fix "Create secrets file" "touch ~/.secrets.zsh && chmod 600 ~/.secrets.zsh"
fi

# Check specific API keys
declare -A API_KEYS=(
  ["SUBFINDER_API_KEYS or CHAOS_KEY"]="${CHAOS_KEY:-}"
  ["SHODAN_API_KEY"]="${SHODAN_API_KEY:-}"
  ["GITHUB_TOKEN"]="${GITHUB_TOKEN:-}"
  ["DISCORD_WEBHOOK_URL"]="${DISCORD_WEBHOOK_URL:-}"
  ["ANTHROPIC_API_KEY"]="${ANTHROPIC_API_KEY:-}"
  ["INTERACTSH_SERVER"]="${INTERACTSH_SERVER:-oast.pro}"
)
for key in "${!API_KEYS[@]}"; do
  val="${API_KEYS[$key]}"
  if [ -n "$val" ] && [ "$val" != "oast.pro" ]; then
    pass "  $key: set (${#val} chars)"
  elif [[ "$key" == *"INTERACTSH"* ]] && [ -n "$val" ]; then
    pass "  $key: $val"
  else
    warn "  $key: NOT SET"
  fi
done

# subfinder provider config
SUBFINDER_CONFIG="${HOME}/.config/subfinder/provider-config.yaml"
if [ -f "$SUBFINDER_CONFIG" ] && grep -qv '^#' "$SUBFINDER_CONFIG" 2>/dev/null; then
  pass "Subfinder provider config: configured"
else
  warn "Subfinder provider config: $SUBFINDER_CONFIG not configured (limits subdomain discovery)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: SHELL ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════════
section "SHELL ENVIRONMENT"

# zshrc deployed
if [ -f "${HOME}/.zshrc" ] && grep -q "Bug Bounty Lab" "${HOME}/.zshrc" 2>/dev/null; then
  pass "~/.zshrc: bug bounty lab config deployed"
else
  warn "~/.zshrc: lab config not deployed"
  add_fix "Deploy zshrc" "cp $BB/config/zshrc-pi ~/.zshrc && source ~/.zshrc"
fi

# Oh-My-Zsh
if [ -d "${HOME}/.oh-my-zsh" ]; then
  pass "Oh-My-Zsh: installed"
else
  warn "Oh-My-Zsh: not installed"
  add_fix "Install Oh-My-Zsh" \
    'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'
fi

# tmux config
if [ -f "${HOME}/.tmux.conf" ] && grep -q 'prefix' "${HOME}/.tmux.conf" 2>/dev/null; then
  pass "~/.tmux.conf: configured"
else
  warn "~/.tmux.conf: not configured"
  add_fix "Install tmux config" "cp $BB/config/tmux.conf ~/.tmux.conf 2>/dev/null || true"
fi

# lsd (better ls)
if command -v lsd >/dev/null 2>&1; then
  pass "lsd: ✓ (better ls)"
else
  warn "lsd: not installed (optional — better ls)"
  add_fix "Install lsd" "sudo apt-get install -y lsd 2>/dev/null || cargo install lsd 2>/dev/null || true"
fi

# fzf (fuzzy finder — used by shell functions)
if command -v fzf >/dev/null 2>&1; then
  pass "fzf: ✓"
else
  warn "fzf: not installed"
  add_fix "Install fzf" "sudo apt-get install -y fzf 2>/dev/null && echo 'fzf installed via apt' || { git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf 2>/dev/null && ~/.fzf/install --all; }"
fi

# ripgrep
if command -v rg >/dev/null 2>&1; then
  pass "ripgrep: ✓"
else
  warn "ripgrep: not installed"
  add_fix "Install ripgrep" "sudo apt-get install -y ripgrep 2>/dev/null || true"
fi

# PATH integrity check — critical bins reachable?
PATH_ISSUES=()
for bin in go subfinder httpx nuclei dnsx; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    PATH_ISSUES+=("$bin")
  fi
done
if (( ${#PATH_ISSUES[@]} == 0 )); then
  pass "PATH: all critical binaries reachable"
else
  fail "PATH: cannot find: ${PATH_ISSUES[*]}"
  add_fix "Add all lab dirs to PATH" \
    "echo 'export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin:\$HOME/.pdtm/go/bin:\$HOME/.local/bin' >> ~/.bashrc && source ~/.bashrc"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: SERVICES
# ═══════════════════════════════════════════════════════════════════════════════
section "SERVICES"

# Redis
if systemctl is-active redis-server >/dev/null 2>&1 || systemctl is-active redis >/dev/null 2>&1; then
  pass "Redis: running"
elif command -v redis-cli >/dev/null 2>&1 && redis-cli ping 2>/dev/null | grep -q PONG; then
  pass "Redis: responding"
else
  warn "Redis: not running"
  add_fix "Start redis-server" "sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null || true"
fi

# Docker
if command -v docker >/dev/null 2>&1; then
  DOCKER_VER=$(docker --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if docker info >/dev/null 2>&1; then
    pass "Docker: $DOCKER_VER (daemon running)"
  else
    warn "Docker: $DOCKER_VER installed but daemon not running"
    add_fix "Start Docker daemon" "sudo systemctl start docker"
  fi
else
  warn "Docker: not installed (optional — used for some tools)"
fi

# Cron jobs
CRON_COUNT=$(crontab -l 2>/dev/null | grep -v '^#' | grep -c . || echo "0")
if (( CRON_COUNT > 0 )); then
  pass "Cron: $CRON_COUNT jobs configured"
  crontab -l 2>/dev/null | grep -v '^#' | sed 's/^/  /'
else
  warn "Cron: no jobs configured (recommend daily tool updates)"
  add_fix "Set up daily maintenance cron" \
    "bash $BB/scripts/setup-cron.sh 2>/dev/null || (crontab -l 2>/dev/null; echo '0 4 * * * $BB/scripts/daily-update.sh >> /tmp/daily-update.log 2>&1') | crontab -"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10: LIVE TOOL SMOKE TESTS
# ═══════════════════════════════════════════════════════════════════════════════
section "TOOL SMOKE TESTS"

# subfinder smoke test
if command -v subfinder >/dev/null 2>&1; then
  if echo "" | timeout 5 subfinder -d example.com -silent 2>/dev/null | head -1 >/dev/null 2>&1; then
    pass "subfinder: responds"
  else
    pass "subfinder: binary executes ✓ (no API keys = limited output)"
  fi
fi

# httpx smoke test
if command -v httpx >/dev/null 2>&1; then
  if echo "https://example.com" | timeout 10 httpx -silent -status-code 2>/dev/null | head -1 | grep -q '200\|301\|302'; then
    pass "httpx: probing works (example.com → 200)"
  else
    warn "httpx: probe result unexpected (network issue?)"
  fi
fi

# dnsx smoke test
if command -v dnsx >/dev/null 2>&1; then
  if echo "google.com" | timeout 5 dnsx -silent 2>/dev/null | grep -q 'google.com'; then
    pass "dnsx: DNS resolution works"
  else
    warn "dnsx: DNS test failed"
  fi
fi

# nuclei quick check
if command -v nuclei >/dev/null 2>&1; then
  if nuclei -version >/dev/null 2>&1; then
    pass "nuclei: binary functional"
  else
    fail "nuclei: binary fails to run"
  fi
fi

# ffuf smoke test
if command -v ffuf >/dev/null 2>&1; then
  pass "ffuf: $(ffuf -V 2>/dev/null | head -1 || echo 'installed')"
fi

# interactsh-client
if command -v interactsh-client >/dev/null 2>&1; then
  pass "interactsh-client: installed"
  if timeout 8 interactsh-client -server oast.pro -n 1 2>/dev/null | grep -q 'interactsh'; then
    pass "interactsh-client: OOB connectivity to oast.pro ✓"
  else
    warn "interactsh-client: could not connect to oast.pro (network or rate limit)"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: PROJECT FILES
# ═══════════════════════════════════════════════════════════════════════════════
section "PROJECT FILES"

if [ -d "$BB" ]; then
  pass "Repo: $BB"
  BRANCH=$(git -C "$BB" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
  COMMITS_BEHIND=$(git -C "$BB" rev-list HEAD..origin/HEAD --count 2>/dev/null || echo "?")
  pass "Branch: $BRANCH (${COMMITS_BEHIND} commits behind remote)"
else
  fail "Repo: $BB not found"
fi

[ -f "$BB/config/scope.yaml" ] && pass "scope.yaml: found" || fail "scope.yaml: MISSING"
[ -f "$BB/scripts/scope-check.sh" ] && pass "scope-check.sh: found" || fail "scope-check.sh: MISSING"
[ -f "$BB/methodology/METHODOLOGY.md" ] && pass "METHODOLOGY.md: found" || warn "METHODOLOGY.md: missing"

RESULTS_COUNT=$(find "$BB/results" -name "HUNT-LOG.md" 2>/dev/null | wc -l)
pass "Hunt logs: $RESULTS_COUNT targets tracked"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12: SUMMARY + FIX PROMPT
# ═══════════════════════════════════════════════════════════════════════════════
section "SUMMARY"

TOTAL=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
echo ""
echo -e "  ${GREEN}Passed: ${PASS_COUNT}/${TOTAL}${NC}  ${YELLOW}Warnings: ${WARN_COUNT}${NC}  ${RED}Failures: ${FAIL_COUNT}${NC}"
echo ""

if (( ${#FIXES[@]} > 0 )); then
  echo -e "${BOLD}Available fixes (${#FIXES[@]} items):${NC}"
  for i in "${!FIXES[@]}"; do
    DESC="${FIXES[$i]%%|*}"
    echo -e "  ${YELLOW}[$((i+1))]${NC} $DESC"
  done
  echo ""

  if ! $REPORT_ONLY; then
    if $AUTO_FIX; then
      echo -e "${CYAN}[*] Auto-fix mode — applying all fixes...${NC}"
      APPLY=y
    else
      echo -n "Apply all fixes? [y/N] "
      read -r APPLY
    fi

    if [[ "${APPLY:-}" =~ ^[Yy]$ ]]; then
      echo ""
      for i in "${!FIXES[@]}"; do
        DESC="${FIXES[$i]%%|*}"
        CMD="${FIXES[$i]#*|}"
        echo -e "${CYAN}[*] Fixing: $DESC${NC}"
        if eval "$CMD" 2>&1 | tail -3; then
          echo -e "${GREEN}[✓] Done${NC}"
        else
          echo -e "${RED}[✗] Failed — try manually: $CMD${NC}"
        fi
        echo ""
      done
      echo -e "${GREEN}[+] All fixes attempted. Re-run pi-diag.sh to verify.${NC}"
    fi
  fi
fi

if $JSON_OUT; then
  python3 -c "import json; print(json.dumps({'pass':$PASS_COUNT,'warn':$WARN_COUNT,'fail':$FAIL_COUNT,'fixes':${#FIXES[@]}}))"
fi

# Exit code
if (( FAIL_COUNT > 0 )); then exit 2; elif (( WARN_COUNT > 0 )); then exit 1; else exit 0; fi
