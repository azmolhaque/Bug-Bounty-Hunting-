#!/usr/bin/env bash
# setup-pi.sh — Raspberry Pi 5 Bug Bounty Lab — Complete Provisioner
#
# Builds a professional-grade bug bounty hunting lab on Pi 5 (16 GB, ARM64):
#   Phase 1 — System tuning (CPU governor, network stack, limits, swap)
#   Phase 2 — Full Go toolchain (recon, scan, SSRF, XSS, secret detection)
#   Phase 3 — Python tools (sqlmap, jwt_tool, corsy, arjun, dirsearch)
#   Phase 4 — Wordlists (SecLists + Assetnote API/parameter/route lists)
#   Phase 5 — Nuclei templates (official + fuzzing + custom)
#   Phase 6 — tmux + shell environment
#
# Usage:
#   ./scripts/setup-pi.sh              # full install (all phases)
#   ./scripts/setup-pi.sh --check      # verify installed tools
#   ./scripts/setup-pi.sh --tools      # Go + Python tools only
#   ./scripts/setup-pi.sh --system     # system tuning only
#   ./scripts/setup-pi.sh --wordlists  # wordlists only
#   ./scripts/setup-pi.sh --upgrade    # update all tools + templates
#
# Idempotent: safe to re-run at any time.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()     { echo -e "${GREEN}[+]${NC} $*"; }
info()    { echo -e "${CYAN}[*]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

ARCH="$(uname -m)"
[ "$ARCH" = "aarch64" ] || warn "Arch=$ARCH — expected aarch64 (Pi 5). Continuing anyway."

GO_VERSION="1.22.5"
GOBIN="${HOME}/go/bin"
VENV="${HOME}/bug-bounty-hunting-/.venv"

# ─── PATH propagation ──────────────────────────────────────────────────────────
ensure_path() {
  local needed='export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin:$HOME/.local/bin'
  if ! grep -qF 'go/bin' "${HOME}/.bashrc" 2>/dev/null; then
    echo "$needed" >> "${HOME}/.bashrc"
  fi
  export PATH="$PATH:$GOBIN:/usr/local/go/bin:${HOME}/.local/bin"
}

# ─── Phase 1: System tuning ────────────────────────────────────────────────────
tune_system() {
  section "Phase 1 — Pi 5 System Tuning"

  log "CPU governor → performance"
  for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [ -f "$gov" ] && echo performance | sudo tee "$gov" >/dev/null
  done || warn "Could not set CPU governor (may need root)"

  log "Persist CPU governor across reboots…"
  if ! grep -q 'scaling_governor' /etc/rc.local 2>/dev/null; then
    sudo bash -c "cat >> /etc/rc.local" <<'RC'
# Bug bounty lab — CPU performance mode
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -f "$gov" ] && echo performance > "$gov"
done
RC
    sudo chmod +x /etc/rc.local 2>/dev/null || true
  fi

  log "Network stack tuning (TCP SYN backlog, port range, BBR)…"
  sudo bash -c 'cat >> /etc/sysctl.d/99-bugbounty.conf' <<'SYSCTL' 2>/dev/null || true
# Bug bounty lab — network + memory tuning
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.core.netdev_max_backlog=65535
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_congestion_control=bbr
vm.swappiness=10
vm.dirty_ratio=15
fs.file-max=1048576
SYSCTL
  sudo sysctl --system >/dev/null 2>&1 || true

  log "File descriptor limits (1M)…"
  if ! grep -q 'nofile' /etc/security/limits.d/99-bugbounty.conf 2>/dev/null; then
    sudo bash -c 'cat > /etc/security/limits.d/99-bugbounty.conf' <<'LIMITS'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc  65535
* hard nproc  65535
LIMITS
  fi

  log "Swap: 4 GB swapfile (for long nuclei runs)…"
  if ! swapon --show | grep -q '/swapfile'; then
    sudo fallocate -l 4G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=4096 2>/dev/null
    sudo chmod 600 /swapfile && sudo mkswap /swapfile >/dev/null && sudo swapon /swapfile
    grep -q '/swapfile' /etc/fstab 2>/dev/null || echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
    log "  Swap active"
  else
    log "  Swap already configured ✓"
  fi

  log "tmpfs /tmp overlay (faster temp I/O for scanner output)…"
  grep -q 'tmpfs /tmp' /etc/fstab 2>/dev/null || \
    echo "tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0" | sudo tee -a /etc/fstab >/dev/null

  log "System tuning done."
}

# ─── Phase 2: Base packages ────────────────────────────────────────────────────
install_base() {
  section "Phase 2 — APT packages"
  sudo apt-get update -y -q
  sudo apt-get install -y --no-install-recommends \
    git curl wget jq unzip build-essential ca-certificates \
    python3 python3-pip python3-venv pipx \
    dnsutils whois nmap masscan libpcap-dev \
    chromium-browser \
    tmux screen vim htop iotop lsof net-tools \
    ruby ruby-dev \
    sqlite3 redis-server \
    docker.io 2>/dev/null | grep -v "^(Reading|Get:|Hit:|Ign:)" || true
  sudo systemctl enable redis-server --now 2>/dev/null || true
  sudo usermod -aG docker "${USER}" 2>/dev/null || true
}

# ─── Phase 3: Go install ────────────────────────────────────────────────────────
install_go() {
  if command -v go >/dev/null 2>&1; then
    log "Go already present: $(go version)"
    return
  fi
  section "Phase 3 — Go ${GO_VERSION}"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
  ensure_path
  log "Go installed: $(go version)"
}

# ─── Phase 4: Go toolchain ─────────────────────────────────────────────────────
install_go_tools() {
  ensure_path
  section "Phase 4 — Go Toolchain"

  declare -A TOOLS=(
    # ProjectDiscovery suite
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    ["uncover"]="github.com/projectdiscovery/uncover/cmd/uncover@latest"
    ["mapcidr"]="github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
    ["pdtm"]="github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    ["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    ["cariddi"]="github.com/edoardottt/cariddi/cmd/cariddi@latest"
    # TomNomNom utilities
    ["anew"]="github.com/tomnomnom/anew@latest"
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
    ["fff"]="github.com/tomnomnom/fff@latest"
    ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
    ["gf"]="github.com/tomnomnom/gf@latest"
    # Historical URL mining
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    # Fuzzing
    ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
    # XSS
    ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
    # CRLF injection
    ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    # DNS
    ["puredns"]="github.com/d3mondev/puredns/v2@latest"
    ["shuffledns"]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    # JS analysis
    ["jsluice"]="github.com/BishopFox/jsluice/cmd/jsluice@latest"
    # Secret scanning
    ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
    ["gitleaks"]="github.com/zricethezav/gitleaks/v8@latest"
    # HTTP crawlers
    ["hakrawler"]="github.com/hakluke/hakrawler@latest"
    ["gospider"]="github.com/jaeles-project/gospider@latest"
    # Cloud
    ["cloudbrute"]="github.com/m0nad/cloudbrute@latest"
    ["s3scanner"]="github.com/sa7mon/s3scanner@latest"
    # Parameter discovery helper
    ["x8"]="github.com/ffffffff0x1/x8@latest"
  )

  for name in "${!TOOLS[@]}"; do
    if command -v "$name" >/dev/null 2>&1; then
      info "  $name ✓"
      continue
    fi
    log "  Installing $name…"
    GOFLAGS=-buildvcs=false go install -v "${TOOLS[$name]}" 2>/dev/null \
      || warn "  $name failed — try manually: go install ${TOOLS[$name]}"
  done
}

# ─── Phase 5: Python tools ─────────────────────────────────────────────────────
install_python_tools() {
  section "Phase 5 — Python Tools (pipx)"
  pipx ensurepath 2>/dev/null || true

  declare -A PY_TOOLS=(
    ["arjun"]="arjun"                                   # HTTP parameter discovery
    ["dirsearch"]="dirsearch"                           # directory brute force
    ["sqlmap"]="sqlmap"                                 # SQL injection (the gold standard)
    ["jwt_tool"]="jwt_tool"                             # JWT attack toolkit
    ["corsy"]="corsy"                                   # CORS misconfiguration scanner
    ["wfuzz"]="wfuzz"                                   # advanced web fuzzer
  )

  for name in "${!PY_TOOLS[@]}"; do
    if command -v "$name" >/dev/null 2>&1; then
      info "  $name ✓"
      continue
    fi
    log "  pipx install ${PY_TOOLS[$name]}…"
    pipx install "${PY_TOOLS[$name]}" 2>/dev/null || warn "  $name failed"
  done

  # Install truffleHog via pip if go version fails (it's big)
  command -v trufflehog >/dev/null 2>&1 || {
    log "  trufflehog (pip fallback)…"
    pip3 install trufflehog 2>/dev/null || warn "  trufflehog pip failed"
  }

  # Project venv — keep in sync with requirements.txt
  if [ -f "${HOME}/bug-bounty-hunting-/requirements.txt" ]; then
    log "  Updating project venv…"
    python3 -m venv "${VENV}" 2>/dev/null || true
    "${VENV}/bin/pip" install -q -r "${HOME}/bug-bounty-hunting-/requirements.txt" 2>/dev/null || true
  fi
}

# ─── Phase 6: Wordlists ────────────────────────────────────────────────────────
install_wordlists() {
  section "Phase 6 — Wordlists"
  local wl="${HOME}/wordlists"
  mkdir -p "$wl"

  # SecLists — the foundation
  if [ ! -d "$wl/SecLists" ]; then
    log "  Cloning SecLists (shallow)…"
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$wl/SecLists" 2>/dev/null \
      || warn "  SecLists clone failed"
  else
    info "  SecLists ✓"
  fi

  # Assetnote API/parameter/route wordlists (the best for modern APIs)
  local assetnote_dir="$wl/assetnote"
  mkdir -p "$assetnote_dir"
  declare -A ASSETNOTE=(
    ["parameters_top1m.txt"]="https://wordlists-cdn.assetnote.io/data/manual/parameters_top_1m.txt"
    ["apiroutes_210228.txt"]="https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2021_02_28.txt"
    ["graphql_operations.txt"]="https://wordlists-cdn.assetnote.io/data/manual/graphql.txt"
    ["swagger_wordlist.txt"]="https://wordlists-cdn.assetnote.io/data/manual/swagger-wordlist.txt"
    ["raft-large-words.txt"]="https://wordlists-cdn.assetnote.io/data/automated/raft-large-words.txt"
  )
  for name in "${!ASSETNOTE[@]}"; do
    if [ -f "$assetnote_dir/$name" ]; then
      info "  assetnote/$name ✓"
      continue
    fi
    log "  Downloading assetnote/$name…"
    curl -fsSL "${ASSETNOTE[$name]}" -o "$assetnote_dir/$name" 2>/dev/null \
      || warn "  $name download failed"
  done

  # OneListForAll (combined max-coverage wordlist)
  if [ ! -f "$wl/onelistforall/onelistforallshort.txt" ]; then
    log "  Cloning OneListForAll…"
    git clone --depth 1 https://github.com/six2dez/OneListForAll.git "$wl/onelistforall" 2>/dev/null \
      || warn "  OneListForAll clone failed"
  else
    info "  OneListForAll ✓"
  fi

  # GF patterns (grep patterns for gf tool)
  local gf_dir="${HOME}/.gf"
  if [ ! -d "$gf_dir" ]; then
    log "  Installing gf patterns…"
    mkdir -p "$gf_dir"
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null \
      && cp /tmp/gf-patterns/*.json "$gf_dir/" && rm -rf /tmp/gf-patterns || warn "  gf patterns failed"
    # Plus tomnomnom's built-in patterns
    git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf-src 2>/dev/null \
      && cp -r /tmp/gf-src/examples/*.json "$gf_dir/" && rm -rf /tmp/gf-src || true
  else
    info "  gf patterns ✓"
  fi

  log "  Wordlists ready: $wl"
}

# ─── Phase 7: Nuclei templates ─────────────────────────────────────────────────
install_nuclei_templates() {
  section "Phase 7 — Nuclei Templates"
  command -v nuclei >/dev/null 2>&1 || { warn "nuclei not installed yet — skipping"; return; }

  log "  Official templates (nuclei -update-templates)…"
  nuclei -update-templates -silent 2>/dev/null || warn "  Official template update failed"

  local tpl_dir="${HOME}/nuclei-templates"
  mkdir -p "$tpl_dir"

  # ProjectDiscovery fuzzing templates
  if [ ! -d "$tpl_dir/fuzzing-templates" ]; then
    log "  Fuzzing templates…"
    git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git \
      "$tpl_dir/fuzzing-templates" 2>/dev/null || warn "  fuzzing-templates clone failed"
  else
    (cd "$tpl_dir/fuzzing-templates" && git pull -q 2>/dev/null) || true
    info "  fuzzing-templates ✓ (updated)"
  fi

  # community-templates (bb-specific patterns)
  if [ ! -d "$tpl_dir/community" ]; then
    log "  Community templates…"
    git clone --depth 1 https://github.com/geeknik/the-nuclei-templates.git \
      "$tpl_dir/community" 2>/dev/null || warn "  community templates clone failed"
  else
    info "  community templates ✓"
  fi

  # Custom SSRF/IDOR/auth bypass templates for Google VRP targets
  mkdir -p "$tpl_dir/custom"
  cat > "$tpl_dir/custom/expose-debug-endpoints.yaml" <<'TPLEOF'
id: expose-debug-endpoints
info:
  name: Debug/Internal Endpoints Exposed
  author: custom
  severity: medium
  tags: exposure,debug,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/_debug"
      - "{{BaseURL}}/_health"
      - "{{BaseURL}}/_status"
      - "{{BaseURL}}/_metrics"
      - "{{BaseURL}}/debug/vars"
      - "{{BaseURL}}/debug/pprof/"
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/health"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/mappings"
      - "{{BaseURL}}/actuator/beans"
      - "{{BaseURL}}/healthz"
      - "{{BaseURL}}/readyz"
      - "{{BaseURL}}/livez"
      - "{{BaseURL}}/admin/health"
      - "{{BaseURL}}/internal/health"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["status", "healthy", "goroutine", "heap", "version", "uptime"]
        condition: or
TPLEOF

  cat > "$tpl_dir/custom/feature-flags-exposed.yaml" <<'TPLEOF'
id: feature-flags-exposed
info:
  name: Feature Flag API Exposed (LaunchDarkly/Flagsmith/Split.io)
  author: custom
  severity: medium
  tags: exposure,config,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/sdk/latest-all"
      - "{{BaseURL}}/sdk/latest-flags"
      - "{{BaseURL}}/api/v1/flags"
      - "{{BaseURL}}/api/v1/environments"
      - "{{BaseURL}}/api/features"
      - "{{BaseURL}}/flags"
      - "{{BaseURL}}/features"
      - "{{BaseURL}}/config"
      - "{{BaseURL}}/all-flags"
    matchers-condition: or
    matchers:
      - type: word
        words: ["enabledFeatures", "featureFlags", "variations", "flagKey", "rollout"]
      - type: word
        words: ["sdk-key", "client-side-id", "environments", "launchdarkly"]
TPLEOF

  cat > "$tpl_dir/custom/graphql-introspection.yaml" <<'TPLEOF'
id: graphql-introspection-enabled
info:
  name: GraphQL Introspection Enabled
  author: custom
  severity: medium
  tags: graphql,exposure,misconfig

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
      - "{{BaseURL}}/query"
    headers:
      Content-Type: application/json
    body: '{"query":"{__schema{types{name}}}"}'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["__schema", "__Type", "types"]
TPLEOF

  log "  Custom templates written: debug-endpoints, feature-flags, graphql"
}

# ─── Phase 8: tmux + shell ─────────────────────────────────────────────────────
setup_shell() {
  section "Phase 8 — Shell + tmux"

  # tmux config for persistent hunt sessions
  cat > "${HOME}/.tmux.conf" <<'TMUX'
# Bug bounty lab tmux config
set -g default-terminal "screen-256color"
set -g mouse on
set -g history-limit 100000
set -g status-interval 5
set -g status-style bg=colour235,fg=colour136
set -g status-left '#[fg=green]#H #[fg=yellow]| '
set -g status-right '#[fg=cyan]CPU:#{cpu_percentage} #[fg=yellow]| #[fg=green]%H:%M'
set -g base-index 1
setw -g pane-base-index 1
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
bind r source-file ~/.tmux.conf \; display "Config reloaded"
# Fast pane switching
bind -n M-Left  select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up    select-pane -U
bind -n M-Down  select-pane -D
TMUX
  log "  .tmux.conf written"

  # Shell aliases for the hunt lab
  if ! grep -q '# bug-bounty-lab' "${HOME}/.bashrc" 2>/dev/null; then
    cat >> "${HOME}/.bashrc" <<'BASH'

# ── Bug bounty lab aliases ─────────────────────────────────────────
alias bb='cd ~/bug-bounty-hunting- && ./run.sh'
alias bbs='cd ~/bug-bounty-hunting- && ./run.sh'
alias bbstatus='cd ~/bug-bounty-hunting- && ./run.sh'
alias hunt='cd ~/bug-bounty-hunting- && ./run.sh'
alias nuclei-update='nuclei -update-templates -silent'
alias interactsh='interactsh-client -server oast.pro'

# Quick target scoping
scope-check() { bash ~/bug-bounty-hunting-/scripts/scope-check.sh "$@"; }

# Tmux hunt session launcher
hunt-session() {
  local target="${1:-wiz.io}"
  tmux new-session -d -s "hunt-$target" -x 220 -y 50 2>/dev/null || true
  tmux send-keys -t "hunt-$target" "cd ~/bug-bounty-hunting- && ./run.sh $target" Enter
  tmux attach -t "hunt-$target"
}

# Resource check shorthand
picheck() { ~/bug-bounty-hunting-/scripts/pi-resource-guard.sh --report; }

export GOPATH="${HOME}/go"
export PATH="$PATH:${HOME}/go/bin:/usr/local/go/bin:${HOME}/.local/bin"
BASH
    log "  Shell aliases added to .bashrc"
  else
    info "  Shell aliases already in .bashrc ✓"
  fi
}

# ─── Phase 9: API key config prompts ──────────────────────────────────────────
configure_api_keys() {
  section "Phase 9 — API Key Configuration"
  info "The following APIs amplify recon massively (optional but recommended):"
  echo ""
  echo "  Tool           Free Tier   Where to get"
  echo "  ─────────────────────────────────────────────────────────"
  echo "  Shodan         250 credits shodan.io → Account"
  echo "  Censys         250 queries censys.io → API"
  echo "  FOFA           1000/day    fofa.info → Account"
  echo "  GitHub         5000/hr     github.com → Settings → Tokens"
  echo "  SecurityTrails 50/month    securitytrails.com"
  echo "  BinaryEdge     250/month   binaryedge.io"
  echo ""
  echo "  After getting keys, add to ~/.bashrc or ~/bug-bounty-hunting-/config/api_keys.env:"
  echo "  export SHODAN_API_KEY=..."
  echo "  export CENSYS_API_ID=..."
  echo "  export CENSYS_API_SECRET=..."
  echo "  export GITHUB_TOKEN=..."
  echo "  export FOFA_EMAIL=..."
  echo "  export FOFA_KEY=..."
  echo "  export SECURITYTRAILS_KEY=..."
  echo ""
  echo "  Then configure subfinder: subfinder -config ~/.config/subfinder/provider-config.yaml"
  echo "  And uncover: uncover -shodan -censys -fofa (reads env vars)"
  echo ""

  # Create provider config template for subfinder
  local sf_cfg="${HOME}/.config/subfinder"
  mkdir -p "$sf_cfg"
  if [ ! -f "$sf_cfg/provider-config.yaml" ]; then
    cat > "$sf_cfg/provider-config.yaml" <<'SFCFG'
# Subfinder provider config — fill in API keys for maximum subdomain coverage
# Reference: https://github.com/projectdiscovery/subfinder#provider-configuration
binaryedge:
  - BINARYEDGE_KEY_HERE
censys:
  - CENSYS_ID:CENSYS_SECRET
certspotter: []
chaos:
  - CHAOS_KEY_HERE
fofa:
  - FOFA_EMAIL:FOFA_KEY_HERE
fullhunt:
  - FULLHUNT_KEY_HERE
github:
  - GITHUB_TOKEN_HERE
intelx:
  - INTELX_KEY_HERE
passivetotal: []
recon:
  - RECON_KEY_HERE
robtex: []
securitytrails:
  - SECURITYTRAILS_KEY_HERE
shodan:
  - SHODAN_KEY_HERE
threatbook: []
urlscan: []
virustotal:
  - VT_KEY_HERE
SFCFG
    log "  Subfinder provider template → $sf_cfg/provider-config.yaml"
    warn "  Edit with your API keys for maximum subdomain discovery"
  fi
}

# ─── Check mode ────────────────────────────────────────────────────────────────
check() {
  section "Toolchain Status"
  local tools=(
    go subfinder httpx dnsx naabu nuclei katana interactsh-client uncover
    ffuf dalfox crlfuzz puredns shuffledns jsluice trufflehog gitleaks
    hakrawler gospider anew waybackurls assetfinder gau arjun dirsearch
    sqlmap jwt_tool wfuzz cariddi cdncheck tlsx asnmap mapcidr notify
    nmap masscan jq tmux docker chromium-browser gf
  )
  local ok=0 missing=0
  for b in "${tools[@]}"; do
    if command -v "$b" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} $b"
      ((ok++))
    else
      echo -e "  ${RED}✗${NC} $b"
      ((missing++))
    fi
  done
  echo ""
  echo "  Installed: $ok / $((ok+missing))"
  echo ""
  log "Wordlists:"
  [ -d "${HOME}/wordlists/SecLists"   ] && echo -e "  ${GREEN}✓${NC} SecLists"      || echo -e "  ${RED}✗${NC} SecLists"
  [ -d "${HOME}/wordlists/assetnote"  ] && echo -e "  ${GREEN}✓${NC} Assetnote"     || echo -e "  ${RED}✗${NC} Assetnote"
  [ -d "${HOME}/wordlists/onelistforall" ] && echo -e "  ${GREEN}✓${NC} OneListForAll" || echo -e "  ${RED}✗${NC} OneListForAll"
  [ -d "${HOME}/.gf"                  ] && echo -e "  ${GREEN}✓${NC} gf patterns"   || echo -e "  ${RED}✗${NC} gf patterns"
  echo ""
  log "Nuclei templates:"
  local tpl="${HOME}/nuclei-templates"
  [ -d "${HOME}/.config/nuclei"         ] && echo -e "  ${GREEN}✓${NC} Official templates" || echo -e "  ${RED}✗${NC} Official templates"
  [ -d "$tpl/fuzzing-templates"         ] && echo -e "  ${GREEN}✓${NC} Fuzzing templates"  || echo -e "  ${RED}✗${NC} Fuzzing templates"
  [ -d "$tpl/custom"                    ] && echo -e "  ${GREEN}✓${NC} Custom templates"   || echo -e "  ${RED}✗${NC} Custom templates"
  echo ""
  log "System:"
  local gov; gov="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  echo "  CPU governor: $gov"
  local ulimit_n; ulimit_n="$(ulimit -n)"
  echo "  File descriptors: $ulimit_n"
  swapon --show 2>/dev/null | grep -q swapfile && echo -e "  ${GREEN}✓${NC} Swap active" || echo -e "  ${YELLOW}!${NC} No swap (run ./scripts/setup-pi.sh --system)"
}

# ─── Upgrade mode (update everything already installed) ────────────────────────
upgrade() {
  section "Upgrade — updating all installed tools"
  ensure_path

  log "Updating Go tools…"
  for bin in subfinder httpx dnsx naabu nuclei katana interactsh-client \
             uncover mapcidr notify asnmap cdncheck tlsx cariddi \
             anew waybackurls assetfinder gau ffuf dalfox crlfuzz \
             puredns shuffledns jsluice trufflehog gitleaks hakrawler \
             gospider cloudbrute s3scanner gf; do
    command -v "$bin" >/dev/null 2>&1 && {
      log "  updating $bin…"
      GOFLAGS=-buildvcs=false go install "$(go version -m "$(command -v "$bin")" 2>/dev/null | awk '/path/{print $2}')@latest" 2>/dev/null || true
    }
  done

  log "Updating nuclei templates…"
  nuclei -update-templates -silent 2>/dev/null || true
  [ -d "${HOME}/nuclei-templates/fuzzing-templates" ] && \
    (cd "${HOME}/nuclei-templates/fuzzing-templates" && git pull -q 2>/dev/null) || true
  [ -d "${HOME}/nuclei-templates/community" ] && \
    (cd "${HOME}/nuclei-templates/community" && git pull -q 2>/dev/null) || true

  log "Updating project venv…"
  [ -f "${HOME}/bug-bounty-hunting-/requirements.txt" ] && \
    "${VENV}/bin/pip" install -q -r "${HOME}/bug-bounty-hunting-/requirements.txt" 2>/dev/null || true

  log "Upgrade complete."
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║     Bug Bounty Lab Setup — Raspberry Pi 5 / ARM64           ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  case "${1:-all}" in
    --check)     check ;;
    --system)    tune_system ;;
    --tools)     ensure_path; install_go; install_go_tools; install_python_tools; check ;;
    --wordlists) install_wordlists ;;
    --templates) install_nuclei_templates ;;
    --upgrade)   upgrade; check ;;
    all|*)
      tune_system
      install_base
      install_go
      install_go_tools
      install_python_tools
      install_wordlists
      install_nuclei_templates
      setup_shell
      configure_api_keys
      check
      echo ""
      log "Done! Next steps:"
      echo "  1. source ~/.bashrc"
      echo "  2. Edit ~/.config/subfinder/provider-config.yaml (add API keys)"
      echo "  3. Set: export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/..."
      echo "  4. Set: export ANTHROPIC_API_KEY=sk-ant-..."
      echo "  5. Start a hunt: hunt-session wiz.io   (tmux session)"
      ;;
  esac
}

main "$@"
