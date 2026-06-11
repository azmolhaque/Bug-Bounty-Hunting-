#!/usr/bin/env bash
# setup-pi.sh — provision a Raspberry Pi 5 (16 GB, ARM64 / Raspberry Pi OS 64-bit
# or Ubuntu 24.04 arm64) as a bug bounty hunting workstation for this agent.
#
# Installs the Go-based recon/scan toolchain (all have native arm64 builds),
# Python helpers, and wordlists. Idempotent: safe to re-run.
#
# Usage:  ./scripts/setup-pi.sh            # full install
#         ./scripts/setup-pi.sh --tools    # just the Go tools
#         ./scripts/setup-pi.sh --check     # verify what's installed
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

ARCH="$(uname -m)"
[ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] || warn "Arch is $ARCH, not arm64 — this script is tuned for Raspberry Pi 5."

GO_VERSION="1.22.5"
GOPATH_BIN="${HOME}/go/bin"

ensure_path() {
  case ":$PATH:" in *":$GOPATH_BIN:"*) ;; *)
    echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> "${HOME}/.bashrc"
    export PATH="$PATH:$GOPATH_BIN:/usr/local/go/bin" ;;
  esac
}

install_base() {
  log "Installing base packages (apt)…"
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    git curl wget jq unzip build-essential ca-certificates \
    python3 python3-pip python3-venv \
    dnsutils whois nmap libpcap-dev chromium-browser >/dev/null
}

install_go() {
  if command -v go >/dev/null 2>&1; then log "Go already present: $(go version)"; return; fi
  log "Installing Go ${GO_VERSION} (arm64)…"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
  ensure_path
}

install_go_tools() {
  ensure_path
  log "Installing ProjectDiscovery + recon toolchain (arm64 native)…"
  local tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/d3mondev/puredns/v2@latest"
  )
  for t in "${tools[@]}"; do
    local name="${t##*/}"; name="${name%%@*}"
    if command -v "$name" >/dev/null 2>&1; then log "  $name ✓ (already installed)"; continue; fi
    log "  go install $name…"
    GOFLAGS=-buildvcs=false go install -v "$t" 2>/dev/null || warn "  $name failed — install manually"
  done
}

install_python_tools() {
  log "Installing Python helpers (arjun via pipx — works on Debian trixie/PEP-668)…"
  if ! command -v pipx >/dev/null 2>&1; then
    sudo apt-get install -y --no-install-recommends pipx >/dev/null
  fi
  if command -v arjun >/dev/null 2>&1; then log "  arjun ✓ (already installed)"; return; fi
  pipx install arjun 2>/dev/null || warn "  arjun pipx install failed — run: pipx install arjun"
  pipx ensurepath 2>/dev/null || true
}

install_wordlists() {
  local wl="${HOME}/wordlists"
  [ -d "$wl/SecLists" ] && { log "SecLists already present."; return; }
  log "Cloning SecLists (shallow)…"
  mkdir -p "$wl"
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$wl/SecLists" 2>/dev/null \
    || warn "SecLists clone failed — clone manually into $wl"
}

update_nuclei_templates() {
  command -v nuclei >/dev/null 2>&1 && { log "Updating nuclei templates…"; nuclei -update-templates -silent 2>/dev/null || true; }
}

check() {
  log "Toolchain check:"
  for b in go subfinder httpx dnsx naabu nuclei katana gau ffuf amass anew dalfox nmap jq arjun; do
    if command -v "$b" >/dev/null 2>&1; then echo -e "  ${GREEN}✓${NC} $b"; else echo -e "  ${RED}✗${NC} $b"; fi
  done
}

main() {
  case "${1:-all}" in
    --check) check ;;
    --tools) install_go; install_go_tools; update_nuclei_templates; check ;;
    all|*)
      install_base; install_go; install_go_tools; install_python_tools
      install_wordlists; update_nuclei_templates; check
      log "Done. Run 'source ~/.zshrc' (zsh) or 'source ~/.bashrc' (bash), or re-login."
      warn "Reminder: populate config/scope.yaml before hunting. No scope, no hunt." ;;
  esac
}
main "$@"
