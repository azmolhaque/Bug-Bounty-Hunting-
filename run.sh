#!/usr/bin/env bash
# run.sh — Single entry point for the bug bounty hunting pipeline on Pi 5
#
# This script is the ONE command you run on the Raspberry Pi. It:
#   1. Verifies the environment (tools, scope, git branch)
#   2. Delegates to the master orchestrator (scripts/agent-orchestrate.sh)
#   3. Provides a status dashboard when called without a target
#
# Usage:
#   ./run.sh                          → status dashboard (all active hunts)
#   ./run.sh wiz.io                   → full pipeline for wiz.io (resume if running)
#   ./run.sh wiz.io --phase 3         → run Phase 3 only
#   ./run.sh wiz.io --phase 3-4       → run Phases 3 and 4
#   ./run.sh wiz.io --background      → Phase 1+2 recon in background
#   ./run.sh wiz.io --status          → print status, exit
#   ./run.sh wiz.io --dry-run         → plan only, no active probes
#   ./run.sh wiz.io --force           → re-run even completed phases
#
# Environment (optional):
#   WIZ_JWT=eyJ...       set before running Phase 4 trial-account attacks
#   INTERACTSH_URL=...   OOB listener for SSRF blind confirmation

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH

# ─────────────────────────────────────────────────────────────────────────────
# Colors (if terminal supports it)
# ─────────────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; RST='\033[0m'
else
  RED=''; YLW=''; GRN=''; BLU=''; RST=''
fi

banner() {
  echo ""
  echo "${BLU}╔══════════════════════════════════════════════════════════════════╗${RST}"
  echo "${BLU}║       Bug Bounty Hunt Pipeline  —  Pi 5 / 16 GB ARM64           ║${RST}"
  echo "${BLU}╚══════════════════════════════════════════════════════════════════╝${RST}"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Environment preflight
# ─────────────────────────────────────────────────────────────────────────────
preflight() {
  local ok=true

  echo "Preflight checks:"

  # Git branch
  local branch; branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
  printf "  Git branch:   "
  if echo "$branch" | grep -q "claude/bug-bounty-methodology"; then
    echo "${GRN}${branch}${RST}"
  else
    echo "${YLW}${branch}${RST} (expected: claude/bug-bounty-methodology-*)"
  fi

  # Scope file
  printf "  Scope file:   "
  if [ -f "config/scope.yaml" ] && grep -q "in_scope:" "config/scope.yaml"; then
    echo "${GRN}OK${RST}"
  else
    echo "${RED}MISSING or EMPTY — populate config/scope.yaml before hunting${RST}"
    ok=false
  fi

  # Required scripts
  local required_scripts=("scope-check.sh" "recon.sh" "agent-orchestrate.sh" "lead-qualify.sh" "chain-graph.sh")
  printf "  Scripts:      "
  local missing_scripts=()
  for s in "${required_scripts[@]}"; do
    [ -f "scripts/$s" ] || missing_scripts+=("$s")
  done
  if [ "${#missing_scripts[@]}" -eq 0 ]; then
    echo "${GRN}OK${RST}"
  else
    echo "${RED}MISSING: ${missing_scripts[*]}${RST}"
    ok=false
  fi

  # Key tools
  printf "  Tools:        "
  local have=() missing_tools=()
  for tool in nuclei subfinder httpx dnsx python3 dig curl; do
    if command -v "$tool" &>/dev/null; then
      have+=("$tool")
    else
      missing_tools+=("$tool")
    fi
  done
  if [ "${#missing_tools[@]}" -eq 0 ]; then
    echo "${GRN}${have[*]}${RST}"
  else
    echo "${YLW}available: ${have[*]:-none} / missing: ${missing_tools[*]}${RST}"
    echo "    Run: ./scripts/setup-pi.sh to install missing tools"
  fi

  # Pi resources
  printf "  Pi resources: "
  ./scripts/pi-resource-guard.sh --report 2>/dev/null || echo "(resource check unavailable)"

  echo ""
  $ok || { echo "${RED}Preflight FAILED — fix issues above before hunting${RST}"; exit 1; }
}

# ─────────────────────────────────────────────────────────────────────────────
# Status dashboard (no target given)
# ─────────────────────────────────────────────────────────────────────────────
status_dashboard() {
  echo "Active hunts in results/:"
  echo ""

  local found=false
  for state_file in results/*/.orchestrator-state.json; do
    [ -f "$state_file" ] || continue
    found=true
    local target; target=$(python3 -c "import json; d=json.load(open('$state_file')); print(d.get('target','?'))" 2>/dev/null || echo "?")
    local current_phase; current_phase=$(python3 -c "import json; d=json.load(open('$state_file')); print(d.get('current_phase','?'))" 2>/dev/null || echo "?")
    printf "  %-30s  phase=%s\n" "$target" "$current_phase"
  done

  if ! $found; then
    echo "  (no active hunts — run: ./run.sh <target>)"
    echo ""
    echo "  Available targets in scope:"
    if [ -f "config/scope.yaml" ]; then
      grep -A 20 "^in_scope:" config/scope.yaml | grep "^\s*-" | sed 's/.*- /    /'
    fi
  fi

  echo ""
  echo "Quick commands:"
  echo "  ./run.sh wiz.io                  full pipeline"
  echo "  ./run.sh wiz.io --phase 3        vuln discovery only"
  echo "  ./run.sh wiz.io --phase 4        verification + chain elevation"
  echo "  ./run.sh wiz.io --status         status summary"
  echo "  ./run.sh wiz.io --background     recon in background (Pi-safe)"
  echo ""
  echo "Chain graph:"
  echo "  ./scripts/chain-graph.sh report wiz.io"
  echo ""
  echo "Lead qualification (standalone):"
  echo "  ./scripts/lead-qualify.sh <class> <confidence> <impact> <evidence>"
  echo ""
  echo "Resource monitor:"
  echo "  ./scripts/pi-resource-guard.sh --report"
}

# ─────────────────────────────────────────────────────────────────────────────
# Make scripts executable
# ─────────────────────────────────────────────────────────────────────────────
chmod +x scripts/agent-orchestrate.sh scripts/lead-qualify.sh scripts/chain-graph.sh \
         scripts/pi-resource-guard.sh scripts/scope-check.sh scripts/recon.sh \
         2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# Main dispatch
# ─────────────────────────────────────────────────────────────────────────────
banner

# No target → dashboard
if [ $# -eq 0 ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  preflight
  status_dashboard
  exit 0
fi

# Target given — run preflight then orchestrate
TARGET="$1"; shift

preflight

echo "Starting hunt: ${GRN}$TARGET${RST}"
echo ""

exec ./scripts/agent-orchestrate.sh "$TARGET" "$@"
