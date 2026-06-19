#!/usr/bin/env bash
# hunt-workspace.sh — Launch a full multi-pane tmux hunt workspace for a target
#
# Usage:
#   ./scripts/hunt-workspace.sh <target>           # full 4-pane workspace
#   ./scripts/hunt-workspace.sh <target> --attach  # attach if session exists
#   ./scripts/hunt-workspace.sh --list             # show active sessions
#   ./scripts/hunt-workspace.sh --kill <target>    # kill a session
#
# Layout created:
#
#   Window 1: recon      Window 2: scan       Window 3: monitor
#   ┌──────┬──────┐      ┌──────────────┐     ┌──────────────────┐
#   │shell │notes │      │  nuclei/     │     │  pi-resource-    │
#   │      │      │      │  httpx run   │     │  guard watch     │
#   ├──────┴──────┤      │              │     ├──────────────────┤
#   │  OOB log   │      └──────────────┘     │  scan results    │
#   └────────────┘                            └──────────────────┘

set -uo pipefail

BB="${HOME}/bug-bounty-hunting-"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[+]${NC} $*"; }
info() { echo -e "  ${CYAN}[*]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }

# ─── Argument parsing ──────────────────────────────────────────────

if [ "${1:-}" = "--list" ]; then
  echo ""
  echo "Active hunt sessions:"
  tmux ls 2>/dev/null | grep "^hunt-" || echo "  (none)"
  echo ""
  exit 0
fi

if [ "${1:-}" = "--kill" ]; then
  target="${2:?Usage: hunt-workspace.sh --kill <target>}"
  session="hunt-$(echo "$target" | tr '.' '-')"
  tmux kill-session -t "$session" 2>/dev/null && ok "Killed: $session" || warn "Session not found: $session"
  exit 0
fi

TARGET="${1:?Usage: hunt-workspace.sh <target.com>}"
ATTACH_ONLY="${2:-}"

# Clean target name for session / directory use
SESSION="hunt-$(echo "$TARGET" | tr '.' '-')"
RESULTS_DIR="${BB}/results/${TARGET}"

# ─── Scope check ───────────────────────────────────────────────────
if ! bash "${BB}/scripts/scope-check.sh" "$TARGET" 2>/dev/null | grep -q "IN-SCOPE"; then
  echo ""
  warn "SCOPE CHECK FAILED: $TARGET is not in scope."
  warn "Edit config/scope.yaml to add it, or verify the target name."
  echo ""
  exit 1
fi

# ─── Attach to existing session ────────────────────────────────────
if tmux has-session -t "$SESSION" 2>/dev/null; then
  info "Session $SESSION already exists"
  if [ "${ATTACH_ONLY}" = "--attach" ] || [ -t 0 ]; then
    ok "Attaching…"
    tmux attach -t "$SESSION"
  else
    warn "Use --attach or run from an interactive terminal"
  fi
  exit 0
fi

# ─── Resource check ────────────────────────────────────────────────
echo ""
info "Pi resource check before launching workspace…"
"${BB}/scripts/pi-resource-guard.sh" --report
echo ""

# ─── Create result directories ─────────────────────────────────────
mkdir -p "${RESULTS_DIR}/findings" \
         "${RESULTS_DIR}/evidence" \
         "${RESULTS_DIR}/recon/subdomains" \
         "${RESULTS_DIR}/recon/ports" \
         "${RESULTS_DIR}/recon/urls"
ok "Result dirs: ${RESULTS_DIR}"

# ─── Create tmux session ───────────────────────────────────────────
info "Creating tmux session: $SESSION"

# Window 1: recon (main shell + OOB log)
tmux new-session  -d -s "$SESSION" -n "recon" -x 220 -y 55

# Top-left: main shell with context banner
tmux send-keys -t "$SESSION:recon" \
  "cd ${BB} && clear && echo '' && echo '  Target: ${TARGET}' && echo '  Session: ${SESSION}' && echo '  Results: ${RESULTS_DIR}' && echo '' && picheck" Enter

# Top-right pane: notes / scratchpad
tmux split-window -t "$SESSION:recon" -h -p 30
tmux send-keys -t "$SESSION:recon.2" \
  "cd ${RESULTS_DIR} && echo '# ${TARGET} — Hunt Notes' > notes.md && nano notes.md" Enter

# Bottom pane: OOB listener (started automatically)
tmux split-window -t "$SESSION:recon.1" -v -p 25
tmux send-keys -t "$SESSION:recon.3" \
  "cd /tmp && echo '[*] Starting OOB listener...' && interactsh-client -server oast.pro -v 2>&1 | tee /tmp/oob-${TARGET}.log" Enter

# Window 2: scan (nuclei/httpx/ffuf)
tmux new-window -t "$SESSION" -n "scan"
tmux send-keys -t "$SESSION:scan" \
  "cd ${RESULTS_DIR} && echo '[*] Scan window ready. Commands:' && echo '  httpx -l recon/subdomains/alive.txt -o recon/ports/http-services.txt' && echo '  nuclei -l recon/ports/http-services.txt -config ~/.config/nuclei/config.yaml -o findings/nuclei-$(date +%Y%m%d).txt'" Enter

# Window 3: monitor (resource watch)
tmux new-window -t "$SESSION" -n "monitor"
tmux send-keys -t "$SESSION:monitor" \
  "watch -n 5 '${BB}/scripts/pi-resource-guard.sh --report && echo \"\" && echo \"── Active scans ──\" && ps aux | grep -E \"nuclei|httpx|subfinder|ffuf\" | grep -v grep | head -8'" Enter

# Window 4: results (tail finding logs)
tmux new-window -t "$SESSION" -n "results"
tmux send-keys -t "$SESSION:results" \
  "cd ${RESULTS_DIR}/findings && echo '[*] Watching findings directory...' && ls -la && echo '' && echo 'Run: tail -f nuclei-*.txt'" Enter

# Go back to recon window
tmux select-window -t "$SESSION:recon"
tmux select-pane  -t "$SESSION:recon.1"

# ─── Summary ───────────────────────────────────────────────────────
echo ""
ok "Workspace ready: $SESSION"
echo ""
echo "  Windows:"
echo "    1: recon   — main shell + notes + OOB listener"
echo "    2: scan    — nuclei / httpx / ffuf"
echo "    3: monitor — Pi resource watch"
echo "    4: results — finding logs"
echo ""
echo "  Keybindings (after attach):"
echo "    Ctrl-a + |   split vertical"
echo "    Ctrl-a + -   split horizontal"
echo "    Alt+←/→     switch panes"
echo "    Shift+←/→   switch windows"
echo "    Ctrl-a + r   reload tmux config"
echo "    Ctrl-a + H   add 3-pane hunt layout"
echo "    Ctrl-a + M   open resource monitor window"
echo ""

# Attach
if [ -t 0 ]; then
  ok "Attaching to session…"
  sleep 1
  tmux attach -t "$SESSION"
else
  info "Run: tmux attach -t $SESSION"
fi
