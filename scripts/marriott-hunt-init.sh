#!/usr/bin/env bash
# marriott-hunt-init.sh — initialize environment for a Marriott hunting session.
#
# Usage: source scripts/marriott-hunt-init.sh   (bash and zsh compatible)

BB="${BB:-$HOME/bug-bounty-hunting-}"
export SCOPE_FILE="$BB/config/marriott-scope.yaml"
export HUNT_PROGRAM="marriott"
export HUNT_RESULTS="$BB/results/marriott"

# Remove any stale aliases from previous sessions before defining functions.
# zsh parses function NAME() before executing unalias on the same line → must be separate lines.
unalias scope-check 2>/dev/null || true
unalias hunt-log    2>/dev/null || true
unalias runbook     2>/dev/null || true
unalias hunt-status 2>/dev/null || true
unalias hunt-live   2>/dev/null || true

# Use `function NAME { }` (no parentheses) — safe even when an alias NAME exists in zsh
function scope-check  { SCOPE_FILE="$SCOPE_FILE" "$BB/scripts/scope-check.sh" "$@"; }
function hunt-log     { cat "$HUNT_RESULTS/HUNT-LOG.md" | less -R; }
function runbook      { cat "$HUNT_RESULTS/runbooks/PI-RUNBOOK-marriott-${1:-session2}.md" | less -R; }
function hunt-status  { grep -E "^\| M[0-9]+" "$HUNT_RESULTS/HUNT-LOG.md" | column -t -s'|'; }
function hunt-live    { grep "200\|301\|302\|401" "$HUNT_RESULTS/HUNT-LOG.md" 2>/dev/null | head -20; }

# Ensure hunt output directories exist
mkdir -p "$HOME/hunt" "$HUNT_RESULTS/session2" "$HUNT_RESULTS/findings"

# Export functions so subshells can use them
export -f scope-check 2>/dev/null || true

echo "[marriott] Hunt session initialized"
echo "  BB:      $BB"
echo "  Scope:   $SCOPE_FILE"
echo "  Results: $HUNT_RESULTS"
echo "  Hunt dir: $HOME/hunt"
echo ""
echo "  Commands:"
echo "    scope-check <host>          — verify host is in scope"
echo "    hunt-log                    — read full hunt log"
echo "    runbook [session1|session2] — read Pi runbook"
echo "    hunt-status                 — show lead tracker"
