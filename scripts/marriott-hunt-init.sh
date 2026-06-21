#!/usr/bin/env bash
# marriott-hunt-init.sh — initialize environment for a Marriott hunting session.
#
# Usage: source scripts/marriott-hunt-init.sh
#
# Sets env vars + aliases so you can run scope-check, read the hunt log,
# and open the runbook without typing long paths.

export SCOPE_FILE="${BB:-$HOME/bug-bounty-hunting-}/config/marriott-scope.yaml"
export HUNT_PROGRAM="marriott"
export HUNT_RESULTS="${BB:-$HOME/bug-bounty-hunting-}/results/marriott"

alias scope-check='SCOPE_FILE="$SCOPE_FILE" ~/bug-bounty-hunting-/scripts/scope-check.sh'
alias hunt-log='cat "$HUNT_RESULTS/HUNT-LOG.md"'
alias runbook='cat "$HUNT_RESULTS/runbooks/PI-RUNBOOK-marriott-session1.md"'

echo "[marriott] Hunt session initialized"
echo "  Scope:   $SCOPE_FILE"
echo "  Results: $HUNT_RESULTS"
echo "  Check scope: scope-check <host>"
