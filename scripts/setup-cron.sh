#!/usr/bin/env bash
# setup-cron.sh — Configure automated Pi 5 bug bounty cron jobs
#
# Jobs installed:
#   • 02:00 daily  — nuclei template update
#   • 03:00 daily  — subdomain monitoring (all active targets)
#   • 04:00 daily  — Pi optimization cleanup (cache, logs)
#   • 06:00 weekly — full tool upgrade via pdtm
#
# Usage:
#   ./scripts/setup-cron.sh          # install all jobs
#   ./scripts/setup-cron.sh --list   # show current cron
#   ./scripts/setup-cron.sh --remove # remove all bb-lab jobs

set -uo pipefail

BB="${HOME}/bug-bounty-hunting-"
LOG_DIR="${BB}/results/cron-logs"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[+]${NC} $*"; }
info() { echo -e "  ${CYAN}[*]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }

mkdir -p "$LOG_DIR"

case "${1:---install}" in

# ─── List ──────────────────────────────────────────────────────────
--list)
  echo ""
  echo "Current crontab:"
  crontab -l 2>/dev/null || echo "  (empty)"
  echo ""
  exit 0
  ;;

# ─── Remove ────────────────────────────────────────────────────────
--remove)
  echo ""
  info "Removing bug bounty lab cron jobs..."
  ( crontab -l 2>/dev/null | grep -v "# bb-lab" ) | crontab -
  ok "Removed all bb-lab cron jobs"
  echo ""
  crontab -l 2>/dev/null || echo "(crontab now empty)"
  exit 0
  ;;

# ─── Install ───────────────────────────────────────────────────────
--install|-*)

  echo ""
  echo "Installing bug bounty lab cron jobs..."
  echo ""

  # Build the nuclei update job
  NUCLEI_UPDATE_CMD="nuclei -update-templates -silent >> ${LOG_DIR}/nuclei-update.log 2>&1"

  # Build the subdomain monitor job
  # Reads active targets from config/scope.yaml and runs subfinder on each
  SUBDOMAIN_MONITOR_CMD="bash ${BB}/scripts/subdomain-monitor-cron.sh >> ${LOG_DIR}/subdomain-monitor.log 2>&1"

  # Build the cleanup job
  CLEANUP_CMD="sudo ${BB}/scripts/pi-optimize.sh --clean >> ${LOG_DIR}/cleanup.log 2>&1"

  # Build the tool upgrade job (weekly, Sunday 06:00)
  UPGRADE_CMD="bash ${BB}/scripts/setup-pi.sh --upgrade >> ${LOG_DIR}/upgrade.log 2>&1"

  # Discord notification wrapper
  NOTIFY_CMD="curl -sS -X POST \"\${DISCORD_WEBHOOK_URL}\" -H 'Content-Type: application/json'"

  # ── Install cron entries ──────────────────────────────────────────
  # Read existing crontab (excluding our old bb-lab entries)
  EXISTING=$(crontab -l 2>/dev/null | grep -v "# bb-lab" || true)

  # Write new crontab
  (
    echo "$EXISTING"
    echo ""
    echo "# ── Bug bounty lab automated jobs ── # bb-lab"
    echo "# Logs: ${LOG_DIR}/"
    echo ""
    echo "# 02:00 daily — update nuclei templates"
    echo "0 2 * * * PATH=/usr/local/go/bin:\$HOME/go/bin:\$HOME/.pdtm/go/bin:/usr/local/bin:/usr/bin:/bin $NUCLEI_UPDATE_CMD # bb-lab"
    echo ""
    echo "# 03:00 daily — subdomain monitoring (new assets + takeover check)"
    echo "0 3 * * * PATH=/usr/local/go/bin:\$HOME/go/bin:\$HOME/.pdtm/go/bin:/usr/local/bin:/usr/bin:/bin $SUBDOMAIN_MONITOR_CMD # bb-lab"
    echo ""
    echo "# 04:00 daily — Pi cleanup (cache, logs, temp files)"
    echo "0 4 * * * $CLEANUP_CMD # bb-lab"
    echo ""
    echo "# 06:00 every Sunday — full tool upgrade"
    echo "0 6 * * 0 PATH=/usr/local/go/bin:\$HOME/go/bin:\$HOME/.pdtm/go/bin:/usr/local/bin:/usr/bin:/bin bash ${BB}/scripts/setup-pi.sh --upgrade >> ${LOG_DIR}/upgrade.log 2>&1 # bb-lab"
    echo ""
  ) | crontab -

  ok "Nuclei template update  — daily 02:00"
  ok "Subdomain monitor       — daily 03:00"
  ok "Pi cleanup              — daily 04:00"
  ok "Full tool upgrade       — weekly Sun 06:00"
  echo ""
  info "Logs will be in: ${LOG_DIR}/"
  echo ""

  # Verify
  echo "Installed crontab:"
  crontab -l | grep "bb-lab"
  echo ""
  ;;
esac
