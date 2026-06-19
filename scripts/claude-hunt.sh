#!/usr/bin/env bash
# claude-hunt.sh — Launch Claude Code as an autonomous bug bounty agent
#
# Usage:
#   ./scripts/claude-hunt.sh <target>              # full workflow (all phases)
#   ./scripts/claude-hunt.sh <target> --recon      # Phase 1-2 only
#   ./scripts/claude-hunt.sh <target> --hunt       # Phase 3-4 only
#   ./scripts/claude-hunt.sh <target> --triage     # Phase 5 only
#   ./scripts/claude-hunt.sh <target> --report     # Phase 6 only
#   ./scripts/claude-hunt.sh <target> --pipe       # non-interactive, pipe output
#
# Claude reads CLAUDE.md from the repo root and operates autonomously.
# Results are written to results/<target>/

set -uo pipefail

BB="${HOME}/bug-bounty-hunting-"
TARGET="${1:?Usage: claude-hunt.sh <target.com> [--recon|--hunt|--triage|--report|--pipe]}"
MODE="${2:---workflow}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

# Verify ANTHROPIC_API_KEY is set
[ -z "${ANTHROPIC_API_KEY:-}" ] && {
  [ -f "${HOME}/.secrets.zsh" ] && source "${HOME}/.secrets.zsh"
}
[ -z "${ANTHROPIC_API_KEY:-}" ] && {
  warn "ANTHROPIC_API_KEY not set. Add it to ~/.secrets.zsh:"
  warn "  export ANTHROPIC_API_KEY=\"sk-ant-...\""
  exit 1
}

# Scope check first
info "Scope check: $TARGET"
if ! bash "${BB}/scripts/scope-check.sh" "$TARGET" 2>/dev/null | grep -q "IN-SCOPE"; then
  warn "OUT OF SCOPE: $TARGET — aborting"
  exit 1
fi
ok "Scope check passed: $TARGET"

# Build the phase prompt based on mode
case "$MODE" in
  --recon)
    PHASE_PROMPT="Run ONLY Phase 1 (Asset Discovery) and Phase 2 (Attack Surface Mapping) from CLAUDE.md on target: $TARGET
- Use: subfinder, httpx, katana, gau, dnsx, waybackurls
- Check for subdomain takeover candidates with subzy
- Write all results to results/$TARGET/recon/
- Summarize findings in results/$TARGET/HUNT-LOG.md"
    SESSION_NAME="recon-$TARGET"
    ;;
  --hunt)
    PHASE_PROMPT="Run ONLY Phase 3 (Vulnerability Discovery) and Phase 4 (Verification & PoC) from CLAUDE.md on target: $TARGET
- Load existing recon from results/$TARGET/recon/
- Prioritize: SSRF, IDOR, auth bypass, subdomain takeover
- Use nuclei, manual testing, OOB via interactsh
- Write confirmed findings to results/$TARGET/findings/
- Apply Section 3 Hard Rejection List — do NOT log findings that would be rejected"
    SESSION_NAME="hunt-$TARGET"
    ;;
  --triage)
    PHASE_PROMPT="Run ONLY Phase 5 (Triage, Dedup & Submission Gate) from CLAUDE.md on target: $TARGET
- Load all candidates from results/$TARGET/findings/
- Apply CVSS 3.1 scoring, check deduplication against prior findings
- Apply Section 2 Submission Quality Bar — mark each finding: SUBMIT / CHAIN / REJECT
- Output a ranked, triage-ready finding list to results/$TARGET/findings/TRIAGE-REPORT.md"
    SESSION_NAME="triage-$TARGET"
    ;;
  --report)
    PHASE_PROMPT="Run ONLY Phase 6 (Reporting) from CLAUDE.md on target: $TARGET
- Load triage-approved findings from results/$TARGET/findings/
- Write a triager-grade Google VRP report for each SUBMIT-level finding
- Reports go to results/$TARGET/findings/submission/
- Include: title, summary, severity, CVSS, repro steps, PoC, impact, remediation, references
- Each report must pass all 5 criteria in CLAUDE.md Section 2"
    SESSION_NAME="report-$TARGET"
    ;;
  --pipe)
    # Non-interactive: output to stdout, useful for piping
    info "Running in pipe mode (non-interactive output)..."
    cd "$BB" && claude -p \
      --permission-mode auto \
      "Target: $TARGET — Run the full bug bounty workflow from CLAUDE.md. Scope is confirmed IN-SCOPE. Operate autonomously. Write all results to results/$TARGET/"
    exit 0
    ;;
  --workflow|*)
    PHASE_PROMPT="Run the complete bug bounty hunting workflow per CLAUDE.md on target: $TARGET

Scope is confirmed IN-SCOPE. Proceed autonomously through all phases:

Phase 1 — Asset Discovery: subfinder, dnsx, waybackurls, gau, katana
Phase 2 — Attack Surface Mapping: httpx, JS analysis, param discovery
Phase 3 — Vulnerability Discovery: nuclei (medium+), manual SSRF/IDOR/auth-bypass testing
Phase 4 — Verification: reproduce every candidate, minimize PoC, confirm impact
Phase 5 — Triage: apply CLAUDE.md Section 2 quality bar + Section 3 rejection list
Phase 6 — Reporting: write submission-ready report for any confirmed finding

Rules:
- Check scope.yaml first. Stop if any host is out of scope.
- No DoS, no destructive payloads, no brute force
- OOB interactions only via interactsh (oast.pro)
- Write all results to results/$TARGET/
- Log every decision in results/$TARGET/HUNT-LOG.md"
    SESSION_NAME="workflow-$TARGET"
    ;;
esac

echo ""
info "Launching Claude Code autonomous agent"
info "Target:  $TARGET"
info "Mode:    $MODE"
info "Session: $SESSION_NAME"
info "Results: ${BB}/results/${TARGET}/"
echo ""

# Create result directory tree
mkdir -p "${BB}/results/${TARGET}"/{findings/submission,evidence,recon/{subdomains,ports,urls}}

# Run Claude interactively (attach to current terminal)
cd "$BB" && claude \
  --permission-mode auto \
  --name "$SESSION_NAME" \
  -p "$PHASE_PROMPT"
