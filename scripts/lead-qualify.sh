#!/usr/bin/env bash
# lead-qualify.sh — Standalone 5-point Lead Qualification Gate
#
# Answers the 3 questions from METHODOLOGY.md §3 (plus scope + severity gates)
# in under 60 seconds, purely from metadata — no HTTP requests.
#
# Usage:
#   ./scripts/lead-qualify.sh <class> <confidence> <impact> <evidence>
#
# Output (stdout):
#   PURSUE:HIGH:<score>/5:<reason>       score 4-5
#   PURSUE:MARGINAL:<score>/5:<reason>   score 3
#   AUTO_CLOSE:<score>/5:<reason>        score 0-2
#
# Exit codes:
#   0 = PURSUE (any tier)
#   1 = AUTO_CLOSE
#   2 = error / bad args
#
# Examples:
#   ./scripts/lead-qualify.sh "SSRF-blind" "HIGH" "Reach internal metadata" "OOB DNS hit"
#   → PURSUE:HIGH:5/5:clean
#
#   ./scripts/lead-qualify.sh "missing-header" "MEDIUM" "CSP header absent" "curl -I"
#   → AUTO_CLOSE:0/5:Q1: no concrete attacker gain; Q2: documented-intended; Q3: won't fix; Q5: hard-rejection-list

set -uo pipefail

CLASS="${1:-}"
CONFIDENCE="${2:-MEDIUM}"
IMPACT="${3:-}"
EVIDENCE="${4:-}"

[ -n "$CLASS" ] || { echo "Usage: $0 <class> <confidence> <impact> <evidence>" >&2; exit 2; }

# ─────────────────────────────────────────────────────────────────────────────
# Classification helpers
# ─────────────────────────────────────────────────────────────────────────────

in_high_value_class() {
  case "$CLASS" in
    SSRF|SSRF-blind|SSRF-partial|SSRF-full|\
    IDOR|BOLA|IDOR-read|IDOR-write|cross-tenant|\
    RCE|command-injection|SQLi|SSTI|\
    auth-bypass|account-takeover|oauth-hijack|JWT-attack|\
    subdomain-takeover|XSS-stored|credential-exposure|\
    default-creds|path-traversal|business-logic-financial|\
    CORS-sensitive-data) return 0 ;;
    *) return 1 ;;
  esac
}

in_hard_rejection_list() {
  case "$CLASS" in
    missing-header|HSTS-missing|X-Frame-Options|X-Content-Type|Referrer-Policy|\
    CSP-informational|SPF-missing|DMARC-missing|DKIM-missing|\
    TLS-version-old|CORS-no-sensitive|self-XSS|CSRF-logout|\
    open-redirect-owned|rate-limit-nonsensitive|version-disclosure|\
    no-2fa|password-policy|swagger-public-no-secrets|stack-trace-no-data|\
    clickjacking-nonsensitive|HTTP-methods|punycode-phishing) return 0 ;;
    *) return 1 ;;
  esac
}

impact_has_concrete_gain() {
  echo "$IMPACT $EVIDENCE" | grep -qiE \
    "account.takeover|steal.*token|session.*theft|cloud.key|aws.*key|credential|read.*data|RCE|code.exec|cross.tenant|bypass.*auth|exfil|privilege.escal|DEPLOYMENT_NOT_FOUND|internal.*service|metadata"
}

has_chain_potential() {
  echo "$IMPACT $EVIDENCE" | grep -qiE \
    "chain|cookie.domain|oauth|redirect_uri|session|admin|credential|auth|token|internal|CNAME"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5-point scoring
# ─────────────────────────────────────────────────────────────────────────────
SCORE=0
REASONS=()

# Q1: Concrete attacker gain
if in_high_value_class || impact_has_concrete_gain; then
  SCORE=$((SCORE + 1))
elif in_hard_rejection_list; then
  REASONS+=("Q1:no-concrete-gain")
else
  REASONS+=("Q1:vague-gain")
fi

# Q2: NOT documented as intended behavior
if in_hard_rejection_list; then
  REASONS+=("Q2:documented-intended")
else
  case "$CONFIDENCE" in
    HIGH|CONFIRMED|CRITICAL|high|confirmed) SCORE=$((SCORE + 1)) ;;
    MEDIUM|medium)                          SCORE=$((SCORE + 1)) ;;
    LOW|low)                                REASONS+=("Q2:low-confidence-may-be-intended") ;;
    *)                                      SCORE=$((SCORE + 1)) ;;
  esac
fi

# Q3: Vendor would actually fix this
if in_high_value_class; then
  SCORE=$((SCORE + 1))
elif in_hard_rejection_list; then
  REASONS+=("Q3:vendor-wont-fix")
else
  SCORE=$((SCORE + 1))
fi

# Q4: CVSS >= 4.0 standalone or chain to Medium+
case "$CLASS" in
  RCE|account-takeover|IDOR|BOLA|SSRF*|SQLi|auth-bypass|credential-exposure|\
  oauth-hijack|JWT-attack|cross-tenant|command-injection|SSTI)
    SCORE=$((SCORE + 1)) ;;
  subdomain-takeover|XSS-stored|path-traversal|default-creds|\
  CORS-sensitive-data|business-logic-financial)
    if has_chain_potential; then
      SCORE=$((SCORE + 1))
    else
      REASONS+=("Q4:needs-chain-for-CVSS>=4")
    fi ;;
  XSS-reflected|open-redirect)
    if echo "$IMPACT $EVIDENCE" | grep -qiE "session|admin|auth.*token|OAuth|JWT"; then
      SCORE=$((SCORE + 1))
    else
      REASONS+=("Q4:class-below-CVSS4-without-auth-context")
    fi ;;
  *)
    SCORE=$((SCORE + 1)) ;;
esac

# Q5: Not on hard rejection list
if in_hard_rejection_list; then
  REASONS+=("Q5:hard-rejection-list-CLAUDE.md-S3")
else
  SCORE=$((SCORE + 1))
fi

# ─────────────────────────────────────────────────────────────────────────────
# Verdict
# ─────────────────────────────────────────────────────────────────────────────
REASON_STR="$(IFS="; "; echo "${REASONS[*]:-clean}")"

if [ "$SCORE" -ge 4 ]; then
  echo "PURSUE:HIGH:${SCORE}/5:${REASON_STR}"
  exit 0
elif [ "$SCORE" -eq 3 ]; then
  echo "PURSUE:MARGINAL:${SCORE}/5:${REASON_STR}"
  exit 0
else
  echo "AUTO_CLOSE:${SCORE}/5:${REASON_STR}"
  exit 1
fi
