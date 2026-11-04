#!/usr/bin/env bash
# Session 10 Follow-up — targeted diagnosis after main runbook
# Run: bash PI-FOLLOWUP-session10-diagnosis.sh 2>&1 | tee /tmp/s10-followup.txt
# Date: 2026-06-22

FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"

aura() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s10-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

# Ensure fresh cookies
curl -skL -c /tmp/cpp-s10-cookies.txt "https://cpp.marriott.com/s/" -o /dev/null
echo "=== Cookies refreshed ==="

echo ""
echo "=== 1. FULL getObjectInfos I2 — which Tier 2 objects have schemas? ==="
aura "aura://RecordUiController/ACTION\$getObjectInfos" \
  '{"objectApiNames":["ContentDocument","ContentVersion","CollaborationGroup","CollaborationGroupMember","FeedItem","FeedElement","FeedComment"]}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        print(f'state={a.get(\"state\",\"?\")}')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        if isinstance(rv, dict):
            for name, info in sorted(rv.items()):
                if isinstance(info, dict):
                    fcount = len(info.get('fields', {}))
                    label = info.get('label','?')
                    print(f'  ACCESSIBLE: {name} ({label}) — {fcount} fields')
                elif info is None:
                    print(f'  BLOCKED: {name} (null)')
                else:
                    print(f'  UNKNOWN: {name} = {str(info)[:100]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'error: {msg[:300]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:400])
" 2>&1

echo ""
echo "=== 2. RAW executeGraphQL response — what is the actual error? ==="
aura "aura://RecordUiController/ACTION\$executeGraphQL" \
  '{"query":"query users {uiapi {query {User {edges {node {Id Name {value} Email {value}}} totalCount}}}}","variables":{}}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        print(f'state={a.get(\"state\",\"?\")}')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'returnValue={json.dumps(rv)[:500]}')
        print(f'error_raw={json.dumps(err)[:500]}')
except Exception as e:
    print(f'parse_err={e}')
print(f'raw_tail={raw[-300:]}')
" 2>&1

echo ""
echo "=== 3. RAW getItems(NetworkMember) — what exactly comes back? ==="
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"NetworkMember","layoutType":"COMPACT","pageSize":5,"currentPage":0}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    print(f'top_keys={list(obj.keys())}')
    actions = obj.get('actions', [])
    print(f'actions_count={len(actions)}')
    for a in actions:
        print(f'  state={a.get(\"state\")} rv={str(a.get(\"returnValue\"))[:200]} err={str(a.get(\"error\"))[:200]}')
    # Check other top-level keys
    for k in ['context','perfSummary','auraError']:
        v = obj.get(k)
        if v:
            print(f'{k}={str(v)[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:400])
" 2>&1

echo ""
echo "=== 4. getConfigData — re-run to confirm full accessible object list ==="
aura "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION\$getConfigData" \
  '{}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        rv = a.get('returnValue') or {}
        print(f'state={a.get(\"state\",\"?\")}')
        # apiNamesToKeyPrefixes shows accessible objects
        api_map = rv.get('apiNamesToKeyPrefixes', {})
        if api_map:
            print(f'total_accessible_objects={len(api_map)}')
            # Show objects that might have PII
            interesting_prefixes = ['0DO','0CQ','0Yw','069','068','0F9','0FK','0D5','0DB','00e','00D','0N0','0HH','00T','0Ai']
            for name, prefix in sorted(api_map.items()):
                if prefix in interesting_prefixes or any(kw in name for kw in ['User','Login','Token','Auth','Member','Group','Feed','Content','Profile','Network','Community','Case','Contact','Account']):
                    print(f'  {prefix}: {name}')
        # Check other interesting keys
        for key in ['userPermissions','orgPreferences','currentUser']:
            v = rv.get(key)
            if v:
                print(f'{key}={str(v)[:300]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:300])
" 2>&1

echo ""
echo "=== 5. LWC /lwr/fetch endpoint — different API, different access controls? ==="
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/lwr/fetch" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"id":"1","route":"/s/","actions":[]}' \
  | python3 -c "
import sys
raw = sys.stdin.read()
print(f'size={len(raw)}B')
print(raw[:600])
" 2>&1

echo ""
echo "=== 6. Test if getItems returns empty actions or non-empty blocked ==="
# Check the raw structure of getItems(User) — is it actions:[] or ERROR state?
aura "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":5,"currentPage":0}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    actions = obj.get('actions', [])
    print(f'actions_count={len(actions)}')
    if actions:
        for a in actions:
            print(f'state={a.get(\"state\")}')
            print(f'returnValue={json.dumps(a.get(\"returnValue\",{}))[:300]}')
            print(f'error={json.dumps(a.get(\"error\",[]))[:300]}')
    else:
        print('actions IS EMPTY [] — Aura framework blocked before routing')
        # This means the action was rejected at the Aura layer, not the app layer
    # Show top-level context
    ctx = obj.get('context', {})
    if ctx:
        print(f'context_keys={list(ctx.keys())[:5]}')
    ae = obj.get('auraError')
    if ae:
        print(f'auraError={ae}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:400])
" 2>&1

echo ""
echo "=== 7. getPicklistValues — confirm read access to User picklist fields ==="
aura "aura://RecordUiController/ACTION\$getPicklistValues" \
  '{"objectApiName":"User","recordTypeId":"012000000000000AAA","fieldApiName":"UserType"}' \
  | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        print(f'state={state}')
        if isinstance(rv, dict):
            vals = rv.get('values', []) or rv.get('picklistValues', [])
            if vals:
                print(f'  *** PICKLIST VALUES ({len(vals)} items): ***')
                for v in vals[:15]:
                    print(f'    {v}')
            else:
                print(f'  rv_keys={list(rv.keys())[:8]}')
                print(f'  rv_sample={str(rv)[:300]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'  error: {msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:300])
" 2>&1

echo ""
echo "=== DONE: $(date) ==="
echo "=== Copy /tmp/s10-followup.txt and paste output ==="
