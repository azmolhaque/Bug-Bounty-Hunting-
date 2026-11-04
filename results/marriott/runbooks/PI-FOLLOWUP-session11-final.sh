#!/usr/bin/env bash
# Session 11 — Final executeGraphQL test + getObjectInfos I2 fix + M002 evidence update
# Run: bash PI-FOLLOWUP-session11-final.sh 2>&1 | tee /tmp/s11-final.txt
# Date: 2026-06-22

FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"

# Refresh cookies
curl -skL -c /tmp/cpp-s11-cookies.txt "https://cpp.marriott.com/s/" -o /dev/null
echo "=== Cookies refreshed ==="

echo ""
echo "=== TEST 1: executeGraphQL — DIRECT CURL (no aura helper, single-quoted) ==="
echo "--- 1a: Minimal query — bare Id, Name {value} only ---"
# Single-quoted entire --data-urlencode arg to prevent any shell interpretation
# The $executeGraphQL descriptor should be a literal $ here
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s11-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{"query":"query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}","variables":{}}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
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
        print(f'returnValue={json.dumps(rv)[:600]}')
        print(f'error={json.dumps(err)[:600]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

echo ""
echo "--- 1b: Try 'document' instead of 'query' as param key ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s11-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{"document":"query q{uiapi{query{User{edges{node{Id Name{value}Email{value}}}totalCount}}}}","variables":{}}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
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
        print(f'returnValue={json.dumps(rv)[:600]}')
        print(f'error={json.dumps(err)[:600]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

echo ""
echo "--- 1c: Try NetworkMember (not just User) ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s11-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$executeGraphQL","callingDescriptor":"UNKNOWN","params":{"query":"query q{uiapi{query{NetworkMember{edges{node{Id MemberId{value}NetworkId{value}Status{value}}}totalCount}}}}","variables":{}}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
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
        print(f'returnValue={json.dumps(rv)[:600]}')
        print(f'error={json.dumps(err)[:600]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:500])
" 2>&1

echo ""
echo "=== TEST 2: getObjectInfos I2 — FIXED PARSER for 'results' list format ==="
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s11-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfos","callingDescriptor":"UNKNOWN","params":{"objectApiNames":["ContentDocument","ContentVersion","CollaborationGroup","CollaborationGroupMember","FeedItem","FeedComment","FeedAttachment"]}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
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
            # Format is rv['results'] = list of {'result': schema_or_error}
            results_list = rv.get('results', [])
            print(f'results_count={len(results_list)}')
            for item in results_list:
                result = item.get('result', None)
                if isinstance(result, dict):
                    # Success — has apiName, fields, label, etc.
                    name = result.get('apiName', '?')
                    label = result.get('label', '?')
                    fcount = len(result.get('fields', {}))
                    # Sample some fields
                    flds = result.get('fields', {})
                    sample = [(k, v.get('label',''), v.get('dataType','')) for k,v in list(flds.items())[:5]]
                    print(f'  ACCESSIBLE: {name} ({label}) — {fcount} fields')
                    for fname, flabel, ftype in sample:
                        print(f'    {fname} -> {flabel} ({ftype})')
                elif isinstance(result, list):
                    # Error format — list of error objects
                    for e in result:
                        code = e.get('errorCode','?')
                        msg = e.get('message','')
                        print(f'  ERROR: {code} — {msg[:100]}')
                else:
                    print(f'  UNKNOWN result format: {str(result)[:100]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'error: {msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:400])
" 2>&1

echo ""
echo "=== TEST 3: getObjectInfos — User vs Tier 2 field count comparison ==="
# Confirm User fieldcount + get Network, Profile, Organization field counts
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s11-cookies.txt \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfos","callingDescriptor":"UNKNOWN","params":{"objectApiNames":["User","Network","Profile","Organization","NetworkMember","CollaborationGroup"]}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
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
            results_list = rv.get('results', [])
            print(f'results_count={len(results_list)}')
            for item in results_list:
                result = item.get('result', None)
                if isinstance(result, dict):
                    name = result.get('apiName', '?')
                    fcount = len(result.get('fields', {}))
                    label = result.get('label', '?')
                    print(f'  {name} ({label}): {fcount} fields ACCESSIBLE')
                elif isinstance(result, list):
                    for e in result:
                        print(f'  ERROR [{e.get(\"errorCode\",\"?\")}]: {e.get(\"message\",\"\")[:100]}')
                else:
                    print(f'  UNKNOWN: {str(result)[:80]}')
        if err:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'error: {msg[:200]}')
except Exception as e:
    print(f'parse_err={e}')
    print(raw[:400])
" 2>&1

echo ""
echo "=== TEST 4: getPicklistValues on additional User fields ==="
# Confirm we can enumerate picklist values for other User fields
for FIELD in "LanguageLocaleKey" "LocaleSidKey" "TimeZoneSidKey" "ProfileId"; do
  echo "--- getPicklistValues(User.${FIELD}) ---"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s11-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"aura://RecordUiController/ACTION\$getPicklistValues\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"objectApiName\":\"User\",\"recordTypeId\":\"012000000000000AAA\",\"fieldApiName\":\"${FIELD}\"}}]}" \
    --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"${FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined' \
    | python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'  size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue') or {}
        err = a.get('error') or []
        vals = rv.get('values', rv.get('picklistValues', []))
        if state == 'SUCCESS' and vals:
            print(f'  state=SUCCESS ({len(vals)} values): {[v.get(\"value\",\"?\") for v in vals[:8]]}')
        elif state == 'SUCCESS':
            print(f'  state=SUCCESS rv_keys={list(rv.keys())[:6]}')
            print(f'  rv_sample={str(rv)[:300]}')
        else:
            msg = err[0].get('message','') if isinstance(err,list) and err else str(err)
            print(f'  state={state} err={msg[:100]}')
except Exception as e:
    print(f'  parse_err={e}')
    print(f'  raw={raw[:200]}')
" 2>&1
done

echo ""
echo "=== DONE: $(date) ==="
