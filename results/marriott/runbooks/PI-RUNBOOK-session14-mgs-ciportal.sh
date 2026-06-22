#!/usr/bin/env bash
# PI-RUNBOOK-session14-mgs-ciportal.sh
# Session 14 — mgs.marriott.com (M007) + ci-propertyconversionportal (M011) + esupplier doc paths
#
# SCOPE CHECK (run before anything):
#   SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
#     ~/bug-bounty-hunting-/scripts/scope-check.sh mgs.marriott.com
#   SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
#     ~/bug-bounty-hunting-/scripts/scope-check.sh ci-propertyconversionportal.marriott.com
#   SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
#     ~/bug-bounty-hunting-/scripts/scope-check.sh esupplier.marriott.com
#
# Run: bash PI-RUNBOOK-session14-mgs-ciportal.sh 2>&1 | tee /tmp/s14.txt
# Read: tail -f /tmp/s14.txt   (or cat /tmp/s14.txt)
#
# Targets:
#   mgs.marriott.com          — M007 — 200/19501B raw EC2, no WAF, 0 prior reports
#   ci-propertyconversionportal.marriott.com — M011 — 200/5939B, 1 prior report
#   esupplier.marriott.com    — M001 — static doc paths not yet probed
#
# Bug classes prioritized:
#   mgs:     Auth bypass, IDOR on group/property data, GraphQL introspection, SSRF via webhooks
#   ci:      Auth bypass, IDOR on property conversion records, exposed API, source disclosure
#   esupplier: Document path enumeration (static docs may contain credentials/configs)

set -uo pipefail
CURL=/usr/bin/curl
OUTDIR=/tmp/s14
mkdir -p "$OUTDIR"
SEP="=================================================================="
log() { echo; echo "$SEP"; echo ">>> $*"; echo "$SEP"; }

# ─── PHASE 0 ── SCOPE VERIFICATION ───────────────────────────────────────────
log "PHASE 0 — SCOPE CHECK (mandatory)"
SCOPE_SCRIPT=~/bug-bounty-hunting-/scripts/scope-check.sh
SCOPE_CFG=~/bug-bounty-hunting-/config/marriott-scope.yaml

for host in mgs.marriott.com ci-propertyconversionportal.marriott.com esupplier.marriott.com; do
  result=$(SCOPE_FILE="$SCOPE_CFG" bash "$SCOPE_SCRIPT" "$host" 2>&1)
  echo "$host => $result"
  if echo "$result" | grep -q "OUT-OF-SCOPE\|AMBIGUOUS"; then
    echo "FATAL: $host is $result — aborting"; exit 1
  fi
done
echo "All three targets IN-SCOPE. Proceeding."

# ─── PHASE A ── mgs.marriott.com — DEEP FINGERPRINT ─────────────────────────
log "PHASE A — mgs.marriott.com — Full headers + response body"

echo "=== A1: DNS resolution ==="
dig +short mgs.marriott.com A
dig +short mgs.marriott.com CNAME

echo "=== A2: Root page headers ==="
$CURL -sk -D - -o "$OUTDIR/mgs-root.html" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  "https://mgs.marriott.com/" \
  | head -60
echo "Root body saved to $OUTDIR/mgs-root.html ($(wc -c < "$OUTDIR/mgs-root.html") bytes)"

echo "=== A3: Title + meta description ==="
python3 -c "
import sys, re
body = open('$OUTDIR/mgs-root.html').read()
titles = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
metas = re.findall(r'<meta\s[^>]*name=[\"\'](description|keywords|application-name)[\"\']\s[^>]*content=[\"\'](.*?)[\"\']', body, re.I)
print('TITLE:', titles)
print('META:', metas[:5])
"

echo "=== A4: Framework fingerprint from headers and body ==="
python3 -c "
import sys, re
body = open('$OUTDIR/mgs-root.html').read()
# React
react_signs = re.findall(r'(react|__REACT|ReactDOM|_reactRoot|data-reactroot)', body, re.I)
# Angular
ng_signs = re.findall(r'(ng-version|angular\.js|ng-app|ng-controller|__ngContext)', body, re.I)
# Vue
vue_signs = re.findall(r'(vue\.js|Vue\.config|__vue__|data-v-[a-f0-9]+)', body, re.I)
# Next/Nuxt/Gatsby SSR
ssr_signs = re.findall(r'(__NEXT_DATA__|__NUXT__|__gatsby)', body)
# Spring Boot / Thymeleaf / JSF
java_signs = re.findall(r'(javax\.faces\.|th:|Whitelabel Error|Spring)', body, re.I)
# ASP.NET
dotnet_signs = re.findall(r'(ViewState|__EVENTTARGET|aspnetForm|ASP\.NET|\.axd)', body, re.I)
# Cookies
cookies = re.findall(r'Set-Cookie:\s*([^;=\r\n]+)', body)
print('React:', react_signs[:5])
print('Angular:', ng_signs[:5])
print('Vue:', vue_signs[:5])
print('SSR:', ssr_signs[:5])
print('Java:', java_signs[:5])
print('.NET:', dotnet_signs[:5])
print('Cookies found:', cookies[:10])
"

echo "=== A5: Extract all resource URLs (JS bundles, CSS, API paths) ==="
python3 -c "
import sys, re
body = open('$OUTDIR/mgs-root.html').read()
# scripts
scripts = re.findall(r'<script[^>]+src=[\"\'](.*?)[\"\']\s*[>/]', body, re.I)
# links
links = re.findall(r'<link[^>]+href=[\"\'](.*?)[\"\']\s*[>/]', body, re.I)
# data attributes pointing to endpoints
apis = re.findall(r'[\"\'](/api[/\w.\-?=&]+)[\"\'|]', body)
# all hrefs
hrefs = re.findall(r'href=[\"\'](/[^\"\'#?]{1,80})', body, re.I)
print('--- JS Scripts ---')
for s in scripts: print(' ', s)
print('--- CSS/Links ---')
for l in links[:20]: print(' ', l)
print('--- Embedded API paths ---')
for a in set(apis): print(' ', a)
print('--- hrefs (sample) ---')
for h in set(hrefs)[:30]: print(' ', h)
" 2>&1 | tee "$OUTDIR/mgs-resources.txt"

echo "=== A6: Inline JSON data / window.__INITIAL_STATE__ / window.__APP__ ==="
python3 -c "
import sys, re, json
body = open('$OUTDIR/mgs-root.html').read()
# Next.js __NEXT_DATA__
nd = re.findall(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>', body, re.S)
# window.__STATE__ patterns
ws = re.findall(r'window\.__[A-Z_]+__\s*=\s*(\{.*?\});', body, re.S)
# JSON blobs in scripts
jb = re.findall(r'=\s*(\{\"[a-zA-Z]+\":\{)', body)
if nd:
    print('__NEXT_DATA__ found!')
    try: print(json.dumps(json.loads(nd[0]), indent=2)[:2000])
    except: print(nd[0][:500])
if ws:
    print('window.__STATE__ patterns:', len(ws))
    for w in ws[:2]: print(w[:300])
if not nd and not ws:
    print('No inline state blobs found')
"

# ─── PHASE B ── mgs.marriott.com — PATH ENUMERATION (curated ≤80 req) ────────
log "PHASE B — mgs.marriott.com — Curated path enumeration"

# Build the target URL list
cat > "$OUTDIR/mgs-paths.txt" << 'PATHEOF'
/robots.txt
/sitemap.xml
/.well-known/security.txt
/api
/api/v1
/api/v2
/api/v3
/graphql
/health
/healthcheck
/status
/version
/metrics
/actuator
/actuator/health
/actuator/env
/actuator/info
/actuator/mappings
/actuator/heapdump
/swagger-ui.html
/swagger-ui/index.html
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/login
/logout
/auth
/auth/login
/auth/callback
/admin
/admin/
/console
/dashboard
/profile
/users
/user
/account
/accounts
/groups
/properties
/hotels
/events
/bookings
/reservations
/search
/config
/debug
/.env
/.env.local
/.env.production
/web.config
/application.properties
/application.yml
/app.config.js
/config.json
/settings.json
/phpinfo.php
/info.php
/.git/HEAD
/server-status
/server-info
/WEB-INF/web.xml
/api/users
/api/auth
/api/auth/login
/api/me
/api/profile
/api/search
/api/groups
/api/events
/api/properties
/api/hotels
/api/v1/users
/api/v1/auth
/api/v1/health
/api/v2/users
/api/v2/health
PATHEOF

echo "Probing $(wc -l < "$OUTDIR/mgs-paths.txt") paths on mgs.marriott.com..."
echo "Format: STATUS|BYTES|PATH"
while IFS= read -r path; do
  [ -z "$path" ] && continue
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --max-time 10 \
    "https://mgs.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done < "$OUTDIR/mgs-paths.txt" | tee "$OUTDIR/mgs-path-results.txt"

echo ""
echo "=== B2: Non-404 responses ==="
grep -v '^404|' "$OUTDIR/mgs-path-results.txt" | grep -v '^000|' || echo "(none — all 404 or timeout)"

# ─── PHASE C ── mgs.marriott.com — JS BUNDLE MINING ─────────────────────────
log "PHASE C — mgs.marriott.com — JS bundle download + endpoint mining"

# Extract JS bundle URLs from Phase A
echo "=== C1: Extract full JS bundle URLs ==="
python3 - << 'PYEOF'
import re, sys

body = open('/tmp/s14/mgs-root.html').read()
base = 'https://mgs.marriott.com'

scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
chunks = re.findall(r'["\']([^"\']*chunk[^"\']*\.js[^"\']*)["\']', body, re.I)
hashes = re.findall(r'["\']([^"\']*\.[a-f0-9]{8,}\.js)["\']', body, re.I)

all_js = list(set(scripts + chunks + hashes))
urls = []
for s in all_js:
    if s.startswith('//'):
        urls.append('https:' + s)
    elif s.startswith('/'):
        urls.append(base + s)
    elif s.startswith('http'):
        urls.append(s)

print(f"Found {len(urls)} JS bundle URLs:")
for u in urls:
    print(u)

with open('/tmp/s14/mgs-js-urls.txt', 'w') as f:
    f.write('\n'.join(urls) + '\n')
PYEOF

echo "=== C2: Download and mine JS bundles ==="
if [ ! -s "$OUTDIR/mgs-js-urls.txt" ]; then
  echo "No JS bundle URLs found — skipping bundle mining"
else
  mkdir -p "$OUTDIR/mgs-bundles"
  idx=0
  while IFS= read -r jsurl; do
    [ -z "$jsurl" ] && continue
    idx=$((idx+1))
    outfile="$OUTDIR/mgs-bundles/bundle-${idx}.js"
    echo "Downloading: $jsurl"
    $CURL -sk -L --max-time 30 \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Referer: https://mgs.marriott.com/" \
      -o "$outfile" "$jsurl" 2>/dev/null
    sz=$(wc -c < "$outfile" 2>/dev/null || echo 0)
    echo "  Saved: $outfile ($sz bytes)"
  done < "$OUTDIR/mgs-js-urls.txt"

  echo "=== C3: Mine endpoints from JS bundles ==="
  cat > /tmp/mine_js.py << 'PYEOF'
import os, re, sys

bundle_dir = '/tmp/s14/mgs-bundles'
if not os.path.exists(bundle_dir):
    print("No bundle dir")
    sys.exit(0)

api_paths = set()
hostnames = set()
tokens = set()
auth_headers = set()

for fname in os.listdir(bundle_dir):
    fpath = os.path.join(bundle_dir, fname)
    try:
        content = open(fpath, errors='replace').read()
    except:
        continue

    # API paths
    for p in re.findall(r'["\`](\/?(?:api|v\d|graphql|rest|ws|webhook)[/\w.\-{}:?=&%]+)["\`]', content):
        if len(p) > 3 and len(p) < 120:
            api_paths.add(p)

    # Internal/external hostnames
    for h in re.findall(r'["\`]((?:https?://)?(?:[\w-]+\.){2,}[\w-]+(?:/[^"\'`\s]{0,60})?)["\`]', content):
        if 'marriott' in h or 'amazonaws' in h or 'internal' in h.lower():
            hostnames.add(h[:120])

    # Bearer tokens / API keys
    for t in re.findall(r'(?:Bearer|apikey|api_key|token|secret|password)\s*[:=]\s*["\`]([^"\'`\s]{10,60})["\`]', content, re.I):
        tokens.add(t)

    # Authorization header patterns
    for a in re.findall(r'["\']Authorization["\']\s*:\s*["\`]([^"\'`]{5,80})["\`]', content):
        auth_headers.add(a)

print(f"\n=== API PATHS ({len(api_paths)}) ===")
for p in sorted(api_paths)[:100]:
    print(' ', p)

print(f"\n=== HOSTNAMES ({len(hostnames)}) ===")
for h in sorted(hostnames)[:50]:
    print(' ', h)

if tokens:
    print(f"\n=== POTENTIAL SECRETS ({len(tokens)}) ===")
    for t in sorted(tokens)[:20]:
        print(' ', t[:60])

if auth_headers:
    print(f"\n=== AUTH HEADERS ({len(auth_headers)}) ===")
    for a in sorted(auth_headers)[:10]:
        print(' ', a[:80])
PYEOF
  python3 /tmp/mine_js.py | tee "$OUTDIR/mgs-js-mining.txt"
fi

# ─── PHASE D ── mgs.marriott.com — GRAPHQL PROBE ─────────────────────────────
log "PHASE D — mgs.marriott.com — GraphQL introspection probe"

echo "=== D1: GET /graphql ==="
$CURL -sk -D - -o "$OUTDIR/mgs-graphql-get.txt" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  "https://mgs.marriott.com/graphql" 2>/dev/null
head -20 "$OUTDIR/mgs-graphql-get.txt"

echo ""
echo "=== D2: POST /graphql — introspection query ==="
$CURL -sk -D - -o "$OUTDIR/mgs-graphql-introspect.txt" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -d '{"query":"{__schema{queryType{name}}}"}' \
  "https://mgs.marriott.com/graphql" 2>/dev/null
head -5 "$OUTDIR/mgs-graphql-introspect.txt"
wc -c "$OUTDIR/mgs-graphql-introspect.txt"

echo ""
echo "=== D3: POST /api/graphql — introspection ==="
$CURL -sk -o /dev/null -w "Status: %{http_code} Size: %{size_download}\n" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -d '{"query":"{__schema{queryType{name}}}"}' \
  "https://mgs.marriott.com/api/graphql"

# ─── PHASE E ── mgs.marriott.com — AUTH / JWT PROBE ─────────────────────────
log "PHASE E — mgs.marriott.com — Auth surface analysis"

echo "=== E1: Full /login page ==="
$CURL -sk -D - -o "$OUTDIR/mgs-login.html" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --max-time 10 \
  "https://mgs.marriott.com/login" 2>/dev/null
SZ=$(wc -c < "$OUTDIR/mgs-login.html")
echo "Size: $SZ bytes"
if [ "$SZ" -gt 100 ]; then
  python3 -c "
import re
body = open('/tmp/s14/mgs-login.html').read()
forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.I|re.S)
inputs = re.findall(r'<input[^>]+>', body, re.I)
print('Forms found:', len(forms))
for f in forms[:2]: print(f[:400])
print('Inputs:', len(inputs))
for i in inputs[:20]: print(' ', i[:120])
"
fi

echo "=== E2: Check for SAML/OIDC redirect from root ==="
$CURL -sk -D - --max-redirs 0 -o /dev/null \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  "https://mgs.marriott.com/" 2>/dev/null \
  | grep -i 'location:\|set-cookie:\|www-authenticate:' || echo "(no auth redirects)"

echo "=== E3: Unauthenticated API probe — common patterns ==="
for path in /api/me /api/user /api/profile /api/v1/me /api/v1/user; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "https://mgs.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done

echo "=== E4: SSRF probe via external URL parameter ==="
# Test common SSRF param names — look for outbound connections (use /dev/null callback)
# We use only URL metadata check (no callback infrastructure here)
for param in url redirect callback webhook src dest target next; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "https://mgs.marriott.com/?${param}=https://example.com" 2>/dev/null)
  echo "${result}|/?${param}=https://example.com"
done

# ─── PHASE F ── ci-propertyconversionportal.marriott.com (M011) ──────────────
log "PHASE F — ci-propertyconversionportal.marriott.com — Fingerprint + path enum"

echo "=== F1: DNS + root headers ==="
dig +short ci-propertyconversionportal.marriott.com A
dig +short ci-propertyconversionportal.marriott.com CNAME

$CURL -sk -D - -o "$OUTDIR/ci-root.html" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --max-time 15 \
  "https://ci-propertyconversionportal.marriott.com/" 2>/dev/null \
  | head -40
echo "Root body: $(wc -c < "$OUTDIR/ci-root.html") bytes"

echo "=== F2: Tech fingerprint ==="
python3 -c "
import re
try:
    body = open('/tmp/s14/ci-root.html').read()
except:
    print('Could not read ci-root.html'); exit()
title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
scripts = re.findall(r'<script[^>]+src=[\"\'](.*?)[\"\']\s*[>/]', body, re.I)
forms = re.findall(r'<form[^>]*action=[\"\'](.*?)[\"\']\s*[>]', body, re.I)
react = re.findall(r'(ReactDOM|__REACT|data-reactroot|next\.js)', body, re.I)
angular = re.findall(r'(ng-version|angular\.js)', body, re.I)
dotnet = re.findall(r'(ViewState|__EVENTTARGET|aspnetForm)', body, re.I)
print('Title:', title)
print('Scripts:', scripts[:10])
print('Forms:', forms[:5])
print('React:', react[:3])
print('Angular:', angular[:3])
print('.NET:', dotnet[:3])
" 2>&1

echo "=== F3: Path enumeration ==="
for path in /robots.txt /sitemap.xml /api /api/v1 /health /status /login /admin \
            /dashboard /properties /conversion /api/conversions /api/properties \
            /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json \
            /actuator/health /graphql /api/graphql \
            /.git/HEAD /.env /web.config /web.config.bak; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --max-time 10 \
    "https://ci-propertyconversionportal.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done | tee "$OUTDIR/ci-path-results.txt"

echo ""
echo "=== F3b: Non-404 ci-portal responses ==="
grep -v '^404|' "$OUTDIR/ci-path-results.txt" | grep -v '^000|' || echo "(all 404 or timeout)"

echo "=== F4: JS bundle download + mine ==="
python3 - << 'PYEOF'
import re, subprocess
body = open('/tmp/s14/ci-root.html').read()
base = 'https://ci-propertyconversionportal.marriott.com'
scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
urls = []
for s in scripts:
    if s.startswith('//'): urls.append('https:' + s)
    elif s.startswith('/'): urls.append(base + s)
    elif s.startswith('http'): urls.append(s)
print(f"Found {len(urls)} JS URLs:")
for u in urls[:10]: print(' ', u)
with open('/tmp/s14/ci-js-urls.txt', 'w') as f:
    f.write('\n'.join(urls) + '\n')
PYEOF

if [ -s "$OUTDIR/ci-js-urls.txt" ]; then
  mkdir -p "$OUTDIR/ci-bundles"
  idx=0
  while IFS= read -r jsurl; do
    [ -z "$jsurl" ] && continue
    idx=$((idx+1))
    outfile="$OUTDIR/ci-bundles/bundle-${idx}.js"
    $CURL -sk -L --max-time 30 \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Referer: https://ci-propertyconversionportal.marriott.com/" \
      -o "$outfile" "$jsurl" 2>/dev/null
    echo "Bundle $idx: $(wc -c < "$outfile") bytes"
  done < "$OUTDIR/ci-js-urls.txt"

  cat > /tmp/mine_ci_js.py << 'PYEOF'
import os, re

bundle_dir = '/tmp/s14/ci-bundles'
api_paths = set()
hostnames = set()
tokens = set()

for fname in os.listdir(bundle_dir):
    fpath = os.path.join(bundle_dir, fname)
    try: content = open(fpath, errors='replace').read()
    except: continue

    for p in re.findall(r'["\`](\/?(?:api|v\d|graphql|rest|conversion|propert)[/\w.\-{}:?=&%]+)["\`]', content):
        if 3 < len(p) < 120: api_paths.add(p)
    for h in re.findall(r'["\`]((?:https?://)?[\w-]+\.marriott\.com(?:/[^"\'`\s]{0,60})?)["\`]', content):
        hostnames.add(h[:120])
    for t in re.findall(r'(?:apikey|api_key|token|secret)\s*[:=]\s*["\`]([^"\'`\s]{10,60})["\`]', content, re.I):
        tokens.add(t)

print(f"=== CI API PATHS ({len(api_paths)}) ===")
for p in sorted(api_paths)[:60]: print(' ', p)
print(f"\n=== CI HOSTNAMES ({len(hostnames)}) ===")
for h in sorted(hostnames)[:30]: print(' ', h)
if tokens:
    print(f"\n=== CI POTENTIAL SECRETS ({len(tokens)}) ===")
    for t in sorted(tokens)[:10]: print(' ', t[:60])
PYEOF
  python3 /tmp/mine_ci_js.py | tee "$OUTDIR/ci-js-mining.txt"
fi

# ─── PHASE G ── esupplier.marriott.com — Document path probe (S13 leftover) ──
log "PHASE G — esupplier.marriott.com — Document sub-paths (session 13 leftover)"

echo "=== G1: Document paths ==="
for path in \
  "/marrforms/esuppliersplash.htm" \
  "/ESupplier-Basics%20Job%20Aid.doc" \
  "/Electronic%20Payment%20Authorization%20form.doc" \
  "/e-Supplier-%20Self%20Help.pdf" \
  "/default_files/filelist.xml" \
  "/default_files/" \
  "/marrforms/" \
  "/marrforms/index.htm" \
  "/marrforms/index.html"; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --max-time 15 \
    "https://esupplier.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done

echo ""
echo "=== G2: esupplier general path scan (a few more) ==="
for path in /robots.txt /sitemap.xml /.git/HEAD /web.config /web.config.bak \
            /applicationHost.config /appsettings.json /backup.zip /archive.zip \
            /iisstart.htm /iisstart.html /ViewState /trace.axd /elmah.axd; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --max-time 10 \
    "https://esupplier.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done

# ─── PHASE H ── DECISION GATE ─────────────────────────────────────────────────
log "PHASE H — DECISION GATE"

echo "=== Summary of interesting results ==="
echo ""
echo "--- mgs.marriott.com non-404/non-000 paths ---"
grep -v '^404|' "$OUTDIR/mgs-path-results.txt" 2>/dev/null | grep -v '^000|' | grep -v '^301|' || echo "  (none)"

echo ""
echo "--- ci-propertyconversionportal non-404/non-000 paths ---"
grep -v '^404|' "$OUTDIR/ci-path-results.txt" 2>/dev/null | grep -v '^000|' | grep -v '^301|' || echo "  (none)"

echo ""
echo "--- mgs JS mining results (first 30 lines) ---"
head -30 "$OUTDIR/mgs-js-mining.txt" 2>/dev/null || echo "  (no bundles downloaded)"

echo ""
echo "--- ci JS mining results (first 30 lines) ---"
head -30 "$OUTDIR/ci-js-mining.txt" 2>/dev/null || echo "  (no bundles downloaded)"

echo ""
echo "--- GraphQL probes ---"
echo "mgs /graphql GET:"
head -3 "$OUTDIR/mgs-graphql-get.txt" 2>/dev/null
echo "mgs /graphql introspect:"
head -3 "$OUTDIR/mgs-graphql-introspect.txt" 2>/dev/null

echo ""
echo "--- esupplier document paths ---"
# Already printed inline above

echo ""
echo "=== Raw files in $OUTDIR ==="
ls -lh "$OUTDIR/"

log "SESSION 14 COMPLETE. Review $OUTDIR for full output."
echo "Key next steps:"
echo " 1. If mgs has open API endpoints → probe for auth bypass and IDOR"
echo " 2. If JS bundles found → review mgs-js-mining.txt for API paths and secrets"
echo " 3. If GraphQL introspection returns schema → enumerate objects for record access"
echo " 4. If ci-portal has open endpoints → probe for IDOR on conversion records"
echo " 5. Copy $OUTDIR to ~/bug-bounty-hunting-/results/marriott/session14/"
echo "    mkdir -p ~/bug-bounty-hunting-/results/marriott/session14/"
echo "    cp -r /tmp/s14/* ~/bug-bounty-hunting-/results/marriott/session14/"
