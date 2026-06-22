#!/usr/bin/env bash
# PI-RUNBOOK-session15-ci-portal-deep.sh
# Session 15 — ci-propertyconversionportal.marriott.com DEEP DIVE (M011)
#              + esupplier filelist.xml audit (M001)
#
# Context from Session 14:
#   - SPA catch-all: 200/5939-5940B (all unknown routes → index.html)
#   - REAL differentials found:
#       /health          → 200/0B   (live health endpoint, NOT SPA)
#       /openapi.json    → 200/1280B (NOT SPA — potential API spec)
#       /v2/api-docs     → 200/1280B (NOT SPA — potential Swagger v2)
#       /.env            → 403/406B  (app-level path-aware block)
#       /web.config      → 403/412B  (app-level path-aware block)
#       /web.config.bak  → 403/420B  (app-level path-aware block)
#   - esupplier document paths: all 5 accessible (48KB HTML, 550KB DOC, 90KB DOC, 370KB PDF, 273B XML)
#
# Strategy:
#   Phase A: READ openapi.json + v2/api-docs content → extract real endpoint paths
#   Phase B: Re-probe ALL paths with Accept:application/json → bypass SPA catch-all
#            (SPA returns HTML for all routes; real API returns JSON or different size)
#   Phase C: Deep actuator probe with JSON Accept header
#   Phase D: Probe discovered API paths (from openapi/v2-api-docs or sitemap)
#   Phase E: Auth bypass testing on real API endpoints
#   Phase F: esupplier filelist.xml + splash page audit
#
# Run: bash PI-RUNBOOK-session15-ci-portal-deep.sh 2>&1 | tee /tmp/s15.txt

set -uo pipefail
CURL=/usr/bin/curl
BASE=https://ci-propertyconversionportal.marriott.com
OUTDIR=/tmp/s15
mkdir -p "$OUTDIR"
SEP="=================================================================="
log() { echo; echo "$SEP"; echo ">>> $*"; echo "$SEP"; }

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ─── PHASE 0 ── SCOPE ────────────────────────────────────────────────────────
log "PHASE 0 — SCOPE CHECK"
SCOPE_SCRIPT=~/bug-bounty-hunting-/scripts/scope-check.sh
SCOPE_CFG=~/bug-bounty-hunting-/config/marriott-scope.yaml
for host in ci-propertyconversionportal.marriott.com esupplier.marriott.com; do
  result=$(SCOPE_FILE="$SCOPE_CFG" bash "$SCOPE_SCRIPT" "$host" 2>&1)
  echo "$host => $result"
  echo "$result" | grep -q "OUT-OF-SCOPE\|AMBIGUOUS" && { echo "FATAL: $host OOS — abort"; exit 1; }
done
echo "Both targets IN-SCOPE. Proceeding."

# ─── PHASE A ── READ DIFFERENTIAL CONTENT ─────────────────────────────────────
log "PHASE A — Read actual content of non-SPA differentials"

echo "=== A1: /health (200/0B) — content + full headers ==="
$CURL -sk -D - -o "$OUTDIR/ci-health.txt" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json, text/plain, */*" \
  --max-time 10 \
  "${BASE}/health"
echo "Health body:"
cat "$OUTDIR/ci-health.txt"
echo "(end)"

echo ""
echo "=== A2: /openapi.json — FULL CONTENT ==="
$CURL -sk -D - -o "$OUTDIR/ci-openapi.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  --max-time 15 \
  "${BASE}/openapi.json"
echo "openapi.json content ($(wc -c < "$OUTDIR/ci-openapi.json") bytes):"
cat "$OUTDIR/ci-openapi.json"
echo ""

echo "=== A3: /v2/api-docs — FULL CONTENT ==="
$CURL -sk -D - -o "$OUTDIR/ci-v2-api-docs.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  --max-time 15 \
  "${BASE}/v2/api-docs"
echo "v2/api-docs content ($(wc -c < "$OUTDIR/ci-v2-api-docs.json") bytes):"
cat "$OUTDIR/ci-v2-api-docs.json"
echo ""

echo "=== A4: /robots.txt — FULL CONTENT ==="
$CURL -sk -o "$OUTDIR/ci-robots.txt" \
  -H "User-Agent: $UA" \
  --max-time 10 \
  "${BASE}/robots.txt"
echo "robots.txt content:"
cat "$OUTDIR/ci-robots.txt"
echo ""

echo "=== A5: /sitemap.xml — FULL CONTENT ==="
$CURL -sk -o "$OUTDIR/ci-sitemap.xml" \
  -H "User-Agent: $UA" \
  --max-time 10 \
  "${BASE}/sitemap.xml"
echo "sitemap.xml content:"
cat "$OUTDIR/ci-sitemap.xml"
echo ""

echo "=== A6: Extract endpoints from openapi.json ==="
python3 - << 'PYEOF'
import json, os, re, sys

for fname in ['ci-openapi.json', 'ci-v2-api-docs.json']:
    fpath = f'/tmp/s15/{fname}'
    if not os.path.exists(fpath): continue
    raw = open(fpath, errors='replace').read().strip()
    if not raw:
        print(f"{fname}: EMPTY"); continue
    try:
        doc = json.loads(raw)
        print(f"\n=== {fname} — JSON PARSED ===")
        # OpenAPI 3.x
        if 'paths' in doc:
            print(f"Paths found: {len(doc['paths'])}")
            for path in sorted(doc['paths'].keys()):
                methods = list(doc['paths'][path].keys())
                print(f"  {path}  [{', '.join(methods)}]")
        if 'info' in doc:
            print(f"Title: {doc['info'].get('title','?')}")
            print(f"Version: {doc['info'].get('version','?')}")
        if 'servers' in doc:
            print(f"Servers: {[s.get('url') for s in doc['servers']]}")
        # Swagger 2.x
        if 'basePath' in doc:
            print(f"basePath: {doc['basePath']}")
        if 'host' in doc:
            print(f"host: {doc['host']}")
    except json.JSONDecodeError:
        print(f"{fname}: NOT valid JSON — raw content:")
        print(raw[:500])
PYEOF

echo "=== A7: Extract paths from sitemap.xml ==="
python3 -c "
import re
content = open('/tmp/s15/ci-sitemap.xml', errors='replace').read()
locs = re.findall(r'<loc>(.*?)</loc>', content)
print(f'Sitemap URLs: {len(locs)}')
for l in locs[:30]: print(' ', l)
" 2>/dev/null || echo "(sitemap parse error)"

# ─── PHASE B ── JSON ACCEPT HEADER PROBE ─────────────────────────────────────
log "PHASE B — Re-probe paths with Accept:application/json (bypass SPA catch-all)"

# The SPA likely checks Accept header and only serves HTML to HTML requests.
# Real API endpoints should return JSON or a different response.
# Baseline: what does the root look like with JSON Accept?
echo "=== B0: Root with Accept:application/json (baseline) ==="
$CURL -sk -o /dev/null -w "Status: %{http_code} Size: %{size_download}\n" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  "${BASE}/"
echo "(expected: same 5939B if SPA serves HTML regardless of Accept)"

echo ""
echo "=== B1: API paths with Accept:application/json ==="
echo "Format: STATUS|BYTES|PATH"
for path in \
  /api \
  /api/v1 \
  /api/v2 \
  /api/v3 \
  /api/conversions \
  /api/properties \
  /api/users \
  /api/projects \
  /api/tasks \
  /api/forms \
  /api/hotels \
  /api/status \
  /api/me \
  /api/auth \
  /api/admin \
  /actuator \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /actuator/metrics \
  /actuator/mappings \
  /actuator/beans \
  /actuator/configprops \
  /actuator/loggers \
  /actuator/threaddump \
  /actuator/httptrace \
  /actuator/conditions \
  /health \
  /healthz \
  /ready \
  /readyz \
  /ping \
  /status \
  /info \
  /version \
  /metrics \
  /swagger-ui.html \
  /swagger-ui/index.html \
  /v2/api-docs \
  /v3/api-docs \
  /openapi.json \
  /openapi.yaml \
  /conversion \
  /properties \
  /pct \
  /pct/api \
  /admin \
  /admin/api \
  /management \
  /management/health \
  /management/info \
  /management/env \
  /graphql \
  /graphiql; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" \
    -H "Accept: application/json" \
    --max-time 10 \
    "${BASE}${path}" 2>/dev/null)
  echo "${result}|${path}"
done | tee "$OUTDIR/ci-json-probe.txt"

echo ""
echo "=== B2: Non-SPA responses with JSON Accept (not 5939/5940B, not 404) ==="
python3 -c "
lines = open('/tmp/s15/ci-json-probe.txt').readlines()
spa_sizes = {'5939', '5940', '5941', '5938'}  # SPA sizes
for line in lines:
    parts = line.strip().split('|')
    if len(parts) < 3: continue
    status, size, path = parts[0], parts[1], parts[2]
    if status not in ('404', '000') and size not in spa_sizes:
        print(f'  INTERESTING: {status}/{size}B  {path}')
"

# ─── PHASE C ── SPRING BOOT ACTUATOR TARGETED PROBE ──────────────────────────
log "PHASE C — Spring Boot Actuator deep probe"

# Spring Boot >= 2.x moves actuator to /actuator by default
# Spring Boot < 2.x uses /health, /info, /env, /mappings at root

echo "=== C1: Read /actuator full content ==="
$CURL -sk -D - -o "$OUTDIR/ci-actuator.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json, application/vnd.spring-boot.actuator.v3+json" \
  --max-time 10 \
  "${BASE}/actuator"
SZ=$(wc -c < "$OUTDIR/ci-actuator.json")
echo "Size: $SZ bytes"
if [ "$SZ" -lt 6000 ]; then
  cat "$OUTDIR/ci-actuator.json"
else
  echo "(SPA-sized response — actuator not exposed at /actuator)"
fi

echo ""
echo "=== C2: /actuator/health — read JSON content ==="
$CURL -sk -o "$OUTDIR/ci-actuator-health.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json, application/vnd.spring-boot.actuator.v3+json" \
  --max-time 10 \
  "${BASE}/actuator/health"
SZ=$(wc -c < "$OUTDIR/ci-actuator-health.json")
echo "Size: $SZ bytes"
if [ "$SZ" -lt 6000 ]; then
  cat "$OUTDIR/ci-actuator-health.json"
fi

echo ""
echo "=== C3: /actuator/env — environment variables (HIGH VALUE if open) ==="
$CURL -sk -o "$OUTDIR/ci-actuator-env.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  --max-time 10 \
  "${BASE}/actuator/env"
SZ=$(wc -c < "$OUTDIR/ci-actuator-env.json")
echo "Size: $SZ bytes"
if [ "$SZ" -lt 6000 ]; then
  cat "$OUTDIR/ci-actuator-env.json"
else
  echo "(SPA response — actuator/env not exposed)"
fi

echo ""
echo "=== C4: /actuator/mappings — full endpoint map (HIGH VALUE if open) ==="
$CURL -sk -o "$OUTDIR/ci-actuator-mappings.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  --max-time 10 \
  "${BASE}/actuator/mappings"
SZ=$(wc -c < "$OUTDIR/ci-actuator-mappings.json")
echo "Size: $SZ bytes"
if [ "$SZ" -lt 6000 ]; then
  cat "$OUTDIR/ci-actuator-mappings.json"
else
  echo "(SPA response — actuator/mappings not exposed)"
fi

# ─── PHASE D ── DISCOVER AND PROBE REAL API PATHS ─────────────────────────────
log "PHASE D — Probe API paths discovered from openapi.json + sitemap + common PCT patterns"

echo "=== D1: Read openapi.json paths and extract for probing ==="
python3 - << 'PYEOF'
import json, os

paths_to_probe = set()

for fname in ['ci-openapi.json', 'ci-v2-api-docs.json']:
    fpath = f'/tmp/s15/{fname}'
    if not os.path.exists(fpath): continue
    raw = open(fpath, errors='replace').read().strip()
    if not raw: continue
    try:
        doc = json.loads(raw)
        base = doc.get('basePath', '')
        for path in doc.get('paths', {}):
            full = base + path if not path.startswith(base) else path
            paths_to_probe.add(full)
    except:
        pass

# Also add common PCT / Property Conversion Tool patterns
pct_patterns = [
    '/api/v1/conversions',
    '/api/v1/properties',
    '/api/v1/users',
    '/api/v1/projects',
    '/api/v1/conversion-requests',
    '/api/v1/property-conversions',
    '/api/conversions/list',
    '/api/properties/list',
    '/api/v1/tasks',
    '/api/v1/forms',
    '/api/v1/reports',
    '/api/v1/hotels',
    '/api/v1/brands',
    '/api/v1/contacts',
    '/api/v1/documents',
    '/pct/api/v1/conversions',
    '/pct/conversions',
    '/conversion/api/v1',
    '/conversion/list',
]
for p in pct_patterns:
    paths_to_probe.add(p)

print(f"Total paths to probe: {len(paths_to_probe)}")
with open('/tmp/s15/ci-discovered-paths.txt', 'w') as f:
    for p in sorted(paths_to_probe):
        f.write(p + '\n')
for p in sorted(paths_to_probe):
    print(' ', p)
PYEOF

echo ""
echo "=== D2: Probe discovered paths ==="
if [ -s "$OUTDIR/ci-discovered-paths.txt" ]; then
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
      -H "User-Agent: $UA" \
      -H "Accept: application/json" \
      --max-time 10 \
      "${BASE}${path}" 2>/dev/null)
    echo "${result}|${path}"
  done < "$OUTDIR/ci-discovered-paths.txt" | tee "$OUTDIR/ci-discovered-results.txt"

  echo ""
  echo "=== D3: Non-SPA discovered path responses ==="
  python3 -c "
lines = open('/tmp/s15/ci-discovered-results.txt').readlines()
spa_sizes = {'5939','5940','5941','5938','1280'}
for line in lines:
    parts = line.strip().split('|')
    if len(parts) < 3: continue
    status, size, path = parts[0], parts[1], parts[2]
    if status not in ('404','000') and size not in spa_sizes:
        print(f'  REAL ENDPOINT: {status}/{size}B  {path}')
" 2>/dev/null || echo "(no interesting discovered paths)"
else
  echo "No discovered paths file — openapi.json was empty or not JSON"
fi

# ─── PHASE E ── AUTH BYPASS TESTING ──────────────────────────────────────────
log "PHASE E — Auth bypass testing on confirmed real endpoints"

echo "=== E1: /health with various content types ==="
for accept in "application/json" "text/plain" "*/*" "application/xml"; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" -H "Accept: $accept" --max-time 10 "${BASE}/health")
  echo "Accept:$accept → ${result}"
done

echo ""
echo "=== E2: POST to /health (Spring Actuator sometimes allows shutdown via POST) ==="
$CURL -sk -o "$OUTDIR/ci-health-post.txt" \
  -X POST \
  -H "User-Agent: $UA" \
  -H "Content-Type: application/json" \
  --max-time 10 \
  "${BASE}/health"
echo "POST /health: $(cat "$OUTDIR/ci-health-post.txt" | head -3)"

echo ""
echo "=== E3: /actuator/shutdown probe (read-only test — NO POST) ==="
# Only GET probe — do NOT POST to /actuator/shutdown (would kill the app)
result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
  -H "User-Agent: $UA" -H "Accept: application/json" --max-time 10 "${BASE}/actuator/shutdown")
echo "GET /actuator/shutdown: $result (405 = endpoint exists but only accepts POST; 404 = not exposed)"

echo ""
echo "=== E4: Try /api/** without auth — look for 401 vs 403 (forbidden vs unauthorized) ==="
# 401 = auth required but endpoint exists (confirm by adding fake token)
# 403 = endpoint exists but you're blocked regardless
# 404 = endpoint doesn't exist
# SPA size = catch-all
for path in /api/v1/conversions /api/v1/properties /api/conversions /api/properties; do
  # Without auth
  r1=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" -H "Accept: application/json" --max-time 10 "${BASE}${path}")
  # With fake Bearer token (to distinguish 401 vs 403)
  r2=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" -H "Accept: application/json" \
    -H "Authorization: Bearer fake_token_12345" --max-time 10 "${BASE}${path}")
  echo "  ${path}: no-auth=${r1} | fake-token=${r2}"
done

echo ""
echo "=== E5: Check for CORS misconfiguration on any API endpoint ==="
for path in /api /api/v1 /health /openapi.json; do
  cors=$($CURL -sk -o /dev/null \
    -H "User-Agent: $UA" \
    -H "Origin: https://evil.com" \
    -H "Accept: application/json" \
    -D - --max-time 10 "${BASE}${path}" 2>/dev/null \
    | grep -i 'access-control' | head -3)
  echo "  ${path}:"
  echo "    $cors"
done

# ─── PHASE F ── ESUPPLIER DOCUMENT AUDIT ─────────────────────────────────────
log "PHASE F — esupplier.marriott.com document audit"

ESUP=https://esupplier.marriott.com

echo "=== F1: Read /default_files/filelist.xml (273B — directory index) ==="
$CURL -sk -o "$OUTDIR/esupplier-filelist.xml" \
  -H "User-Agent: $UA" \
  --max-time 15 "${ESUP}/default_files/filelist.xml"
echo "filelist.xml content:"
cat "$OUTDIR/esupplier-filelist.xml"
echo ""

echo "=== F2: Parse filelist.xml for additional file paths ==="
python3 -c "
import re
content = open('/tmp/s15/esupplier-filelist.xml', errors='replace').read()
print('Raw content:', repr(content[:500]))
# Extract file names from XML
files = re.findall(r'<File\s+Name=[\"\'](.*?)[\"\']\s*/>', content)
files += re.findall(r'<File[^>]*href=[\"\'](.*?)[\"\']\s*', content)
files += re.findall(r'<File[^>]*Name=\"([^\"]+)\"', content)
files += re.findall(r'href=\"([^\"]+)\"', content)
print(f'Files found: {len(files)}')
for f in files: print(' ', f)
" 2>&1

echo ""
echo "=== F3: Extract links from /marrforms/esuppliersplash.htm (48KB HTML) ==="
$CURL -sk -o "$OUTDIR/esupplier-splash.html" \
  -H "User-Agent: $UA" --max-time 20 \
  "${ESUP}/marrforms/esuppliersplash.htm"
echo "Splash page: $(wc -c < "$OUTDIR/esupplier-splash.html") bytes"

python3 - << 'PYEOF'
import re

try:
    body = open('/tmp/s15/esupplier-splash.html', encoding='windows-1252', errors='replace').read()
except:
    body = open('/tmp/s15/esupplier-splash.html', encoding='latin-1', errors='replace').read()

title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
links = re.findall(r'href=["\']([^"\'#]{3,120})["\']', body, re.I)
forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I)
inputs = re.findall(r'<input[^>]+>', body, re.I)
iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', body, re.I)
metas = re.findall(r'<meta[^>]+content=["\']([^"\']{10,120})["\']', body, re.I)

print(f'Title: {title}')
print(f'\nLinks ({len(links)}):')
for l in links[:40]: print(' ', l)
print(f'\nForms: {forms[:5]}')
print(f'\nInputs: {len(inputs)}')
for i in inputs[:10]: print(' ', i[:100])
print(f'\nIframes: {iframes[:5]}')
print(f'\nMeta content (sample): {metas[:3]}')
PYEOF

echo ""
echo "=== F4: Probe any new paths discovered in splash/filelist ==="
python3 - << 'PYEOF'
import re, subprocess

try:
    body = open('/tmp/s15/esupplier-splash.html', encoding='windows-1252', errors='replace').read()
except:
    body = open('/tmp/s15/esupplier-splash.html', encoding='latin-1', errors='replace').read()

links = re.findall(r'href=["\']([^"\'#]{3,120})["\']', body, re.I)

# Filter for relative paths or esupplier URLs
paths = set()
for l in links:
    if l.startswith('/'):
        paths.add(l.split('?')[0][:80])
    elif 'esupplier.marriott.com' in l:
        from urllib.parse import urlparse
        p = urlparse(l).path
        if p: paths.add(p.split('?')[0][:80])

print(f"Paths to probe: {len(paths)}")
with open('/tmp/s15/esupplier-discovered.txt', 'w') as f:
    for p in sorted(paths): f.write(p + '\n')
for p in sorted(paths): print(' ', p)
PYEOF

if [ -s "$OUTDIR/esupplier-discovered.txt" ]; then
  echo "Probing discovered esupplier paths..."
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
      -H "User-Agent: $UA" --max-time 10 "${ESUP}${path}" 2>/dev/null)
    echo "${result}|${path}"
  done < "$OUTDIR/esupplier-discovered.txt"
fi

# ─── PHASE G ── DECISION GATE ─────────────────────────────────────────────────
log "PHASE G — DECISION GATE"

echo ""
echo "=== CRITICAL: openapi.json and v2/api-docs content ==="
echo "openapi.json ($(wc -c < "$OUTDIR/ci-openapi.json")B):"
cat "$OUTDIR/ci-openapi.json" | head -50
echo ""
echo "v2/api-docs ($(wc -c < "$OUTDIR/ci-v2-api-docs.json")B):"
cat "$OUTDIR/ci-v2-api-docs.json" | head -50

echo ""
echo "=== Non-SPA JSON-Accept responses (real API surface) ==="
python3 -c "
import sys
spa_sizes = {'5939','5940','5941','5938','1280','0'}
try:
    lines = open('/tmp/s15/ci-json-probe.txt').readlines()
    for line in lines:
        parts = line.strip().split('|')
        if len(parts) < 3: continue
        status, size, path = parts[0], parts[1], parts[2]
        if status not in ('404','000') and size not in spa_sizes:
            print(f'  REAL: {status}/{size}B  {path}')
    print('(checked $(wc -l /tmp/s15/ci-json-probe.txt | cut -d\" \" -f1) paths)')
except: pass
" 2>/dev/null || true

echo ""
echo "=== Actuator exposure check ==="
for f in ci-actuator.json ci-actuator-health.json ci-actuator-env.json ci-actuator-mappings.json; do
  if [ -f "$OUTDIR/$f" ]; then
    sz=$(wc -c < "$OUTDIR/$f")
    echo "$f: ${sz}B"
    if [ "$sz" -lt 5500 ] && [ "$sz" -gt 2 ]; then
      echo "  CONTENT: $(cat "$OUTDIR/$f" | head -5)"
    fi
  fi
done

echo ""
echo "=== esupplier filelist.xml ==="
cat "$OUTDIR/esupplier-filelist.xml" 2>/dev/null || echo "(not saved)"

echo ""
echo "=== Raw files in $OUTDIR ==="
ls -lh "$OUTDIR/"

log "SESSION 15 COMPLETE"
echo "Key decision points:"
echo " 1. If openapi.json has real endpoints → test each for missing auth (401 vs 200)"
echo " 2. If actuator/* returns non-SPA JSON → CRITICAL finding (Spring env exposure)"
echo " 3. If JSON-Accept probe reveals API endpoints → test IDOR (increment IDs)"
echo " 4. If esupplier splash has useful links → probe them in next session"
echo " 5. If /health returns JSON with app info → may reveal stack/version details"
echo ""
echo "Save results: mkdir -p ~/bug-bounty-hunting-/results/marriott/session15/ && cp -r /tmp/s15/* ~/bug-bounty-hunting-/results/marriott/session15/"
