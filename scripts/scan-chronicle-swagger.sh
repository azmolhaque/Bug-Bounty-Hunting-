#!/usr/bin/env bash
# Chronicle SOAR API — Swagger enumeration + unauthenticated endpoint probe
# Target: app.siemplify-soar.com (confirmed Swagger accessible without auth)
# Run: bash scripts/scan-chronicle-swagger.sh
# Phase 3C from runbook: SOAR Legacy API Swagger Enumeration
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET="app.siemplify-soar.com"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/chronicle.security/evidence/swagger-${STAMP}
mkdir -p "${OUT}"

LOG="${OUT}/swagger-scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== CHRONICLE SOAR SWAGGER SCAN — ${STAMP} ==="
./scripts/scope-check.sh "${TARGET}" || { echo "SCOPE FAIL"; exit 1; }

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"

# ── Step 1: Fetch Swagger index and JSON for all 3 API versions ──────────────
echo ""
echo "[1] Fetching Swagger UI and JSON schemas..."

for VER in v1 v2 v3; do
    echo "[1] Fetching swagger.json for ${VER}..."
    curl -sk --max-time 30 \
        -H "User-Agent: ${UA}" \
        "https://${TARGET}/swagger/${VER}/swagger.json" \
        -o "${OUT}/swagger-${VER}.json" 2>/dev/null

    if [ -s "${OUT}/swagger-${VER}.json" ]; then
        # Check it's actual JSON, not an error page
        if python3 -c "import sys,json; json.load(open('${OUT}/swagger-${VER}.json'))" 2>/dev/null; then
            echo "[1] ${VER}: $(wc -c < "${OUT}/swagger-${VER}.json") bytes — valid JSON"
            # Count endpoints
            python3 -c "
import json
d = json.load(open('${OUT}/swagger-${VER}.json'))
paths = d.get('paths', {})
print(f'[1] ${VER}: {len(paths)} paths')
# Print all paths
for path in sorted(paths.keys()):
    methods = [m.upper() for m in paths[path].keys() if m in ('get','post','put','delete','patch')]
    print(f'  {\" \".join(methods):20s} {path}')
" | tee "${OUT}/paths-${VER}.txt"
        else
            echo "[1] ${VER}: not valid JSON — got:"
            head -3 "${OUT}/swagger-${VER}.json"
        fi
    else
        echo "[1] ${VER}: empty or failed"
        # Try alternative swagger.json path
        curl -sk --max-time 30 \
            -H "User-Agent: ${UA}" \
            "https://${TARGET}/swagger/swagger.json" \
            -o "${OUT}/swagger-root.json" 2>/dev/null
    fi
done

# Try the Swagger index.html for clues about which URL the JSON is served from
echo "[1] Fetching swagger/index.html..."
curl -sk --max-time 30 \
    -H "User-Agent: ${UA}" \
    "https://${TARGET}/swagger/index.html" \
    -o "${OUT}/swagger-index.html" 2>/dev/null

echo "[1] Swagger HTML title/urls:"
grep -oE '"url"[^,]+|<title>[^<]+|SwaggerUI\([^)]+\)' "${OUT}/swagger-index.html" 2>/dev/null | head -20

# ── Step 2: Extract all unique API paths across versions ─────────────────────
echo ""
echo "[2] Extracting all unique paths..."
python3 -c "
import json, os, sys

all_paths = {}
for ver in ['v1', 'v2', 'v3']:
    fname = '${OUT}/swagger-{}.json'.format(ver)
    if not os.path.exists(fname):
        continue
    try:
        d = json.load(open(fname))
    except:
        continue
    for path, methods in d.get('paths', {}).items():
        for method, spec in methods.items():
            if method not in ('get','post','put','delete','patch','head','options'):
                continue
            key = (method.upper(), path)
            all_paths[key] = {
                'ver': ver,
                'summary': spec.get('summary',''),
                'tags': spec.get('tags', []),
                'params': [p.get('name','') for p in spec.get('parameters',[]) if p.get('in') in ('path','query')],
                'security': spec.get('security', None)  # None = inherits global, [] = no auth
            }

# Print sorted by path
for (method, path), info in sorted(all_paths.items(), key=lambda x: x[0][1]):
    auth_str = 'NO-AUTH' if info['security'] == [] else 'AUTH?'
    params_str = ','.join(info['params']) if info['params'] else ''
    print(f\"{method:7s} {path:80s} [{auth_str}] params=[{params_str}] {info['summary'][:50]}\")
" | tee "${OUT}/all-paths-combined.txt"

echo "[2] Total unique paths: $(wc -l < "${OUT}/all-paths-combined.txt")"

# ── Step 3: Extract URL/URI parameters across all endpoints ──────────────────
echo ""
echo "[3] Extracting URL-parameter fields (SSRF surface)..."
python3 -c "
import json, os

for ver in ['v1', 'v2', 'v3']:
    fname = '${OUT}/swagger-{}.json'.format(ver)
    if not os.path.exists(fname):
        continue
    try:
        d = json.load(open(fname))
    except:
        continue
    for path, methods in d.get('paths', {}).items():
        for method, spec in methods.items():
            if method not in ('get','post','put','delete','patch'):
                continue
            params = spec.get('parameters', [])
            body = spec.get('requestBody', {})
            for p in params:
                name = p.get('name','').lower()
                if any(k in name for k in ('url','uri','endpoint','host','server','address','webhook','callback','redirect','source','target','destination','feed')):
                    print(f\"[{ver}] {method.upper()} {path} → param: {p.get('name','')} (in={p.get('in','')})\")
" | tee "${OUT}/ssrf-params.txt"

echo "[3] SSRF-relevant parameter paths: $(wc -l < "${OUT}/ssrf-params.txt")"

# ── Step 4: Extract ID-based paths (IDOR surface) ────────────────────────────
echo ""
echo "[4] Extracting ID-parameterized paths (IDOR surface)..."
grep -E '\{[A-Za-z_]*[Ii][Dd][A-Za-z_]*\}|\{case|\{alert|\{integration|\{connector|\{playbook|\{instance' \
    "${OUT}/all-paths-combined.txt" 2>/dev/null \
    | sort -u | tee "${OUT}/idor-paths.txt"

echo "[4] IDOR candidate paths: $(wc -l < "${OUT}/idor-paths.txt")"

# ── Step 5: Probe key unauthenticated endpoints ───────────────────────────────
echo ""
echo "[5] Probing select endpoints without auth..."

probe_unauth() {
    local METHOD="$1"
    local BPATH="$2"
    local DESC="$3"
    local RESP
    RESP=$(curl -sk --max-time 15 \
        -X "${METHOD}" \
        -H "User-Agent: ${UA}" \
        -H "Accept: application/json" \
        -w "\n__CODE__%{http_code}" \
        "https://${TARGET}${BPATH}" 2>/dev/null)
    local CODE="${RESP##*__CODE__}"
    local BODY="${RESP%__CODE__*}"
    echo "[5][${CODE}] ${METHOD} ${BPATH} — ${DESC}"
    # Print body for non-401/000 responses
    if [ "${CODE}" != "401" ] && [ "${CODE}" != "000" ] && [ "${CODE}" != "403" ]; then
        echo "    BODY: ${BODY}" | head -4
        printf '%s %s [%s]: %s\n' "${METHOD}" "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/unauth-hits.txt"
    fi
}

# Health/status — often unauthenticated
probe_unauth "GET" "/healthz" "health check"
probe_unauth "GET" "/health" "health check"
probe_unauth "GET" "/api/v1/health" "API health"
probe_unauth "GET" "/api/v1/version" "version info"
probe_unauth "GET" "/api/v2/health" "API v2 health"

# Case management — could be public on demo tenant
probe_unauth "GET" "/external/v1/cases/getpage" "list cases"
probe_unauth "GET" "/api/external/v1/cases" "list cases v2"
probe_unauth "GET" "/external/v1/cases/1" "get case 1"
probe_unauth "GET" "/external/v1/cases/2" "get case 2"

# Integration instances — store API credentials
probe_unauth "GET" "/external/v1/integrations/instances/list" "list integration instances"
probe_unauth "GET" "/external/v1/integrations/GetIntegrationInstance" "get integration instance"
probe_unauth "GET" "/api/external/v1/integrations/instances" "integration instances"

# Connectors (SSRF surface)
probe_unauth "GET" "/external/v1/connectors" "list connectors"
probe_unauth "GET" "/api/external/v1/connectors" "list connectors v2"
probe_unauth "GET" "/external/v1/connectors/1" "get connector 1"

# Playbooks
probe_unauth "GET" "/external/v1/playbooks" "list playbooks"
probe_unauth "GET" "/api/external/v1/playbooks" "list playbooks v2"

# Webhooks (SSRF: if webhook URL is exposed in config)
probe_unauth "GET" "/external/v1/webhooks" "list webhooks"
probe_unauth "GET" "/api/external/v1/webhooks" "list webhooks v2"

# Alerts
probe_unauth "GET" "/external/v1/alerts" "list alerts"
probe_unauth "GET" "/api/external/v1/alerts" "list alerts v2"

# Settings (may expose config including URLs)
probe_unauth "GET" "/external/v1/settings" "settings"
probe_unauth "GET" "/api/external/v1/settings" "settings v2"

# Marketplace (integration catalog — may expose configs)
probe_unauth "GET" "/external/v1/marketplace" "marketplace"
probe_unauth "GET" "/api/external/v1/marketplace/integrations" "marketplace integrations"

# Homepage/dashboard (often needs auth but worth checking)
probe_unauth "GET" "/homepage" "homepage"
probe_unauth "GET" "/api/v1/homepage" "API homepage"

# SOC roles (user/role enumeration)
probe_unauth "GET" "/external/v1/security/users" "list users"
probe_unauth "GET" "/api/external/v1/security/roles" "list roles"

# ── Step 6: Check if app tenant Swagger exposes real data structure ───────────
echo ""
echo "[6] Checking Swagger-defined models for sensitive data structures..."
python3 -c "
import json, os

for ver in ['v1', 'v2', 'v3']:
    fname = '${OUT}/swagger-{}.json'.format(ver)
    if not os.path.exists(fname):
        continue
    try:
        d = json.load(open(fname))
    except:
        continue
    # Definitions/schemas
    defs = d.get('definitions', d.get('components', {}).get('schemas', {}))
    interesting = ['IntegrationInstance', 'Connector', 'PlaybookAction', 'Webhook',
                   'FeedSource', 'Credential', 'ApiKey', 'Token', 'Password',
                   'Case', 'Alert', 'User', 'Role', 'Settings']
    for name, schema in defs.items():
        for iname in interesting:
            if iname.lower() in name.lower():
                props = list(schema.get('properties', {}).keys())
                print(f'[{ver}] Schema: {name} — fields: {props[:10]}')
                break
" | tee "${OUT}/sensitive-schemas.txt"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== SWAGGER SCAN COMPLETE — ${STAMP} ==="
echo "Swagger v1 paths    : $(wc -l < "${OUT}/paths-v1.txt" 2>/dev/null || echo 0)"
echo "Swagger v2 paths    : $(wc -l < "${OUT}/paths-v2.txt" 2>/dev/null || echo 0)"
echo "Swagger v3 paths    : $(wc -l < "${OUT}/paths-v3.txt" 2>/dev/null || echo 0)"
echo "Total unique paths  : $(wc -l < "${OUT}/all-paths-combined.txt" 2>/dev/null || echo 0)"
echo "SSRF param paths    : $(wc -l < "${OUT}/ssrf-params.txt" 2>/dev/null || echo 0)"
echo "IDOR candidate paths: $(wc -l < "${OUT}/idor-paths.txt" 2>/dev/null || echo 0)"
echo "Unauth hits         : $(wc -l < "${OUT}/unauth-hits.txt" 2>/dev/null || echo 0)"
echo "Log                 : ${LOG}"
echo ""
echo "NEXT STEPS:"
echo "  1. Review SSRF params: ${OUT}/ssrf-params.txt"
echo "  2. Review IDOR paths: ${OUT}/idor-paths.txt"
echo "  3. Sign up for trial → get Bearer token → test IDOR between accounts"
echo "  4. Any unauth hits: ${OUT}/unauth-hits.txt"
echo "  5. git add ${OUT}/ && git push"
