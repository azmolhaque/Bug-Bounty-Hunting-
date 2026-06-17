#!/usr/bin/env bash
# Chronicle SOAR — probe REAL /api/external/v1/ endpoints without auth
#
# Previous scan had a bug: it probed paths WITHOUT /api/ prefix, hitting the
# Angular SPA catch-all (HTTP 200 with HTML) instead of real API endpoints.
#
# This script:
#   1. Downloads/re-uses Swagger JSON to get all real /api/external/v1/ paths
#   2. Probes each with GET and POST (with empty body), checking for JSON vs HTML
#   3. Flags non-401/403 responses that return JSON (real API data without auth)
#
# Run: bash scripts/scan-chronicle-api-routes.sh
# Optional: SOAR_TOKEN=xxx bash scripts/scan-chronicle-api-routes.sh (for auth comparison)
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET="app.siemplify-soar.com"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/chronicle.security/evidence/api-routes-${STAMP}
mkdir -p "${OUT}"

LOG="${OUT}/api-routes.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== CHRONICLE SOAR API ROUTE PROBE — ${STAMP} ==="
./scripts/scope-check.sh "${TARGET}" || { echo "SCOPE FAIL"; exit 1; }

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
SOAR_TOKEN="${SOAR_TOKEN:-}"

# ── Step 1: Get Swagger JSON (re-use existing or download fresh) ──────────────
echo ""
echo "[1] Fetching Swagger v1 JSON..."

SWAGGER_JSON="${OUT}/swagger-v1.json"
curl -sk --max-time 30 \
    -H "User-Agent: ${UA}" \
    "https://${TARGET}/swagger/v1/swagger.json" \
    -o "${SWAGGER_JSON}" 2>/dev/null

if ! python3 -c "import json; json.load(open('${SWAGGER_JSON}'))" 2>/dev/null; then
    echo "[1] ERROR: Could not fetch valid swagger.json from ${TARGET}"
    # Try to find a previously saved one
    EXISTING=$(find ~/bug-bounty-hunting-/results/chronicle.security/evidence -name "swagger-v1.json" 2>/dev/null | head -1)
    if [ -n "${EXISTING}" ]; then
        echo "[1] Using existing Swagger: ${EXISTING}"
        cp "${EXISTING}" "${SWAGGER_JSON}"
    else
        echo "[1] No existing Swagger found — cannot enumerate paths. Exiting."
        exit 1
    fi
fi

NPATH=$(python3 -c "import json; d=json.load(open('${SWAGGER_JSON}')); print(len(d.get('paths',{})))")
echo "[1] Swagger loaded: ${NPATH} paths"

# ── Step 2: Extract all unique paths from Swagger ────────────────────────────
echo ""
echo "[2] Extracting all Swagger paths..."
python3 - <<'PYEOF' | tee "${OUT}/swagger-paths.txt"
import json, sys

try:
    d = json.load(open("/dev/stdin"))
except:
    import os
    d = json.load(open(sys.argv[1] if len(sys.argv)>1 else ""))

PYEOF

python3 - "${SWAGGER_JSON}" <<'PYEOF' | tee "${OUT}/swagger-paths.txt"
import json, sys

d = json.load(open(sys.argv[1]))
for path, methods in sorted(d.get('paths', {}).items()):
    for method in methods:
        if method.lower() in ('get','post','put','delete','patch'):
            print(f"{method.upper()} {path}")
PYEOF

echo "[2] Total path+method combinations: $(wc -l < "${OUT}/swagger-paths.txt")"

# ── Step 3: Probe each path — detect JSON vs HTML, flag non-401 ──────────────
echo ""
echo "[3] Probing all /api/external/ paths (this will take a few minutes)..."
echo "    JSON non-401 responses will be logged to: ${OUT}/unauth-json-hits.txt"
echo ""

touch "${OUT}/unauth-json-hits.txt"
touch "${OUT}/all-probes.tsv"

is_json() {
    python3 -c "import sys,json; json.loads(sys.stdin.read()); print('yes')" 2>/dev/null || echo "no"
}

probe_api() {
    local METHOD="$1"
    local SWAGGER_PATH="$2"
    # Convert Swagger path params {foo} to literal "1" for probing
    local BPATH
    BPATH=$(printf '%s' "${SWAGGER_PATH}" | sed 's/{[^}]*}/1/g')

    local RESP CODE BODY JSON_BODY AUTH_HEADER=""
    if [ -n "${SOAR_TOKEN}" ]; then
        AUTH_HEADER="-H 'AppKey: ${SOAR_TOKEN}'"
    fi

    if [ "${METHOD}" = "GET" ]; then
        RESP=$(curl -sk --max-time 15 \
            -X GET \
            -H "User-Agent: ${UA}" \
            -H "Accept: application/json" \
            ${SOAR_TOKEN:+-H "AppKey: ${SOAR_TOKEN}"} \
            -w "\n__CODE__%{http_code}" \
            "https://${TARGET}${BPATH}" 2>/dev/null)
    else
        RESP=$(curl -sk --max-time 15 \
            -X "${METHOD}" \
            -H "User-Agent: ${UA}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            ${SOAR_TOKEN:+-H "AppKey: ${SOAR_TOKEN}"} \
            -d '{}' \
            -w "\n__CODE__%{http_code}" \
            "https://${TARGET}${BPATH}" 2>/dev/null)
    fi

    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"

    # Check if response is JSON or HTML
    local IS_JSON
    IS_JSON=$(printf '%s' "${BODY}" | python3 -c "import sys,json; json.loads(sys.stdin.read()); print('yes')" 2>/dev/null || echo "no")

    printf '%s\t%s\t%s\t%s\t%s\n' "${METHOD}" "${BPATH}" "${CODE}" "${IS_JSON}" "${BODY:0:100}" \
        >> "${OUT}/all-probes.tsv"

    # Highlight non-auth-blocked, JSON responses
    if [ "${IS_JSON}" = "yes" ] && [ "${CODE}" != "000" ]; then
        if [ "${CODE}" != "401" ] && [ "${CODE}" != "403" ]; then
            echo "*** HIT [${CODE}] ${METHOD} ${BPATH} (JSON response, not blocked by auth!)"
            printf '%s\n' "${BODY}" | python3 -m json.tool 2>/dev/null | head -15
            echo "---"
            printf '%s\t%s\t%s\t%s\n' "${METHOD}" "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/unauth-json-hits.txt"
        else
            # 401/403 JSON — still useful to know it's a real API endpoint
            echo "  [${CODE}] ${METHOD} ${BPATH} — real API (JSON), auth required"
        fi
    elif [ "${CODE}" = "405" ]; then
        echo "  [405] ${METHOD} ${BPATH} — Method Not Allowed (wrong method, endpoint EXISTS)"
        printf '%s\t%s\t%s\t%s\n' "${METHOD}" "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/unauth-json-hits.txt"
    fi
}

# Read paths and probe, rate-limit to ~1 req/sec
TOTAL=$(wc -l < "${OUT}/swagger-paths.txt")
COUNT=0
while IFS=' ' read -r METHOD SWAGGER_PATH; do
    COUNT=$((COUNT + 1))
    echo -n "[${COUNT}/${TOTAL}] "
    probe_api "${METHOD}" "${SWAGGER_PATH}"
    sleep 0.5  # 2 req/sec max — polite
done < "${OUT}/swagger-paths.txt"

# ── Step 4: Special test — POST endpoints that Swagger marks as no-security ──
echo ""
echo "[4] Checking Swagger for endpoints with explicit security: [] (no-auth override)..."
python3 - "${SWAGGER_JSON}" <<'PYEOF'
import json, sys

d = json.load(open(sys.argv[1]))
global_sec = d.get('security', None)
for path, methods in sorted(d.get('paths', {}).items()):
    for method, spec in methods.items():
        if method.lower() not in ('get','post','put','delete','patch'):
            continue
        ep_sec = spec.get('security', None)
        # security: [] explicitly means NO AUTH required
        if ep_sec == []:
            print(f"  NO-AUTH OVERRIDE: {method.upper()} {path}")
            print(f"    Summary: {spec.get('summary', '')}")
PYEOF

# ── Step 5: Check /api/external/v1/settings/GetPublicCertificate explicitly ──
echo ""
echo "[5] Probing known-public endpoints explicitly..."
for BPATH in \
    "/api/external/v1/settings/GetPublicCertificate" \
    "/api/external/v1/settings/GetLatestLicenseAgreement" \
    "/api/external/v1/settings/GetSystemVersion" \
    "/api/external/v1/warroom/GetForgotPasswordTimeLimit" \
    "/api/external/v1/warroom/GetDepartments" \
    "/api/external/v1/store/GetIntegrationsStoreData" \
    "/api/external/v1/store/GetUsecasesCards" \
    "/api/external/v1/store/GetMarketplaceCountsData"; do
    RESP=$(curl -sk --max-time 10 \
        -H "User-Agent: ${UA}" \
        -H "Accept: application/json" \
        -w "\n__CODE__%{http_code}" \
        "https://${TARGET}${BPATH}" 2>/dev/null)
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"
    IS_JSON=$(printf '%s' "${BODY}" | python3 -c "import sys,json; json.loads(sys.stdin.read()); print('yes')" 2>/dev/null || echo "no")
    echo "  [${CODE}][json=${IS_JSON}] GET ${BPATH}"
    if [ "${IS_JSON}" = "yes" ] && [ "${CODE}" != "401" ] && [ "${CODE}" != "403" ]; then
        printf '%s' "${BODY}" | python3 -m json.tool 2>/dev/null | head -10
        printf 'GET\t%s\t%s\t%s\n' "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/unauth-json-hits.txt"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== API ROUTE PROBE COMPLETE — ${STAMP} ==="
echo "Total probes      : ${TOTAL}"
echo "All results (TSV) : ${OUT}/all-probes.tsv"
echo "Non-auth JSON hits: $(wc -l < "${OUT}/unauth-json-hits.txt" 2>/dev/null || echo 0)"
echo "Log               : ${LOG}"
echo ""
echo "REVIEW:"
echo "  1. Non-auth JSON hits (real API data without auth): ${OUT}/unauth-json-hits.txt"
echo "  2. 405s in hits file = confirmed real endpoints with wrong method tested"
echo "  3. Any 200 JSON = unauthenticated data exposure → report"
echo ""
if [ -z "${SOAR_TOKEN}" ]; then
    echo "NOTE: Re-run with SOAR_TOKEN=<token> to compare authenticated vs unauthenticated responses"
fi
