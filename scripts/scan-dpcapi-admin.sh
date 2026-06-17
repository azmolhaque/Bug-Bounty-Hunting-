#!/usr/bin/env bash
# dpcapi-admin.photomath.com — deep path enumeration
# /healthz returns "alive" (confirmed from mobile 2026-06-17)
# Pi needs WAF bypass headers (X-Forwarded-For: 127.0.0.1) to bypass 403
# Run: bash scripts/scan-dpcapi-admin.sh
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET="dpcapi-admin.photomath.com"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/photomath.net/evidence/session2-${STAMP}
mkdir -p "${OUT}"

LOG="${OUT}/dpcapi-admin-scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== dpcapi-admin DEEP SCAN — ${STAMP} ==="
./scripts/scope-check.sh "${TARGET}" || { echo "SCOPE FAIL"; exit 1; }

# WAF bypass headers — required for Pi IP; mobile doesn't need them
HDRS='-H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1"'

probe() {
    local BPATH="$1"
    local RESPONSE
    RESPONSE=$(curl -sk --max-time 15 \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" \
        -H "X-Originating-IP: 127.0.0.1" \
        -w "\n__STATUS__%{http_code}" \
        "https://${TARGET}${BPATH}" 2>/dev/null)
    local STATUS="${RESPONSE##*__STATUS__}"
    local BODY="${RESPONSE%__STATUS__*}"
    # Only print if NOT the GCLB no-route 404 and NOT 000
    if [ "${STATUS}" = "000" ]; then
        return
    fi
    if echo "${BODY}" | grep -q "service rules for the path non-existent"; then
        # GCLB routing miss — boring, print only to full log
        echo "  GCLB-404: ${BPATH}" >> "${OUT}/dpcapi-all-paths.txt"
        return
    fi
    # Anything else: interesting — print to both stdout and file
    echo "[${STATUS}] ${BPATH}"
    echo "${BODY}" | head -5
    echo "---"
    echo "[${STATUS}] ${BPATH}" >> "${OUT}/dpcapi-hits.txt"
    echo "${BODY}" >> "${OUT}/dpcapi-hits.txt"
    echo "---" >> "${OUT}/dpcapi-hits.txt"
}

echo "[*] Phase 1 — Known live path verification"
probe /healthz
probe /readyz
probe /livez

echo ""
echo "[*] Phase 2 — Standard health/info paths"
for BPATH in \
    /health /healthz /healthz/ /readyz /livez /ping /status /version /info \
    /healthz/ready /readyz/ready /livez/ping \
    /actuator /actuator/health /actuator/info /actuator/env \
    /actuator/mappings /actuator/routes /actuator/beans; do
    probe "${BPATH}"
done

echo ""
echo "[*] Phase 3 — API version prefixes"
for VER in /api /api/v1 /api/v2 /api/v3 /api/v4 /api/v5 /v1 /v2 /v3 /v4 /v5 \
            /api/v1/ /api/v2/ /api/v3/; do
    probe "${VER}"
done

echo ""
echo "[*] Phase 4 — DPC domain paths (Data Processing/Content)"
for BPATH in \
    /dpc /dpc/api /dpc/v1 /dpc/admin \
    /problems /problems/list /problem \
    /solutions /solution \
    /quizzes /quiz /quiz/list \
    /grading /grade /grades /grade-quizzes \
    /experts /expert /experts/list \
    /users /user /users/list \
    /cases /case /assignments /assignment \
    /content /content/list /content/api \
    /topics /topic \
    /submissions /submission \
    /reviews /review \
    /admin /admin/login /admin/dashboard /admin/users \
    /dashboard /login /auth /auth/login; do
    probe "${BPATH}"
done

echo ""
echo "[*] Phase 5 — Common API doc / debug paths"
for BPATH in \
    /swagger /swagger/ /swagger-ui /swagger-ui.html /swagger-ui/index.html \
    /api-docs /api-docs/swagger.json /v2/api-docs /v3/api-docs \
    /openapi /openapi.json /openapi.yaml \
    /graphql /graphiql /graphql/playground \
    /docs /doc /documentation \
    /metrics /prometheus /debug /pprof \
    /robots.txt /sitemap.xml /.well-known/openid-configuration; do
    probe "${BPATH}"
done

echo ""
echo "[*] Phase 6 — API paths derived from portal URL mining (user ID 273638 found)"
for BPATH in \
    /api/quiz/grade-quizzes \
    /api/quiz/grade-quizzes/user/1 \
    /api/quiz/grade-quizzes/user/273638 \
    /api/quiz \
    /api/quiz/list \
    /api/quiz/1 \
    /api/users/273638 \
    /api/users/1 \
    /api/users \
    /api/experts \
    /api/experts/1 \
    /api/solutions \
    /api/solutions/1 \
    /api/cases \
    /api/problems \
    /api/assignments \
    /api/grading \
    /api/earnings \
    /api/earnings/user/273638; do
    probe "${BPATH}"
done

echo ""
echo "[*] Phase 7 — Also probe the non-admin DPC API for comparison"
TARGET_NONAUTH="dpcapi.photomath.net"
./scripts/scope-check.sh "${TARGET_NONAUTH}" || echo "dpcapi.photomath.net not in scope — skipping"
if ./scripts/scope-check.sh "${TARGET_NONAUTH}" 2>/dev/null | grep -q IN-SCOPE; then
    echo "--- dpcapi.photomath.net (non-admin, for path comparison) ---"
    for BPATH in /healthz /health /readyz /api /api/v1 /api/v2 /swagger /version \
                 /api/quiz /api/users /api/solutions /api/problems; do
        STATUS=$(curl -sk --max-time 10 \
            -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" \
            -o /tmp/dpcapi-nonauth-resp.txt \
            -w "%{http_code}" "https://${TARGET_NONAUTH}${BPATH}" 2>/dev/null || echo 000)
        BODY=$(cat /tmp/dpcapi-nonauth-resp.txt 2>/dev/null | head -3)
        if ! echo "${BODY}" | grep -q "service rules for the path non-existent"; then
            echo "  [dpcapi.net][${STATUS}] ${BPATH}: ${BODY}"
        fi
    done
fi

echo ""
echo "[*] Phase 8 — Response header inspection on /healthz"
echo "--- Full headers for /healthz ---"
curl -sk --max-time 15 -D - \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    "https://${TARGET}/healthz" 2>/dev/null \
    | tee "${OUT}/dpcapi-healthz-headers.txt"

echo ""
echo "=== SCAN COMPLETE — ${STAMP} ==="
echo "Hits (non-GCLB responses): $(wc -l < "${OUT}/dpcapi-hits.txt" 2>/dev/null || echo 0)"
echo "Results: ${OUT}/dpcapi-hits.txt"
echo "Full log: ${LOG}"
echo ""
if [ -s "${OUT}/dpcapi-hits.txt" ]; then
    echo "=== HITS SUMMARY ==="
    cat "${OUT}/dpcapi-hits.txt"
fi
