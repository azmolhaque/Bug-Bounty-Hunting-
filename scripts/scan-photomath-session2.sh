#!/usr/bin/env bash
# Photomath Session 2 — overnight Pi scan
# Covers: new subdomains, ArgoCD auth probe, portal JS mining, dpcapi variants
# Run: bash scripts/scan-photomath-session2.sh
set -uo pipefail

cd "$(dirname "$0")/.."

STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/photomath.net/evidence/session2-${STAMP}
mkdir -p "${OUT}"

LOG="${OUT}/session2-scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== PHOTOMATH SESSION 2 SCAN — ${STAMP} ==="

# ── Phase A: ArgoCD dwh-eu-dev auth probe ──────────────────────────────────
echo ""
echo "[A] argocd-dwh-eu-dev.photomath.net auth probe..."
./scripts/scope-check.sh argocd-dwh-eu-dev.photomath.net || true

ARGOCD="argocd-dwh-eu-dev.photomath.net"

echo "[A] Response headers..."
curl -sk --max-time 15 -D - -o /dev/null \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
    "https://${ARGOCD}/" 2>/dev/null \
    | tee "${OUT}/argocd-headers.txt" || echo "[A] connection failed"

# ArgoCD-specific endpoints — unauthenticated in some versions
echo "[A] ArgoCD API probes..."
for BPATH in \
    /healthz /readyz \
    /api/version \
    /api/v1/settings \
    /api/v1/clusters \
    /api/v1/applications \
    /auth/login \
    /auth/callback \
    /metrics \
    /robots.txt; do
    for HDR in \
        "" \
        "X-Forwarded-For: 127.0.0.1" \
        "X-Real-IP: 10.0.0.1"; do
        if [ -z "${HDR}" ]; then
            RESP=$(curl -sk --max-time 10 -w "\n__CODE__%{http_code}" \
                -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
                "https://${ARGOCD}${BPATH}" 2>/dev/null)
        else
            RESP=$(curl -sk --max-time 10 -w "\n__CODE__%{http_code}" \
                -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
                -H "${HDR}" \
                "https://${ARGOCD}${BPATH}" 2>/dev/null)
        fi
        CODE="${RESP##*__CODE__}"
        BODY="${RESP%__CODE__*}"
        # Print anything that isn't 403 or 000
        if [ "${CODE}" != "403" ] && [ "${CODE}" != "000" ]; then
            HDR_LABEL="${HDR:-no-bypass}"
            echo "  [${CODE}] ${BPATH} (${HDR_LABEL})"
            echo "${BODY}" | head -3
            echo "${BODY}" | head -5 >> "${OUT}/argocd-hits.txt"
        fi
    done
done

echo "[A] ArgoCD /auth/login full response..."
curl -sk --max-time 15 -L \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
    "https://${ARGOCD}/auth/login" 2>/dev/null \
    | head -100 | tee "${OUT}/argocd-login.html" || echo "[A] /auth/login failed"

echo "[A] ArgoCD JS bundle secrets check..."
curl -sk --max-time 15 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
    "https://${ARGOCD}/" 2>/dev/null \
    | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' \
    | grep -v "^http" | sed "s|^|https://${ARGOCD}|" \
    | sort -u > /tmp/argocd-js-urls.txt

echo "[A] JS bundles found: $(wc -l < /tmp/argocd-js-urls.txt)"
while IFS= read -r JSURL; do
    [ -z "${JSURL}" ] && continue
    curl -sk --max-time 30 "${JSURL}" 2>/dev/null \
        | grep -oE '(clientId|client_id|issuer|oidcConfig|dex|password|token|secret|apiKey|oidc)["\047= :]+[A-Za-z0-9._\-]{8,}' \
        | sort -u
done < /tmp/argocd-js-urls.txt | tee "${OUT}/argocd-js-secrets.txt"

# ── Phase B: New subdomains — idp, glooker, cms ──────────────────────────────
echo ""
echo "[B] New subdomain probes..."

for HOST in idp.photomath.net glooker.photomath.net cms.photomath.net; do
    echo ""
    echo "[B] === ${HOST} ==="
    ./scripts/scope-check.sh "${HOST}" 2>/dev/null | grep -q IN-SCOPE || { echo "  SKIP: out of scope"; continue; }

    echo "[B] Headers..."
    curl -sk --max-time 15 -D - -o "${OUT}/${HOST}-body.html" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
        "https://${HOST}/" 2>/dev/null \
        | head -30 | tee "${OUT}/${HOST}-headers.txt" \
        || echo "  [B] connection failed"

    echo "[B] Follow redirects..."
    FINAL=$(curl -sk --max-time 15 -L -o /dev/null -w "%{url_effective} -> HTTP %{http_code}" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
        "https://${HOST}/" 2>/dev/null || echo "failed")
    echo "  Final URL: ${FINAL}"

    echo "[B] Response body preview..."
    head -50 "${OUT}/${HOST}-body.html" 2>/dev/null || echo "  (empty)"
done

# glooker specifically — probe Looker API paths
echo ""
echo "[B] Looker API probe on glooker.photomath.net..."
GLOOKER="glooker.photomath.net"
if ./scripts/scope-check.sh "${GLOOKER}" 2>/dev/null | grep -q IN-SCOPE; then
    for BPATH in \
        /api/4.0/user \
        /api/4.0/users \
        /api/4.0/content/search \
        /api/4.0/look/1 \
        /api/4.0/dashboard/1 \
        /api/4.0/connections \
        /api/3.1/user \
        /api/3.1/connections \
        /login \
        /swagger.json \
        /api/swagger.json \
        /healthz /health; do
        STATUS=$(curl -sk --max-time 10 -o /tmp/glooker-resp.txt -w "%{http_code}" \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
            "https://${GLOOKER}${BPATH}" 2>/dev/null || echo 000)
        BODY=$(cat /tmp/glooker-resp.txt 2>/dev/null | head -3)
        if [ "${STATUS}" != "000" ] && [ "${STATUS}" != "404" ]; then
            echo "  [${STATUS}] ${BPATH}: ${BODY}"
        fi
    done | tee "${OUT}/glooker-hits.txt"
fi

# ── Phase C: lapi / tlapi / taportal / cuvar — deeper probe with bypass ──────
echo ""
echo "[C] Secondary API subdomains deeper probe..."
for HOST in lapi.photomath.net tlapi.photomath.net taportal.photomath.net; do
    ./scripts/scope-check.sh "${HOST}" 2>/dev/null | grep -q IN-SCOPE || continue
    echo "[C] === ${HOST} ==="
    for BPATH in / /healthz /health /readyz /api /api/v1 /api/v2 /version /status \
                 /swagger /openapi.json /graphql /login /auth; do
        STATUS=$(curl -sk --max-time 10 -o /tmp/lapi-resp.txt -w "%{http_code}" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -H "X-Real-IP: 127.0.0.1" \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
            "https://${HOST}${BPATH}" 2>/dev/null || echo 000)
        BODY=$(cat /tmp/lapi-resp.txt 2>/dev/null | head -2)
        [ "${STATUS}" != "403" ] && [ "${STATUS}" != "000" ] && \
            echo "  [${STATUS}] ${BPATH}: ${BODY}"
    done | tee "${OUT}/${HOST}-hits.txt"
done

# ── Phase D: portal.photomath.net JS mining via User-Agent spoof ─────────────
echo ""
echo "[D] portal.photomath.net JS mining (with browser User-Agent)..."
./scripts/scope-check.sh portal.photomath.net || true

PORTAL_HTML=$(curl -sk --max-time 20 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    "https://portal.photomath.net/login" 2>/dev/null)

if [ -n "${PORTAL_HTML}" ] && ! echo "${PORTAL_HTML}" | grep -q "ERR_EMPTY"; then
    echo "[D] Portal login page fetched — mining JS..."
    echo "${PORTAL_HTML}" | head -50 | tee "${OUT}/portal-login-preview.html"
    echo "${PORTAL_HTML}" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' \
        | grep -v "^http" | sed 's|^|https://portal.photomath.net|' \
        | sort -u > "${OUT}/portal-js-urls.txt"
    echo "[D] JS bundles: $(wc -l < "${OUT}/portal-js-urls.txt")"
    while IFS= read -r JSURL; do
        [ -z "${JSURL}" ] && continue
        curl -sk --max-time 30 \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
            "${JSURL}" 2>/dev/null \
            | grep -oE '("\/api\/[^"]{3,100}"|[A-Za-z_]{3,}[Kk]ey["\047= :|]+[A-Za-z0-9+/=_-]{16,})' \
            | tr -d '"' | sort -u
    done < "${OUT}/portal-js-urls.txt" | tee "${OUT}/portal-js-strings.txt"
    echo "[D] Interesting strings:"
    grep -iE "(key|token|secret|api|endpoint|internal|gcp|auth|client_id|oauth)" \
        "${OUT}/portal-js-strings.txt" 2>/dev/null | sort -u | head -30
else
    echo "[D] Portal still blocking Pi (ERR_EMPTY from curl too)"
fi

# ── Phase E: GitHub org scan ──────────────────────────────────────────────────
echo ""
echo "[E] github.com/photomath public repos..."
curl -s --max-time 30 \
    "https://api.github.com/orgs/photomath/repos?per_page=100&type=public" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    repos = json.load(sys.stdin)
    for r in repos:
        print(r['full_name'], r['updated_at'], r.get('description','')[:60])
except Exception as e:
    print('Error:', e)
" | tee "${OUT}/github-repos.txt"
echo "[E] $(wc -l < "${OUT}/github-repos.txt") public repos"

if command -v trufflehog &>/dev/null; then
    echo "[E] trufflehog scan..."
    trufflehog github --org photomath --only-verified --json 2>/dev/null \
        | tee "${OUT}/trufflehog.jsonl"
    SECRETS=$(wc -l < "${OUT}/trufflehog.jsonl" 2>/dev/null || echo 0)
    [ "${SECRETS}" -gt 0 ] && echo "[!!!] ${SECRETS} VERIFIED SECRETS FOUND"
else
    echo "[E] trufflehog not installed — skipping"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== SESSION 2 SCAN COMPLETE — ${STAMP} ==="
echo "ArgoCD hits    : $(wc -l < "${OUT}/argocd-hits.txt" 2>/dev/null || echo 0)"
echo "ArgoCD JS      : $(wc -l < "${OUT}/argocd-js-secrets.txt" 2>/dev/null || echo 0) strings"
echo "glooker hits   : $(wc -l < "${OUT}/glooker-hits.txt" 2>/dev/null || echo 0)"
echo "Portal JS      : $(wc -l < "${OUT}/portal-js-strings.txt" 2>/dev/null || echo 0) strings"
echo "GitHub repos   : $(wc -l < "${OUT}/github-repos.txt" 2>/dev/null || echo 0)"
echo "Log            : ${LOG}"
echo ""
echo "NEXT: git add results/photomath.net/evidence/session2-${STAMP}/ && git push"
