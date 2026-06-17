#!/usr/bin/env bash
# Chronicle.security — Phase 1-2 Pi scan (passive + unauthenticated)
# Phase 3 (SSRF, IDOR) requires a free Google SecOps trial account — run manually
# Run: bash scripts/scan-chronicle.sh
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET="chronicle.security"
TARGET2="siemplify-soar.com"
TARGET3="siemplify.co"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/chronicle.security
mkdir -p "${OUT}/01-assets" "${OUT}/02-surface" "${OUT}/03-candidates" \
         "${OUT}/evidence/session1-${STAMP}"

LOG="${OUT}/evidence/session1-${STAMP}/scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== CHRONICLE.SECURITY SCAN — ${STAMP} ==="

./scripts/scope-check.sh "${TARGET}" || { echo "SCOPE FAIL: ${TARGET}"; exit 1; }
./scripts/scope-check.sh "${TARGET2}" || echo "WARN: ${TARGET2} not in scope — check scope.yaml"
./scripts/scope-check.sh "${TARGET3}" || echo "WARN: ${TARGET3} not in scope — check scope.yaml"

# ── Phase 1A: Subdomain enumeration ──────────────────────────────────────────
echo ""
echo "[1A] subfinder on ${TARGET}..."
subfinder -d "${TARGET}" -all -silent -timeout 30 -rate-limit 50 \
  -o "${OUT}/01-assets/subfinder-chronicle-${STAMP}.txt" 2>/dev/null
echo "[1A] ${TARGET}: $(wc -l < "${OUT}/01-assets/subfinder-chronicle-${STAMP}.txt") subs"

echo "[1A] subfinder on ${TARGET2}..."
subfinder -d "${TARGET2}" -all -silent -timeout 30 -rate-limit 50 \
  -o "${OUT}/01-assets/subfinder-siemplify-soar-${STAMP}.txt" 2>/dev/null
echo "[1A] ${TARGET2}: $(wc -l < "${OUT}/01-assets/subfinder-siemplify-soar-${STAMP}.txt") subs"

echo "[1A] subfinder on ${TARGET3}..."
subfinder -d "${TARGET3}" -all -silent -timeout 30 -rate-limit 50 \
  -o "${OUT}/01-assets/subfinder-siemplify-co-${STAMP}.txt" 2>/dev/null
echo "[1A] ${TARGET3}: $(wc -l < "${OUT}/01-assets/subfinder-siemplify-co-${STAMP}.txt") subs"

echo "[1A] crt.sh..."
for DOMAIN in "${TARGET}" "${TARGET2}" "${TARGET3}"; do
    curl -s --max-time 30 "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null \
      | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for e in data:
        for n in e['name_value'].split():
            if not n.startswith('*') and n not in seen:
                seen.add(n)
                print(n)
except: pass
" | sort -u >> "${OUT}/01-assets/crtsh-all-${STAMP}.txt"
done
echo "[1A] crt.sh: $(wc -l < "${OUT}/01-assets/crtsh-all-${STAMP}.txt") entries"

# Merge all discovered subdomains
cat "${OUT}/01-assets/subfinder-chronicle-${STAMP}.txt" \
    "${OUT}/01-assets/subfinder-siemplify-soar-${STAMP}.txt" \
    "${OUT}/01-assets/subfinder-siemplify-co-${STAMP}.txt" \
    "${OUT}/01-assets/crtsh-all-${STAMP}.txt" \
  | sort -u > "${OUT}/01-assets/all-subs-${STAMP}.txt"

# Add known seeds
cat >> "${OUT}/01-assets/all-subs-${STAMP}.txt" <<'SEED'
chronicle.security
backstory.chronicle.security
secops.chronicle.security
siemplify-soar.com
siemplify.co
passbolt.siemplify.co
iafwsjwcmh.com
backstory.googleapis.com
secops.googleapis.com
malachiteingestion-pa.googleapis.com
SEED
sort -u "${OUT}/01-assets/all-subs-${STAMP}.txt" -o "${OUT}/01-assets/all-subs-${STAMP}.txt"
echo "[1A] Total unique: $(wc -l < "${OUT}/01-assets/all-subs-${STAMP}.txt") entries"

# ── Phase 1B: DNS resolution ──────────────────────────────────────────────────
echo ""
echo "[1B] dnsx..."
dnsx -silent -a -cname -resp -rate-limit 50 \
  -l "${OUT}/01-assets/all-subs-${STAMP}.txt" \
  -o "${OUT}/01-assets/dnsx-${STAMP}.txt" 2>/dev/null
echo "[1B] $(wc -l < "${OUT}/01-assets/dnsx-${STAMP}.txt") hosts resolve"

# ── Phase 1C: HTTP probe ──────────────────────────────────────────────────────
echo ""
echo "[1C] httpx..."
httpx -silent -follow-redirects \
      -status-code -title -tech-detect -content-length \
      -rate-limit 20 -timeout 15 \
      -l "${OUT}/01-assets/dnsx-${STAMP}.txt" \
      -o "${OUT}/01-assets/httpx-${STAMP}.jsonl" 2>/dev/null

echo "[1C] Live hosts:"
python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        print(r.get('status_code','?'), r.get('url',''), r.get('title',''))
    except: pass
" < "${OUT}/01-assets/httpx-${STAMP}.jsonl" | sort | tee "${OUT}/01-assets/httpx-summary-${STAMP}.txt"

# ── Phase 1D: Manual probes of key endpoints ──────────────────────────────────
echo ""
echo "[1D] Key endpoint probes..."

echo "--- chronicle.security ---"
for BPATH in / /login /auth /api /docs /swagger /health /healthz; do
    STATUS=$(curl -sk --max-time 10 -o /tmp/chron-resp.txt -w "%{http_code}" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
        -L "https://chronicle.security${BPATH}" 2>/dev/null || echo 000)
    BODY=$(head -3 /tmp/chron-resp.txt 2>/dev/null)
    echo "  [${STATUS}] ${BPATH}: ${BODY}"
done | tee "${OUT}/evidence/session1-${STAMP}/chronicle-paths.txt"

echo "--- siemplify-soar.com tenant patterns ---"
# Legacy Siemplify SOAR is typically at {tenantname}.siemplify-soar.com
# Known: 'demo', 'app', 'trial', 'community' tenants sometimes exist
for TENANT in demo app trial community test staging dev; do
    STATUS=$(curl -sk --max-time 10 -o /tmp/soar-resp.txt -w "%{http_code}" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
        -L "https://${TENANT}.siemplify-soar.com/" 2>/dev/null || echo 000)
    TITLE=$(grep -oP '(?<=<title>)[^<]+' /tmp/soar-resp.txt 2>/dev/null | head -1)
    [ "${STATUS}" != "000" ] && echo "  [${STATUS}] ${TENANT}.siemplify-soar.com — ${TITLE}"
done | tee "${OUT}/evidence/session1-${STAMP}/siemplify-tenants.txt"

echo "--- siemplify-soar.com Swagger probe (common paths) ---"
for BPATH in \
    /swagger/index.html \
    /swagger/v1/swagger.json \
    /api-docs \
    /api/swagger \
    /external/v1/cases \
    /api/v1/cases \
    /login \
    /auth/login \
    /healthz /health; do
    STATUS=$(curl -sk --max-time 10 -o /tmp/soar-resp.txt -w "%{http_code}" \
        "https://siemplify-soar.com${BPATH}" 2>/dev/null || echo 000)
    [ "${STATUS}" != "000" ] && [ "${STATUS}" != "404" ] && \
        echo "  [${STATUS}] siemplify-soar.com${BPATH}"
done | tee "${OUT}/evidence/session1-${STAMP}/siemplify-soar-paths.txt"

echo "--- backstory.googleapis.com ---"
for BPATH in / /v1 /v2 /v1/partners /v2/detect/rules /v1/feeds /swagger; do
    STATUS=$(curl -sk --max-time 10 -o /tmp/bstory-resp.txt -w "%{http_code}" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36" \
        "https://backstory.googleapis.com${BPATH}" 2>/dev/null || echo 000)
    BODY=$(head -2 /tmp/bstory-resp.txt 2>/dev/null)
    [ "${STATUS}" != "000" ] && echo "  [${STATUS}] backstory.googleapis.com${BPATH}: ${BODY}"
done | tee "${OUT}/evidence/session1-${STAMP}/backstory-paths.txt"

echo "--- iafwsjwcmh.com (Chronicle legacy domain) ---"
STATUS=$(curl -sk --max-time 10 -L -o /tmp/iaf-resp.txt -w "%{url_effective} HTTP %{http_code}" \
    "https://iafwsjwcmh.com/" 2>/dev/null || echo "000")
echo "  ${STATUS}"
head -20 /tmp/iaf-resp.txt

# ── Phase 2: URL mining ───────────────────────────────────────────────────────
echo ""
echo "[2] URL mining..."
gau --threads 5 --retries 3 --timeout 30 "${TARGET}" 2>/dev/null \
  | grep -vE '\.(png|jpg|gif|svg|ico|woff|woff2|ttf|eot|css|map)$' \
  | sort -u > "${OUT}/02-surface/gau-chronicle-${STAMP}.txt"

echo "chronicle.security" | waybackurls 2>/dev/null \
  | grep -vE '\.(png|jpg|gif|svg|ico|css|woff)$' \
  | sort -u >> "${OUT}/02-surface/gau-chronicle-${STAMP}.txt"

echo "siemplify-soar.com" | waybackurls 2>/dev/null \
  | grep -vE '\.(png|jpg|gif|svg|ico|css|woff)$' \
  | sort -u >> "${OUT}/02-surface/gau-chronicle-${STAMP}.txt"

sort -u "${OUT}/02-surface/gau-chronicle-${STAMP}.txt" \
  -o "${OUT}/02-surface/gau-chronicle-${STAMP}.txt"

echo "[2] $(wc -l < "${OUT}/02-surface/gau-chronicle-${STAMP}.txt") URLs mined"

echo "[2] SSRF-relevant patterns:"
grep -iE "(feed|ingest|webhook|playbook|connector|integrat|fetch|url|uri|import|export|source|upload|callback|redirect|proxy)" \
  "${OUT}/02-surface/gau-chronicle-${STAMP}.txt" \
  | sort -u | head -50 | tee "${OUT}/02-surface/interesting-chronicle-${STAMP}.txt"

# ── Phase 3: Nuclei on live hosts ────────────────────────────────────────────
if [ -s "${OUT}/01-assets/httpx-${STAMP}.jsonl" ]; then
    echo ""
    echo "[3] nuclei..."
    python3 -c "
import sys, json
for line in sys.stdin:
    try: print(json.loads(line)['url'])
    except: pass
" < "${OUT}/01-assets/httpx-${STAMP}.jsonl" > /tmp/chron-targets.txt

    nuclei -l /tmp/chron-targets.txt \
        -t ~/nuclei-templates/technologies/ \
        -t ~/nuclei-templates/exposures/ \
        -t ~/nuclei-templates/misconfiguration/ \
        -rate-limit 10 -timeout 10 -bulk-size 5 \
        -o "${OUT}/03-candidates/nuclei-${STAMP}.jsonl" -jsonl 2>/dev/null || true

    HITS=$(wc -l < "${OUT}/03-candidates/nuclei-${STAMP}.jsonl" 2>/dev/null || echo 0)
    echo "[3] nuclei: ${HITS} findings"
    if [ "${HITS}" -gt 0 ]; then
        python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        print(r['info']['severity'], r['info']['name'], r['matched-at'])
    except: pass
" < "${OUT}/03-candidates/nuclei-${STAMP}.jsonl" | sort
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== SCAN COMPLETE — ${STAMP} ==="
echo "Subdomains    : $(wc -l < "${OUT}/01-assets/all-subs-${STAMP}.txt")"
echo "DNS resolving : $(wc -l < "${OUT}/01-assets/dnsx-${STAMP}.txt")"
echo "Live HTTP     : $(wc -l < "${OUT}/01-assets/httpx-${STAMP}.jsonl" 2>/dev/null || echo 0)"
echo "URLs mined    : $(wc -l < "${OUT}/02-surface/gau-chronicle-${STAMP}.txt")"
echo "Log           : ${LOG}"
echo ""
echo "NEXT STEPS:"
echo "  1. Review: ${OUT}/01-assets/httpx-summary-${STAMP}.txt"
echo "  2. Review SSRF patterns: ${OUT}/02-surface/interesting-chronicle-${STAMP}.txt"
echo "  3. Sign up for free Google SecOps trial → run SSRF test (Phase 3 in runbook)"
echo "  4. git add ${OUT}/evidence/session1-${STAMP}/ && git push"
