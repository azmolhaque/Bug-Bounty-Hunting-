#!/usr/bin/env bash
# Photomath deep scan — Phase 1-4
# Run: bash scripts/scan-photomath.sh
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET_NET="photomath.net"
TARGET_COM="photomath.com"
STAMP=$(date -u +%Y%m%d-%H%M)
OUT=~/bug-bounty-hunting-/results/photomath.net

mkdir -p "${OUT}/01-assets" \
         "${OUT}/02-surface/js" "${OUT}/02-surface/api" "${OUT}/02-surface/params" \
         "${OUT}/03-candidates" \
         "${OUT}/evidence/session1-${STAMP}"

LOG="${OUT}/evidence/session1-${STAMP}/scan.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== PHOTOMATH DEEP SCAN — ${STAMP} ==="
./scripts/scope-check.sh photomath.net        || { echo "SCOPE FAIL: photomath.net not in scope"; exit 1; }
./scripts/scope-check.sh portal.photomath.net || { echo "SCOPE FAIL: portal.photomath.net not in scope — run git pull to get updated scope.yaml"; exit 1; }

# ── Phase 1A: Subdomain enumeration ──────────────────────────────────────────
echo "[1A] subfinder..."
subfinder -d "${TARGET_NET}" -all -silent -rate-limit 50 -timeout 30 \
  -o "${OUT}/01-assets/subfinder-net-${STAMP}.txt"

subfinder -d "${TARGET_COM}" -all -silent -rate-limit 50 -timeout 30 \
  -o "${OUT}/01-assets/subfinder-com-${STAMP}.txt"

echo "[1A] crt.sh..."
curl -s "https://crt.sh/?q=%.${TARGET_NET}&output=json" 2>/dev/null \
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
" | sort -u > "${OUT}/01-assets/crtsh-net-${STAMP}.txt"

curl -s "https://crt.sh/?q=%.${TARGET_COM}&output=json" 2>/dev/null \
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
" | sort -u > "${OUT}/01-assets/crtsh-com-${STAMP}.txt"

# Seed list from scope.yaml
cat > "${OUT}/01-assets/scope-seed.txt" <<'SEED'
portal.photomath.net
dpcapi-admin.photomath.com
internal.photomath.com
lapi.photomath.net
tlapi.photomath.net
taportal.photomath.net
cuvar.photomath.net
dpcapi-admin.photomath.net
internal.photomath.net
dpcapi.photomath.net
mankey.photomath.net
baja.photomath.net
zuja.photomath.net
daportal.photomath.net
photomath.net
www.photomath.net
photomath.com
www.photomath.com
SEED

cat "${OUT}/01-assets/subfinder-net-${STAMP}.txt" \
    "${OUT}/01-assets/subfinder-com-${STAMP}.txt" \
    "${OUT}/01-assets/crtsh-net-${STAMP}.txt" \
    "${OUT}/01-assets/crtsh-com-${STAMP}.txt" \
    "${OUT}/01-assets/scope-seed.txt" \
  | sort -u > "${OUT}/01-assets/all-subs-${STAMP}.txt"

echo "[1A] $(wc -l < "${OUT}/01-assets/all-subs-${STAMP}.txt") unique subdomains"

# ── Phase 1B: DNS resolution ──────────────────────────────────────────────────
echo "[1B] dnsx..."
dnsx -silent -a -cname -resp -rate-limit 50 \
  -l "${OUT}/01-assets/all-subs-${STAMP}.txt" \
  -o "${OUT}/01-assets/dnsx-${STAMP}.txt"

echo "[1B] $(wc -l < "${OUT}/01-assets/dnsx-${STAMP}.txt") hosts resolve"

# ── Phase 1C: HTTP probe ──────────────────────────────────────────────────────
echo "[1C] httpx..."
httpx -silent -follow-redirects \
      -status-code -title -tech-detect -content-length \
      -rate-limit 20 -timeout 15 \
      -l "${OUT}/01-assets/dnsx-${STAMP}.txt" \
      -o "${OUT}/01-assets/httpx-${STAMP}.jsonl"

echo "[1C] Live hosts:"
python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        print(r.get('status_code',''), r.get('url',''), r.get('title',''))
    except: pass
" < "${OUT}/01-assets/httpx-${STAMP}.jsonl" | sort | tee "${OUT}/01-assets/httpx-summary-${STAMP}.txt"

# ── Phase 2A: WAF bypass on 403 cluster ──────────────────────────────────────
echo "[2A] WAF bypass..."
BYPASS_OUT="${OUT}/02-surface/waf-bypass-${STAMP}.txt"
> "${BYPASS_OUT}"

TARGETS="portal.photomath.net dpcapi-admin.photomath.com internal.photomath.com lapi.photomath.net tlapi.photomath.net taportal.photomath.net cuvar.photomath.net"

for HOST in ${TARGETS}; do
    echo "--- ${HOST} ---" | tee -a "${BYPASS_OUT}"
    for HDR in \
        "X-Forwarded-For: 127.0.0.1" \
        "X-Real-IP: 127.0.0.1" \
        "X-Originating-IP: 127.0.0.1" \
        "X-Remote-IP: 127.0.0.1" \
        "X-Client-IP: 127.0.0.1" \
        "True-Client-IP: 127.0.0.1" \
        "CF-Connecting-IP: 127.0.0.1" \
        "X-Host: 127.0.0.1"; do
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
            -H "${HDR}" "https://${HOST}/" 2>/dev/null || echo "000")
        if [ "${STATUS}" != "403" ] && [ "${STATUS}" != "000" ]; then
            echo "  [BYPASS] Header='${HDR}' -> ${STATUS}" | tee -a "${BYPASS_OUT}"
        fi
    done
    # Path bypass attempts
    for BPATH in "//" "/./" "%2f" "..;/" "/.;/" "/%2e/"; do
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
            "https://${HOST}/${BPATH}" 2>/dev/null || echo "000")
        if [ "${STATUS}" != "403" ] && [ "${STATUS}" != "000" ]; then
            echo "  [PATH BYPASS] path='${BPATH}' -> ${STATUS}" | tee -a "${BYPASS_OUT}"
        fi
    done
done

grep "BYPASS" "${BYPASS_OUT}" | head -20 || echo "[2A] No bypasses found — all still 403"

# ── Phase 2B: URL mining ──────────────────────────────────────────────────────
echo "[2B] URL mining portal.photomath.net..."
gau --threads 5 --retries 3 --timeout 30 portal.photomath.net 2>/dev/null \
  | grep -vE '\.(png|jpg|gif|svg|ico|woff|woff2|ttf|eot|css|map)$' \
  | sort -u > "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt"

echo "portal.photomath.net" | waybackurls 2>/dev/null \
  | grep photomath \
  | grep -vE '\.(png|jpg|gif|svg|ico|woff|css)$' \
  | sort -u >> "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt"

sort -u "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt" \
  -o "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt"

echo "[2B] $(wc -l < "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt") URLs mined"

echo "[2B] Interesting paths:"
grep -iE "(quiz|solve|expert|training|grade|answer|solution|admin|user|account|api|token|auth|oauth|callback)" \
  "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt" \
  | sort -u | tee "${OUT}/02-surface/interesting-portal-${STAMP}.txt" | head -40

# ── Phase 2C: JS analysis ─────────────────────────────────────────────────────
echo "[2C] JS mining..."
httpx -u "https://portal.photomath.net" \
  -path "/,/login,/home,/solve,/api/v1,/api/v2,/health,/swagger,/openapi.json,/graphql,/robots.txt,/sitemap.xml" \
  -silent -status-code -rate-limit 10 -timeout 10 \
  | tee "${OUT}/02-surface/portal-paths-${STAMP}.txt"

# Extract and download JS bundles from the login page
PORTAL_HTML=$(curl -sk --max-time 20 "https://portal.photomath.net/login" 2>/dev/null)
echo "${PORTAL_HTML}" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' \
  | grep -v "^http" | sed 's|^|https://portal.photomath.net|' \
  | sort -u > "${OUT}/02-surface/js/portal-js-urls-${STAMP}.txt"

echo "[2C] JS bundles found: $(wc -l < "${OUT}/02-surface/js/portal-js-urls-${STAMP}.txt")"

while IFS= read -r JSURL; do
    [ -z "${JSURL}" ] && continue
    echo "  Fetching: ${JSURL}"
    curl -sk --max-time 30 "${JSURL}" 2>/dev/null \
      | grep -oE '("\/api\/[^"]{3,100}"|"https?:\/\/[^"]{10,100}"|[A-Za-z_]{3,}[Kk]ey["\047= :|]+[A-Za-z0-9+/=_-]{16,})' \
      | tr -d '"' | sort -u \
      >> "${OUT}/02-surface/js/portal-js-strings-${STAMP}.txt"
done < "${OUT}/02-surface/js/portal-js-urls-${STAMP}.txt"

echo "[2C] Interesting JS strings:"
grep -iE "(key|token|secret|api|endpoint|internal|gcp|auth|password|credential|bearer)" \
  "${OUT}/02-surface/js/portal-js-strings-${STAMP}.txt" 2>/dev/null \
  | sort -u | head -30 | tee "${OUT}/02-surface/js/portal-js-interesting-${STAMP}.txt"

# ── Phase 2D: GitHub org ──────────────────────────────────────────────────────
echo "[2D] github.com/photomath public repos..."
curl -s "https://api.github.com/orgs/photomath/repos?per_page=100&type=public" 2>/dev/null \
  | python3 -c "
import sys, json
try:
    for r in json.load(sys.stdin):
        print(r['full_name'], r['updated_at'], r.get('description',''))
except: pass
" | tee "${OUT}/01-assets/github-repos-${STAMP}.txt"

echo "[2D] $(wc -l < "${OUT}/01-assets/github-repos-${STAMP}.txt") public repos"

if command -v trufflehog &>/dev/null; then
    echo "[2D] trufflehog secrets scan..."
    trufflehog github --org photomath --only-verified --json 2>/dev/null \
      | tee "${OUT}/01-assets/trufflehog-${STAMP}.jsonl"
    SECRETS=$(wc -l < "${OUT}/01-assets/trufflehog-${STAMP}.jsonl")
    [ "${SECRETS}" -gt 0 ] && echo "[!!!] ${SECRETS} SECRETS FOUND — check trufflehog output"
fi

# ── Phase 3: Nuclei ───────────────────────────────────────────────────────────
echo "[3] nuclei..."
python3 -c "
import sys, json
for line in sys.stdin:
    try: print(json.loads(line)['url'])
    except: pass
" < "${OUT}/01-assets/httpx-${STAMP}.jsonl" > /tmp/pm-targets.txt

nuclei -l /tmp/pm-targets.txt \
    -t ~/nuclei-templates/technologies/ \
    -t ~/nuclei-templates/exposures/ \
    -t ~/nuclei-templates/misconfiguration/ \
    -t ~/nuclei-templates/vulnerabilities/generic/ \
    -t ~/nuclei-templates/default-logins/ \
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

# ── Phase 4: Quiz ID probe ────────────────────────────────────────────────────
echo "[4] portal.photomath.net quiz ID probe (unauthenticated)..."
{
for N in 1 2 5 10 50 100 147 200 500 1000; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        "https://portal.photomath.net/expert-training/qualification-quiz/${N}" 2>/dev/null)
    echo "  quiz/${N} -> HTTP ${STATUS}"
done
} | tee "${OUT}/02-surface/quiz-id-probe-${STAMP}.txt"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== SCAN COMPLETE — ${STAMP} ==="
echo "Subdomains   : $(wc -l < "${OUT}/01-assets/all-subs-${STAMP}.txt")"
echo "DNS resolving: $(wc -l < "${OUT}/01-assets/dnsx-${STAMP}.txt")"
echo "Live HTTP    : $(wc -l < "${OUT}/01-assets/httpx-${STAMP}.jsonl" 2>/dev/null)"
echo "URLs mined   : $(wc -l < "${OUT}/02-surface/gau-portal-filtered-${STAMP}.txt")"
echo "Nuclei hits  : ${HITS}"
echo "Log          : ${LOG}"
echo ""
echo "NEXT STEPS:"
echo "  1. Check quiz ID probe: cat ${OUT}/02-surface/quiz-id-probe-${STAMP}.txt"
echo "  2. Check nuclei hits: cat ${OUT}/03-candidates/nuclei-${STAMP}.jsonl"
echo "  3. Register expert account at https://portal.photomath.net/login"
echo "  4. Run Burp IDOR test per runbook"
