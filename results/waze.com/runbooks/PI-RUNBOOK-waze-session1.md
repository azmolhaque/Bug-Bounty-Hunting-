#!/usr/bin/env bash
# PI-RUNBOOK-waze-session1.md
# Waze biz.waze.com + proxy/adsapi cluster — Session 1 recon
# Run from: Raspberry Pi 5
# Goal: Determine what's exposed unauthenticated on proxy.waze.com,
#       adsapi-staging.waze.com, adsapi.waze.com, and biz.waze.com
# Scope: all targets confirmed IN-SCOPE via scope-check.sh

## SETUP

```bash
cd ~/bug-bounty-hunting-
git pull origin claude/appsheet-vrp-submission-vq80t5

OUTDIR=~/bug-bounty-hunting-/results/waze.com
STAMP=$(date -u +%Y%m%d-%H%M)
EVDIR="${OUTDIR}/evidence/session1-${STAMP}"
mkdir -p "${EVDIR}"
LOG="${EVDIR}/scan.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== WAZE SESSION 1 — ${STAMP} ==="

# Scope check all targets before touching
for HOST in proxy.waze.com proxy-staging.waze.com adsapi.waze.com adsapi-staging.waze.com biz.waze.com; do
  ./scripts/scope-check.sh "${HOST}" || echo "OUT-OF-SCOPE — SKIP ${HOST}"
done
```

---

## PHASE A — `proxy.waze.com` and `proxy-staging.waze.com` [HIGHEST PRIORITY]

The "proxy" naming suggests a URL-fetching service — potential SSRF surface.

```bash
EVFILE="${EVDIR}/A-proxy-waze.txt"
echo "=== proxy.waze.com Investigation ===" | tee "$EVFILE"
echo "Date: $(date -u)" | tee -a "$EVFILE"

for HOST in proxy.waze.com proxy-staging.waze.com; do
  echo "" | tee -a "$EVFILE"
  echo "=== HOST: ${HOST} ===" | tee -a "$EVFILE"

  # Headers / response body
  echo "--- Headers ---" | tee -a "$EVFILE"
  curl -sv --connect-timeout 10 --max-time 20 "https://${HOST}/" 2>&1 \
    | head -50 | tee -a "$EVFILE"

  # Path probe
  echo "--- Path probe ---" | tee -a "$EVFILE"
  for path in /health /status /ping /api /v1 /proxy /fetch /url /render \
              /robots.txt /.well-known/security.txt /swagger /openapi.json; do
    CODE=$(curl -sko /dev/null -w "%{http_code}" \
      --connect-timeout 8 --max-time 15 \
      "https://${HOST}${path}")
    echo "${CODE}  https://${HOST}${path}" | tee -a "$EVFILE"
  done

  # Does it accept a URL parameter? Test with benign OOB
  echo "--- URL parameter test (passive OOB) ---" | tee -a "$EVFILE"
  OOB="https://$(cat /tmp/interactsh-host 2>/dev/null || echo 'omit-if-no-oob')"
  if [ "$OOB" != "https://omit-if-no-oob" ]; then
    for param in "url" "u" "target" "src" "href" "link" "proxy" "fetch" "redirect"; do
      CODE=$(curl -sko /dev/null -w "%{http_code}" \
        --connect-timeout 8 --max-time 15 \
        "https://${HOST}/?${param}=${OOB}")
      echo "${CODE}  ?${param}=<OOB>" | tee -a "$EVFILE"
    done
  else
    echo "(OOB not configured — start interactsh first if testing URL params)" | tee -a "$EVFILE"
  fi
done

echo "" | tee -a "$EVFILE"
echo "=== DECISION (proxy.waze.com) ===" | tee -a "$EVFILE"
echo "If any endpoint returns 200 with non-trivial content → investigate immediately." | tee -a "$EVFILE"
echo "If any path accepts ?url= or similar and makes outbound request → SSRF → STOP + report." | tee -a "$EVFILE"
```

---

## PHASE B — `adsapi.waze.com` and `adsapi-staging.waze.com` [HIGH PRIORITY]

Legacy Waze Ads API. Staging is higher priority (likely weaker auth).

```bash
EVFILE="${EVDIR}/B-adsapi-probe.txt"
echo "=== adsapi Cluster Probe ===" | tee "$EVFILE"
echo "Date: $(date -u)" | tee -a "$EVFILE"

for HOST in adsapi-staging.waze.com adsapi.waze.com; do
  echo "" | tee -a "$EVFILE"
  echo "=== HOST: ${HOST} ===" | tee -a "$EVFILE"

  # DNS resolution
  echo "--- DNS ---" | tee -a "$EVFILE"
  dig +short "${HOST}" | tee -a "$EVFILE"

  # Headers
  echo "--- Headers ---" | tee -a "$EVFILE"
  curl -sv --connect-timeout 10 "https://${HOST}/" 2>&1 | head -40 | tee -a "$EVFILE"

  # Path probe
  echo "--- Path probe ---" | tee -a "$EVFILE"
  for path in /health /status /api /v1 /v2 /swagger /swagger.json /swagger/index.html \
              /openapi.json /openapi /docs /api-docs /api/v1 /api/v2 \
              /robots.txt /.well-known/security.txt; do
    CODE=$(curl -sko /dev/null -w "%{http_code}" \
      --connect-timeout 8 --max-time 15 \
      "https://${HOST}${path}")
    echo "${CODE}  ${path}" | tee -a "$EVFILE"
  done

  # Error response with invalid auth — reveals framework/error format
  echo "--- Auth error format ---" | tee -a "$EVFILE"
  curl -sk --connect-timeout 10 --max-time 15 \
    -H "Authorization: Bearer invalid-token-probe" \
    -w "\nHTTP_%{http_code}" \
    "https://${HOST}/v1/accounts" | tee -a "$EVFILE"
  echo "" | tee -a "$EVFILE"
done
```

---

## PHASE C — WAM API (`ads.wazeapis.com`) [MEDIUM PRIORITY]

Newer gRPC-transcoded REST API. Check health endpoint and auth error format.

```bash
EVFILE="${EVDIR}/C-wam-api-probe.txt"
echo "=== ads.wazeapis.com WAM API Probe ===" | tee "$EVFILE"
echo "Date: $(date -u)" | tee -a "$EVFILE"

WAM="https://ads.wazeapis.com"

# Health endpoint (may be unauthenticated per GCP API patterns)
echo "--- /v1/health ---" | tee -a "$EVFILE"
curl -sk --connect-timeout 10 --max-time 15 \
  -w "\nHTTP_%{http_code}" \
  "${WAM}/v1/health" | tee -a "$EVFILE"
echo "" | tee -a "$EVFILE"

# Discovery
echo "--- /v1/ discovery ---" | tee -a "$EVFILE"
curl -sk --connect-timeout 10 --max-time 15 \
  -w "\nHTTP_%{http_code}" \
  "${WAM}/v1/" | tee -a "$EVFILE"
echo "" | tee -a "$EVFILE"

# Auth error format — reveals framework
echo "--- /v1/accounts (no auth) ---" | tee -a "$EVFILE"
curl -sk --connect-timeout 10 --max-time 15 \
  -w "\nHTTP_%{http_code}" \
  "${WAM}/v1/accounts" | tee -a "$EVFILE"
echo "" | tee -a "$EVFILE"

echo "--- /v1/accounts (bad Bearer) ---" | tee -a "$EVFILE"
curl -sk --connect-timeout 10 --max-time 15 \
  -H "Authorization: Bearer bad-token" \
  -w "\nHTTP_%{http_code}" \
  "${WAM}/v1/accounts" | tee -a "$EVFILE"
echo "" | tee -a "$EVFILE"

echo "=== DECISION (WAM API) ===" | tee -a "$EVFILE"
echo "If /v1/health returns 200 → WAM API is still live." | tee -a "$EVFILE"
echo "If no auth returns 200 on any path → high severity, stop and document." | tee -a "$EVFILE"
echo "Error format reveals framework; gRPC errors → different IDOR test approach." | tee -a "$EVFILE"
```

---

## PHASE D — `biz.waze.com` Pre-auth Surface

```bash
EVFILE="${EVDIR}/D-biz-waze-preauth.txt"
echo "=== biz.waze.com Pre-auth Surface ===" | tee "$EVFILE"
echo "Date: $(date -u)" | tee -a "$EVFILE"

for HOST in biz.waze.com biz.world.waze.com; do
  echo "" | tee -a "$EVFILE"
  echo "=== HOST: ${HOST} ===" | tee -a "$EVFILE"
  dig +short "${HOST}" | tee -a "$EVFILE"

  # Pre-auth path probe
  for path in / /app/login /app/signup /app/forgot-password /app/reset-password \
    /app/auth/refresh-token /health /api/health \
    /.well-known/openid-configuration /.well-known/security.txt \
    /robots.txt /sitemap.xml; do
    CODE=$(curl -sko /dev/null -w "%{http_code}" \
      --connect-timeout 8 --max-time 15 \
      -L "https://${HOST}${path}")
    echo "${CODE}  ${path}" | tee -a "$EVFILE"
  done

  # Full response on login page
  echo "--- Login page body (first 200 bytes) ---" | tee -a "$EVFILE"
  curl -sk --connect-timeout 10 "https://${HOST}/app/login" \
    | head -c 200 | tee -a "$EVFILE"
  echo "" | tee -a "$EVFILE"
done
```

---

## PHASE E — Decision Gate

```bash
echo "" 
echo "=== SESSION 1 DECISION GATE ==="
echo ""
echo "STOP → PURSUE if any of these are true:"
echo "  [proxy] proxy.waze.com or proxy-staging.waze.com accepts ?url= parameter → SSRF test"
echo "  [proxy] Any proxy endpoint returns 200 with meaningful content"
echo "  [adsapi-staging] Any path returns 200 unauthenticated"
echo "  [adsapi-staging] Swagger/OpenAPI schema exposed"
echo "  [WAM] /v1/health returns 200 AND /v1/accounts returns 200 without auth"
echo ""
echo "DEPRIORITIZE if:"
echo "  All proxy paths return 404/403/000"
echo "  adsapi-staging returns 000 (not live) or all 401/403"
echo "  WAM API health returns 000 or 404"
echo ""
echo "If DEPRIORITIZE: pivot to Photomath portal IDOR (TIER0, needs desktop + expert account)"
echo "  Desktop action: register at portal.photomath.net as expert → Burp IDOR test"
echo "  Target: GET /api/quiz/grade-quizzes/user/{N} with N ± 1 from observed 273638"
```

---

## NOTES

**OOB setup (if testing SSRF)**:
```bash
# Start interactsh before Phase A
interactsh-client -s oast.pro 2>/dev/null &
INTERACTSH_PID=$!
INTERACTSH_HOST=$(interactsh-client -s oast.pro -json 2>/dev/null | jq -r '.domain' | head -1)
echo "$INTERACTSH_HOST" > /tmp/interactsh-host
echo "OOB host: $INTERACTSH_HOST"
```

**Save results**:
```bash
git add results/waze.com/evidence/
git commit -m "waze: session 1 — unauthenticated surface probe results"
git push -u origin claude/appsheet-vrp-submission-vq80t5
```
