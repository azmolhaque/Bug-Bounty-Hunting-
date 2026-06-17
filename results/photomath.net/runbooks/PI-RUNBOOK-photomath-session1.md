# Photomath Pi Runbook — Session 1

**Target:** photomath.net / photomath.com (TIER0, Google VRP)  
**Scope:** All confirmed IN-SCOPE via scope-check.sh  
**Primary surface:** portal.photomath.net (expert marketplace, GCP, prior XSS disclosed)  
**Created:** 2026-06-16

---

## Phase 0 — Scope & Setup

```bash
cd ~/bug-bounty-hunting-
./scripts/scope-check.sh portal.photomath.net   # IN-SCOPE
./scripts/scope-check.sh dpcapi-admin.photomath.com   # IN-SCOPE
./scripts/scope-check.sh lapi.photomath.net   # IN-SCOPE (photomath.net wildcard)

OUTDIR=~/bug-bounty-hunting-/results/photomath.net
STAMP=$(date -u +%Y%m%d-%H%M)
```

---

## Phase 1 — Asset Discovery (30 min)

```bash
# Full subdomain enumeration
subfinder -d photomath.net -all -silent -rate-limit 50 \
  -o "${OUTDIR}/01-assets/subfinder-net-${STAMP}.txt"

subfinder -d photomath.com -all -silent -rate-limit 50 \
  -o "${OUTDIR}/01-assets/subfinder-com-${STAMP}.txt"

# Also check official GitHub org
curl -s "https://api.github.com/orgs/photomath/repos?per_page=100&type=public" \
  | python3 -c "import sys,json; [print(r['full_name'],r['updated_at']) for r in json.load(sys.stdin)]" \
  | tee "${OUTDIR}/01-assets/github-public-repos-${STAMP}.txt"

# crt.sh certificate transparency (finds subdomains not in subfinder)
curl -s "https://crt.sh/?q=%.photomath.net&output=json" \
  | python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" \
  | sort -u | tee "${OUTDIR}/01-assets/crtsh-net-${STAMP}.txt"

curl -s "https://crt.sh/?q=%.photomath.com&output=json" \
  | python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" \
  | sort -u | tee "${OUTDIR}/01-assets/crtsh-com-${STAMP}.txt"

# DNS + HTTP probe all discovered subdomains
cat "${OUTDIR}/01-assets/subfinder-net-${STAMP}.txt" \
    "${OUTDIR}/01-assets/subfinder-com-${STAMP}.txt" \
    "${OUTDIR}/01-assets/crtsh-net-${STAMP}.txt" \
    "${OUTDIR}/01-assets/crtsh-com-${STAMP}.txt" | sort -u \
  | dnsx -silent -a -resp -rate-limit 50 \
  | tee "${OUTDIR}/01-assets/dnsx-${STAMP}.txt"

cat "${OUTDIR}/01-assets/dnsx-${STAMP}.txt" | \
  httpx -status-code -title -tech-detect -follow-redirects \
        -rate-limit 20 -timeout 10 \
        -o "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl"

# Live hosts summary
jq -r '[.url,.status_code,.title,.tech[]] | @tsv' \
  "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl" | sort -k2 -n
```

### GitHub org secrets scan
```bash
# Scan official Photomath GitHub org for leaked secrets
trufflehog github --org photomath --only-verified 2>&1 \
  | tee "${OUTDIR}/01-assets/trufflehog-${STAMP}.txt"

# Fallback: gitleaks on each public repo
while read repo; do
  git clone --depth=1 "https://github.com/${repo}" /tmp/pm-repo 2>/dev/null
  gitleaks detect --source=/tmp/pm-repo --no-git 2>&1 | grep -v "^INF"
  rm -rf /tmp/pm-repo
done < <(cut -d' ' -f1 "${OUTDIR}/01-assets/github-public-repos-${STAMP}.txt")
```

---

## Phase 2 — Portal Attack Surface Mapping (30 min)

portal.photomath.net is the primary surface — an expert marketplace with integer-ID quiz system.

```bash
# URL mining — portal specifically
gau --threads 5 portal.photomath.net \
  | tee "${OUTDIR}/02-surface/gau-portal-${STAMP}.txt" \
  | grep -vE '\.(png|jpg|gif|svg|ico|css|woff)$'

# Spider with waybackurls
echo "portal.photomath.net" | waybackurls \
  | grep photomath \
  | tee "${OUTDIR}/02-surface/wayback-portal-${STAMP}.txt"

# HTTP probe all portal paths
httpx -u "https://portal.photomath.net" \
  -path "/,/login,/signup,/register,/home,/dashboard,/admin,/solve,/api,/api/v1,/api/v2,/health,/actuator,/actuator/health,/swagger,/swagger-ui.html,/openapi.json,/api-docs,/metrics,/debug,/graphql" \
  -status-code -title -rate-limit 10 -timeout 10 \
  | tee "${OUTDIR}/02-surface/portal-paths-${STAMP}.txt"

# Also probe with WAF bypass headers (for the 403 cluster)
for host in dpcapi-admin.photomath.com internal.photomath.com lapi.photomath.net tlapi.photomath.net; do
  echo "=== Testing ${host} ==="
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    -H "X-Originating-IP: 127.0.0.1" \
    -H "X-Remote-IP: 127.0.0.1" \
    "https://${host}/"
  
  # Try common API paths
  for path in /health /api /api/v1 /actuator/health /swagger /v1 /status; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${host}${path}")
    [ "$STATUS" != "403" ] && echo "  INTERESTING: ${path} → ${STATUS}"
  done
done | tee "${OUTDIR}/02-surface/403-bypass-${STAMP}.txt"
```

---

## Phase 3A — IDOR: portal.photomath.net Quiz IDs (PRIMARY MANUAL TEST)

**Requires: Burp Suite + two expert accounts on portal.photomath.net**

### Step 1 — Account creation
```
1. Go to: https://portal.photomath.net/login
2. Register expert Account A (your primary test account)
3. Register expert Account B (your secondary test account — separate email)
4. Navigate through onboarding to reach the qualification quiz
5. Note your quiz ID: https://portal.photomath.net/expert-training/qualification-quiz/N
```

### Step 2 — IDOR enumeration (Burp Intruder)
```
Target: /expert-training/qualification-quiz/§N§
Range: N-10 to N+100 (and try low integers 1, 2, 3, ...)
Compare: does N±1 return another expert's quiz content?

Document for each:
- Your own quiz ID (N)
- IDs accessible to your account
- IDs that return data belonging to other experts (IDOR confirmed)
- IDs that return 403/404 (expected — those are other users' protected data)
```

### Step 3 — Capture and replay API calls
```
With Burp Suite proxying portal.photomath.net:
1. Log in as Account A, complete actions (view solutions, submit answers, view profile)
2. Capture all API calls and note resource IDs (solution_id, user_id, quiz_id, case_id, assignment_id)
3. Log in as Account B, replay Account A's API calls using Account B's session token
4. Check: does Account B's session return Account A's data?

Key API endpoints to test:
  GET /api/v*/users/{user_id}        — user profile IDOR
  GET /api/v*/solutions/{id}          — solution content IDOR
  GET /api/v*/quizzes/{id}            — quiz answers IDOR
  GET /api/v*/assignments/{id}        — assignment IDOR
  GET /api/v*/earnings/{user_id}      — financial data IDOR
```

### Step 4 — Vertical privilege escalation
```
As a normal expert, try to access admin/grader functionality:
  GET /admin/...
  GET /api/v*/admin/...
  GET /api/v*/grades/...
  GET /api/v*/review/...
  POST /api/v*/approve/... or /reject/...
```

---

## Phase 3B — Authentication Testing on portal.photomath.net

```bash
# Enumerate API structure before auth
curl -sk "https://portal.photomath.net/" | head -50  # Check response headers

# Test Google OAuth flow
# Open browser → https://portal.photomath.net/login
# Click "Sign in with Google"
# Note: client_id, redirect_uri parameters in OAuth URL
# Check: is redirect_uri strictly validated?
# Try: add &redirect_uri=https://attacker.example.com/callback → does it redirect?

# API endpoint discovery (no auth)
for path in /api /api/v1 /api/v2 /api/v3 /graphql /healthz /health /version /swagger /openapi.json; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://portal.photomath.net${path}")
  echo "${STATUS}: ${path}"
done
```

---

## Phase 3C — SSRF Test (if URL fields found in portal)

If the portal has any feature that fetches a URL server-side (image upload by URL, profile picture URL, webhook config, API endpoint config), test SSRF:

```bash
# Setup OOB listener first
interactsh-client -server oast.pro -v 2>&1 | tee ~/photomath-oob-${STAMP}.log &
L1=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/photomath-oob-${STAMP}.log | head -1)
echo "OOB: https://${L1}"

# Submit OOB URL to any URL-accepting field in the portal
# If GCP-origin hit arrives → SSRF confirmed → STOP (do not redirect to IMDS)
```

---

## Phase 4 — Automated Scan

```bash
# Nuclei on all live hosts
jq -r '.url' "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl" \
  | nuclei -t ~/nuclei-templates/technologies/ \
           -t ~/nuclei-templates/exposures/ \
           -t ~/nuclei-templates/misconfiguration/ \
           -t ~/nuclei-templates/vulnerabilities/ \
           -rate-limit 10 -timeout 10 -bulk-size 5 \
           -o "${OUTDIR}/03-candidates/nuclei-${STAMP}.jsonl" -jsonl

jq -r '[.info.severity,.info.name,.matched_at] | @tsv' \
  "${OUTDIR}/03-candidates/nuclei-${STAMP}.jsonl" | sort
```

---

## Evidence Schema

```
results/photomath.net/evidence/session1-YYYYMMDD/
  burp-portal-api-calls.xml       # Burp Suite export of captured API calls
  idor-quiz-probe.txt             # Intruder results for quiz ID enumeration
  idor-api-calls.txt              # Cross-account API replay results
  403-bypass-results.txt          # Header bypass test results
  oob_L1_<date>.log               # OOB listener (SSRF tests)
  github-secrets.txt              # trufflehog/gitleaks output
```

---

## Decision Matrix

| Result | Action |
|--------|--------|
| Quiz ID N±1 returns another expert's data | F001 — IDOR → High/Critical |
| Account A session works with Account B's API calls | F001 — broken object-level auth → High |
| Admin endpoint accessible to expert account | F001 — vertical privesc → High/Critical |
| Google OAuth redirect_uri not validated | F001 — OAuth hijack → Critical |
| Any server-side URL fetch (SSRF) from GCP | F002 — SSRF → High |
| GitHub secret found (API key, token) | F001 — secret exposure → High |
| WAF bypass reveals admin login page | Investigate further → auth bypass candidate |
| Only 403 / no data accessible | Log; pivot to chronicle.security |
