# Chronicle.security Recon Runbook — Session 1

**Target:** chronicle.security (Google Security Operations — former Siemplify SOAR)
**Scope status:** IN-SCOPE (matches `chronicle.security` in config/scope.yaml)
**Program:** Google VRP / bughunters.google.com — TIER0 (Google-acquired, cloud SaaS)
**Created:** 2026-06-16

---

## Objective

Map chronicle.security attack surface with emphasis on:
1. SOAR connector / integration URL fields (SSRF pattern identical to AppSheet T1/T2)
2. Playbook/automation webhook destinations (SSRF, same pattern)
3. Threat-intel / URL-enrichment fetching (SSRF via submitted IOC URL)
4. Multi-tenant isolation (IDOR pattern — can tenant A access tenant B's data?)
5. Authentication and session management (OAuth, SAML SSO)

---

## Phase 0 — Scope Check (always run first)

```bash
cd ~/bug-bounty-hunting-
./scripts/scope-check.sh chronicle.security   # must print IN-SCOPE
./scripts/scope-check.sh securityoperations.google.com   # OUT-OF-SCOPE (google.com main program)
./scripts/scope-check.sh backstory.googleapis.com         # check if IN-SCOPE
./scripts/scope-check.sh secops.googleapis.com            # check if IN-SCOPE
```

---

## Phase 1 — Asset Discovery (~20 min)

```bash
TARGET="chronicle.security"
STAMP=$(date -u +%Y%m%d-%H%M)
OUTDIR=~/bug-bounty-hunting-/results/${TARGET}

# Subdomain enumeration
subfinder -d "${TARGET}" -all -silent -o "${OUTDIR}/01-assets/subfinder-${STAMP}.txt" \
  -timeout 30 -rate-limit 50

# Add backstory.googleapis.com scope if confirmed
subfinder -d "backstory.googleapis.com" -all -silent \
  -o "${OUTDIR}/01-assets/subfinder-backstory-${STAMP}.txt" 2>/dev/null

# DNS resolution — only A/CNAME records, filter live
cat "${OUTDIR}/01-assets/subfinder-${STAMP}.txt" | \
  dnsx -resp -a -cname -silent -rate-limit 50 \
  -o "${OUTDIR}/01-assets/dnsx-${STAMP}.txt"

# HTTP probe — identify live web services
cat "${OUTDIR}/01-assets/dnsx-${STAMP}.txt" | \
  httpx -status-code -title -tech-detect -follow-redirects \
        -rate-limit 20 -timeout 10 \
        -o "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl"

echo "=== LIVE HOSTS ==="
cat "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl" | \
  python3 -c "import sys,json; [print(r['url'],r['status_code'],r.get('title','')) for r in (json.loads(l) for l in sys.stdin) if r['status_code'] not in [0,400,404,502,503]]"
```

---

## Phase 2 — Attack Surface Mapping (~30 min)

```bash
# URL mining (Wayback + Common Crawl + gau)
gau --threads 5 --retries 3 --timeout 30 "${TARGET}" \
  | tee "${OUTDIR}/02-surface/gau-raw-${STAMP}.txt" \
  | grep -vE '\.(png|jpg|gif|svg|ico|woff|woff2|ttf|eot|css|map)$' \
  > "${OUTDIR}/02-surface/gau-filtered-${STAMP}.txt"

# Interesting endpoint patterns
grep -E '(api|admin|connect|integrat|webhook|playbook|soar|case|alert|rule|feed|enrich|scan|url|submit|upload|import|export|config|setting)' \
  "${OUTDIR}/02-surface/gau-filtered-${STAMP}.txt" | sort -u \
  > "${OUTDIR}/02-surface/interesting-endpoints-${STAMP}.txt"

echo "=== TOP ENDPOINT PATTERNS ==="
cat "${OUTDIR}/02-surface/interesting-endpoints-${STAMP}.txt" | head -50
```

### JS Mining — Connector endpoints and API keys

```bash
# Extract JS URLs from live httpx results
jq -r '.url' "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl" | \
  httpx -match-regex '\.js(\?|$)' -silent -rate-limit 10 \
  -o "${OUTDIR}/02-surface/js/js-urls-${STAMP}.txt"

# Mine JS for internal endpoints, API keys, hardcoded config
while read url; do
  curl -sk --max-time 15 "$url" | \
    grep -oE '(https?://[a-z0-9._/-]+|/api/v[0-9]+/[a-z0-9/_-]+|[A-Z_]{6,}=[a-zA-Z0-9_-]{20,})' | \
    sort -u >> "${OUTDIR}/02-surface/js/js-strings-${STAMP}.txt"
done < "${OUTDIR}/02-surface/js/js-urls-${STAMP}.txt"

echo "=== INTERESTING JS STRINGS ==="
grep -iE '(key|token|secret|auth|api|endpoint|internal|gcp|cloud|service.account)' \
  "${OUTDIR}/02-surface/js/js-strings-${STAMP}.txt" | sort -u | head -40
```

---

## Phase 3 — SSRF / Connector Testing (MANUAL — Pi session)

Chronicle Security Operations is a SOAR platform. The primary SSRF surface is:

### 3A — Integration connectors

Every SOAR has connectors that make HTTP requests to external services. After creating a free/trial account at chronicle.security:

1. Navigate to: **Integrations** or **Marketplace** or **App Store**
2. Find any connector with an "API URL", "Service URL", "Base URL", "Endpoint URL", "Webhook URL", or "Server URL" field
3. Enter your OOB listener URL: `https://<your-interactsh-OOB>`
4. Click "Test", "Validate", "Save", or "Connect"
5. Monitor OOB listener for GCP-origin HTTP hit

**Document per connector:**
- Connector name + UI path
- Field name used
- OOB hit: YES/NO
- Source IP (should be GCP if YES)
- Headers leaked: credentials forwarded?
- Response reflected in UI error?

**Target connectors (highest priority — URL field confirmed):**
- Jira (Issue Tracker connector — API Base URL)
- Slack (Webhook URL)
- PagerDuty (API Base URL)
- ServiceNow (Instance URL)
- Splunk (Server URL + Port)
- QRadar (Server URL)
- Any "Custom Integration" / HTTP Action connector

### 3B — Playbook/Automation HTTP Action

1. Navigate to: **Playbooks** → Create new → Add action block
2. Look for "HTTP Request", "Webhook", "REST API Call" action types
3. Set URL to OOB listener
4. Run playbook on a test case/alert

### 3C — Threat Intel URL Detonation

1. In an active case/alert, look for "Analyze URL" or "Detonate" actions
2. Submit: `https://<OOB>/detonate-test`
3. Check if chronicle.security backend fetches the URL (not client-side)

---

## Phase 4 — Nuclei Automated Scan (low-noise config)

```bash
# Run only technology-detection and exposure templates — no fuzzing
nuclei -l "${OUTDIR}/01-assets/httpx-${STAMP}.jsonl" \
  -t ~/nuclei-templates/technologies/ \
  -t ~/nuclei-templates/exposures/ \
  -t ~/nuclei-templates/misconfiguration/ \
  -rate-limit 10 -timeout 10 -bulk-size 10 \
  -o "${OUTDIR}/03-candidates/nuclei-${STAMP}.jsonl" \
  -jsonl

# Parse results
jq -r '[.info.severity,.info.name,.matched_at] | @tsv' \
  "${OUTDIR}/03-candidates/nuclei-${STAMP}.jsonl" | sort -k1
```

---

## SSRF Hard Stops (binding)

- OOB hit confirmed from GCP IP → **STOP. Document. Do NOT follow redirect to IMDS.**
- Do NOT submit `http://169.254.169.254` or `http://metadata.google.internal` as payload
- Do NOT submit RFC1918 URLs (`10.`, `172.16-31.`, `192.168.`)
- Do NOT try to retrieve service account tokens
- DO prove: GCP fetch origin + any credential leaked in headers → then stop

---

## Evidence Schema

Save all evidence to: `results/chronicle.security/evidence/session1-YYYYMMDD/`

```
oob_L1_<date>.log        # raw interactsh output
httpx-<stamp>.jsonl       # live hosts
nuclei-<stamp>.jsonl      # scanner results
connector-test-<name>.md  # manual connector test notes (one per connector)
```

---

## Decision Matrix

| Result | Action |
|--------|--------|
| 0 SSRF surfaces confirmed | File assets; log "no SSRF found"; pivot to IDOR/auth |
| 1 SSRF surface confirmed (GCP hit, creds leaked) | Draft F001 — same structure as AppSheet F002 |
| ≥2 SSRF surfaces (different connectors) | Draft systemic report — same structure as AppSheet F003 |
| IDOR — cross-tenant data read | Standalone Critical/High report |
| Auth bypass on admin or case management | Standalone High/Critical report |
