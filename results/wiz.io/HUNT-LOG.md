# Hunt Log — wiz.io (Google VRP TIER1)
Started: 2026-06-11 | Last updated: 2026-06-14

## CURRENT STATUS (2026-06-15)

| # | Item | Status |
|---|------|--------|
| 1 | **F001 win-test.wiz.io subdomain takeover** | ✅ VERIFIED — **SUBMIT NOW (standalone High 8.2)** |
| 2 | Chain 1 (F001 → CSP bypass) | ❌ CLOSED — no win-test in script-src on app.wiz.io or www.wiz.io |
| 3 | Chain 2 (F001 → OAuth redirect_uri hijack) | ❌ INCONCLUSIVE/CLOSED — Auth0 validates client_id first; cannot probe allowlist without valid client_id; mentioned in report as unconfirmed escalation path |
| 4 | ACTION A (WizCLI binary strings) | ✅ DONE — revealed Chain 11 |
| 5 | **Chain 11 (AI Remediation cross-tenant PR injection)** | 🔥 CRITICAL CANDIDATE — needs trial account |
| 6 | Chain 3 (Webhook SSRF → Grafana/IMDS) | 🔒 Needs trial account |
| 7 | Chain 4 (GraphQL cross-tenant IDOR) | 🔒 Needs trial account |
| 8 | Chain 9 (forensics-package IDOR) | 🔒 Needs trial account + 2nd account |
| 9 | ACTION B (PR preview GraphQL) | ⏳ Run on Pi |
| 10 | ACTION D (Ghost CMS API key) | ⏳ Run on Pi |
| 11 | test.wiz.io | 🆕 Live subdomain — referenced in Auth0 error page logo; add to recon |

**NEXT ACTION:** Submit F001 to Google/Wiz bug bounty program. Submission texts at:
- `findings/submission/F001-problem-description.md` — paste into "Problem description"
- `findings/submission/F001-impact-analysis.md` — paste into "Impact" field

---

| Time | Phase | Action | Finding |
|------|-------|---------|---------|
| 2026-06-11 | 0 | Scope confirmed | `*.wiz.io` IN-SCOPE, TIER1, blackout-exempt |
| 2026-06-11 | 1 | DNS resolution (dnsx) COMPLETE | See dns-analysis.md |
| 2026-06-11 | 1 | gau/waybackurls — COMPLETE | 166K endpoints, 46K JS files |
| 2026-06-11 | 2 | httpx probe (from Pi) — PARTIAL | peach=200(Wix), app=200(portal), wizcli=403(S3+CF) |
| 2026-06-11 | 2 | Grafana instances httpx (from Pi) | All ports FILTERED — VPC-internal only |
| 2026-06-11 | 2 | Active probe from cloud env BLOCKED | Anthropic egress gateway intercepts all TLS; remote env unusable for probing |
| 2026-06-11 | 3 | win-test.wiz.io takeover CONFIRMED | DEPLOYMENT_NOT_FOUND + expired cert → F001 READY TO SUBMIT |
| 2026-06-11 | 3 | GraphQL endpoint confirmed live | api.us1.app.wiz.io/graphql → UNAUTHORIZED (needs trial JWT) |
| 2026-06-11 | 3 | gh-109705.pr.test.wiz.io analyzed | PR preview loads full portal w/ apollo-client-dev build |
| 2026-06-11 | 3 | api.internal.integration.wiz.io | AWS API Gateway → "Missing Authentication Token" on all paths |
| 2026-06-11 | 3 | api.digitaltrust.{test,demo}.wiz.io | S3 AccessDenied — not real APIs, just S3-backed CF |
| 2026-06-11 | 3 | downloads.wiz.io/v1/wizcli/* | wizcli-linux-arm64 200 OK, 247MB, no auth (public binary) |
| 2026-06-11 | 3 | www.wiz.io CSP audit | ws://localhost:3000 dev artifact in production CSP connect-src |
| 2026-06-11 | 3 | blog.wiz.io Ghost CMS | /ghost/api/content/ confirmed; API key extraction PENDING |
| 2026-06-11 | 3 | WizCLI binary analysis | COMPLETE — 247MB Go binary, Envoy embedded, client_id fetched dynamically via gRPC (not hardcoded) |
| 2026-06-11 | 3 | Auth0 client_id hunt | CLOSED — server-side auth SDK, key never exposed in client JS or HTTP redirects |
| 2026-06-11 | 3 | www.wiz.io CSP full audit | Chain 1 CLOSED — win-test.wiz.io NOT in script-src/connect-src; frame-src has *.wiz.io but no script exec |
| 2026-06-11 | 3 | auth.app.wiz.io | AWS ELB 403 all paths — VPC-internal auth service; added to SSRF target list |
| 2026-06-11 | 3 | languageserver.app.wiz.io | AWS ELB 403 all paths — VPC-internal WebSocket LSP service; added to SSRF target list |
| 2026-06-11 | 3 | evs.wiz.io | Mixpanel analytics proxy (405 + developer.mixpanel.com body) — CLOSED informational |
| 2026-06-11 | 3 | hey.wiz.io | Full Supabase deployment (PostgREST 401, CORS *, JWKS public). Supabase project: gdujsswviqkyszcyopoh.supabase.co. Anon key NOT in any client-side bundle (server-side proxied). CLOSED — informational. |
| 2026-06-11 | 3 | F001 re-confirmed live | DEPLOYMENT_NOT_FOUND still returned — takeover window still open |
| 2026-06-11 | 2 | prod-us52.forensics-package.app.wiz.io | HTTP/2 401 Lambda@Edge auth (x-cache: LambdaGeneratedResponse); browser UA bypasses WAF, Lambda validates Bearer before routing; all paths 401 |
| 2026-06-11 | 2 | events-ingestion.eu21.app.wiz.io | AWS API Gateway EU21; GET/POST all 403 ForbiddenException (application/json, empty body); requires auth token |
| 2026-06-11 | 2 | cli-results.us1.integration.wiz.io | Amazon S3 + CloudFront; bucket listing disabled (AccessDenied XML); all path probes auth-gated |
| 2026-06-12 | 2 | file-upload.eu1.e2e.wiz.io | S3 + CloudFront; 403 AccessDenied; bucket exists; e2e environment |
| 2026-06-12 | 2 | outpost-storage.eu1.e2e.wiz.io | S3 + CloudFront; 403 AccessDenied; Wiz Outpost on-prem storage in e2e |
| 2026-06-12 | 2 | prod-us116-outpost-storage.app.wiz.io | AWS API Gateway; 403 "Missing Authentication Token"; production outpost storage API |
| 2026-06-12 | 2 | netscanner-v2-results.us3.integration.wiz.io | S3 + CloudFront; 403 AccessDenied; network scanner v2 results bucket |
| 2026-06-12 | 2 | netscanner-results.us23.app.wiz.io | S3 + CloudFront; 403 AccessDenied; netscanner results bucket |
| 2026-06-12 | 2 | prod-us106.sensor-forensics.app.wiz.io | CloudFront HTML 403; WAF bot block (same pattern as forensics-package) |
| 2026-06-12 | 2 | prod-eu32-sensor.app.wiz.io | AWS API Gateway; 403 "Missing Authentication Token" |
| 2026-06-12 | 2 | no-cdn-version-backup.wiz.io | Global Accelerator IPs (75.2.70.75, 99.83.190.102) → nginx origin; HTTP 301 → HTTPS on all paths; HTTPS port 443 unreachable (000); DEAD END — VPC-internal origin only accessible through CloudFront |
| 2026-06-12 | 2 | diskanalyzer-results-source.me-south-1.{app,e2e}.wiz.io | CloudFront 504 Gateway Timeout via CCU50-P5 (Kolkata PoP) to me-south-1 origin; generic error body — no S3 bucket name leaked; direct S3 bucket guesses timed out; PARKED — origin unknown |
| 2026-06-12 | 2 | a2a.eu1.test.wiz.io | Direct AWS ELB (awselb/2.0, no CloudFront); blanket 403 on all 17 paths probed (/, /health, /api, /v1, /graphql, /admin, /livez, etc.); needs auth token to proceed; PARKED |
| 2026-06-12 | 2 | a2a.test.wiz.io | 403 from AWS ELB via CloudFront (x-cache: Error from cloudfront); same pattern as eu1 variant |
| 2026-06-14 | 4 | F001 Phase 4 verified | win-test.wiz.io CNAME still live; DEPLOYMENT_NOT_FOUND confirmed; report + submission texts written |
| 2026-06-14 | 5 | F001 triaged | CVSS 8.2 High; passes all CLAUDE.md §2 gates; ready to submit |
| 2026-06-14 | 6 | Workflow cleaned | 00-plan.md updated; orchestrator state corrected; Chain 9+10 probes added to phase4 script |
| 2026-06-14 | 3 | **Chain 11 DISCOVERED** | WizCLI binary strings → embedded `github.com/wiz-sec/wiz/grpclib/rpc/ai` proto reveals AI Remediation gRPC service: `RequestCustomPullRequest(repositoryId, scanId, patches)` + `RunResponseAction(inputJson)` → cross-tenant PR injection candidate (Critical) |
| 2026-06-14 | 1 | FedRAMP/GovCloud envs confirmed | `app.wiz.io` login "Another environment" dropdown shows: **Wiz for Gov (FedRAMP)** → `app.gov.wiz.io`; **Commercial on GovCloud** → `govcloud.wiz.io` (est.) — separate Auth0 tenants; Chain 2 OAuth scope expanded |
| 2026-06-14 | 2 | **HTML config block extracted** | SPA serves full prod config at every path; extracted: `VITE_APP_COGNITO_AUDIENCE=wiz-api` (JWT confusion candidate Chain 12), LD client ID `5f2bbaa730af0f08855ad7e9`, S3 bucket `wizio-public.s3.amazonaws.com`, CloudFormation template path, git commit `4553dc648e2ab5a5a90cd26d4fd2eabe2209f0c2` |
| 2026-06-14 | 2 | **graphqlTypes bundle extracted** | `graphqlTypes-N1XN-ltn.js` (222KB) downloaded from browser; 250+ mutations found including: **Chain 13** `CopyResourceForensicsToExternalAccount` (Critical IDOR candidate), **Chain 14** `CreateMemberTenantRequest` (MSSP unauthorized access), `RequestRemediationPullRequest`+`FindingPullRequestRemediation` (Chain 11 confirmed), `RunResponseActionFix(inputJson)` (injection), `WebhookIntegrationParams` (Chain 3) |
| 2026-06-15 | 4 | Chain 1 CLOSED | Pi confirms: app.wiz.io `script-src` = `'self' sha384` only; www.wiz.io `script-src` = `'self' unsafe-inline` + CDN; win-test NOT in any script-src/connect-src |
| 2026-06-15 | 4 | Chain 2 CLOSED (inconclusive) | auth0.demo.wiz.io + auth0.e2e.wiz.io LIVE OIDC tenants; redirect_uri probe: Auth0 validates client_id first → "Oops!" page → cannot determine allowlist; auth.app.wiz.io production Auth0 = VPC-internal (403 from awselb/2.0); side-note: test.wiz.io live (found in Auth0 error page logo URL) |
| 2026-06-15 | 6 | F001 SUBMISSION DECISION | Submit standalone High 8.2 — all chain paths closed or inconclusive. Submission texts in findings/submission/. |

## Key Findings

### [CONFIRMED / READY TO SUBMIT] F001 — win-test.wiz.io Subdomain Takeover
- `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com` — Vercel project deleted
- Confirmed: `DEPLOYMENT_NOT_FOUND` body + expired LE cert (expired 2025-12-16)
- CVSS 3.1: 8.2 (High) — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
- **Report:** `findings/F001-win-test-subdomain-takeover.md`
- **Chain 1 CLOSED (2026-06-15):** app.wiz.io `script-src` = `'self' sha384` only; no *.wiz.io wildcard
- **Chain 2 INCONCLUSIVE/CLOSED (2026-06-15):** auth0.demo.wiz.io + auth0.e2e.wiz.io LIVE but
  redirect_uri allowlist unprobeable without valid client_id; mentioned in report as potential escalation
- **Submit standalone High 8.2 — no further chain work needed for F001**

### [DROPPED] CSP ws://localhost:3000 in production
- `www.wiz.io` CSP `connect-src` contains `ws://localhost:3000` dev artifact
- **Dropped:** No exploitation path; fails Hard Rejection List. Google VRP = Informational/won't fix.

### [INVESTIGATING] WizCLI Binary — Internal Endpoint Discovery
- `downloads.wiz.io/v1/wizcli/latest/wizcli-linux-arm64` → 247MB, no auth
- Binary strings extraction may reveal hardcoded internal API endpoints, auth flows, metadata URL references
- Status: STRINGS EXTRACTION PENDING

### [INVESTIGATING] gh-109705.pr.test.wiz.io — PR Preview GraphQL Attack Surface
- Loads full Wiz portal with `apollo-client-dev` build (debug mode)
- GraphQL introspection likely enabled in dev builds
- Auth may be relaxed vs production
- Status: GRAPHQL INTROSPECTION PENDING

### [CONFIRMED] Grafana instances — VPC-internal, SSRF chain targets
- `us1.grafana.wiz.io`, `us2.grafana.wiz.io` (production)
- `us1.grafana.test.wiz.io`, `us1.grafana.fedtest.wiz.io` (non-prod)
- All ports filtered from external internet — ONLY reachable via SSRF
- **Value:** Chain target if SSRF found in webhook/connector

### [PENDING] Webhook SSRF — PRIMARY HIGH-VALUE TARGET
- 100+ regional webhook endpoints: `webhooks.{region}{N}.app.wiz.io`
- Requires Wiz trial account
- Status: REGISTER TRIAL ACCOUNT → H1 test

### [PENDING] Developer RDE webhook endpoints
- `webhooks.{developer}.rde.wiz.io` — 100+ personal dev environments
- Status: MUST PROBE FROM PI

### [CLOSED] hey.wiz.io Supabase
- Full Supabase Cloud deployment (project: gdujsswviqkyszcyopoh.supabase.co)
- CORS `*`, JWKS public key obtained, all services confirmed (REST/Auth/Storage/Functions/Realtime)
- Supabase anon key NOT accessible — all calls server-side proxied through Next.js API routes
- CTF challenge names embedded in /ctf chunk: BigIAMChallenge, AISecurityChallenge
- OIDC discovery leaks project URL — but this is STANDARD Supabase behavior (designed to be public)
- No submission value — informational

### [CONFIRMED VPC-INTERNAL] SSRF Target List (requires webhook SSRF to reach)
- `us1.grafana.wiz.io`, `us2.grafana.wiz.io` — Grafana (creds/dashboards)
- `auth.app.wiz.io` — Auth service (could expose Auth0 client_id via OIDC)
- `languageserver.app.wiz.io` — IaC language server (WebSocket LSP)
- All confirmed AWS ELB, all return 403 from external internet

### [NEW / FINGERPRINTED] forensics-package.app.wiz.io (Lambda@Edge, 401 gated)
- `prod-us52.forensics-package.app.wiz.io` — forensics scan package result storage
- Architecture: CloudFront WAF → bot block by default; browser UA bypasses WAF → Lambda@Edge validates `Authorization: Bearer` before routing
- All paths return HTTP/2 **401** `Unauthorized` with `x-cache: LambdaGeneratedResponse`
- Meaning: Lambda auth runs at edge BEFORE any backend is reached
- **Attack hypothesis (Chain 9):** With WizCLI auth token, probe cross-tenant paths like
  `/packages/<other-tenant-id>/<scan-id>` — if tenant ID is in path and not server-validated, IDOR → another tenant's forensic scan results
- **Blocker:** Requires Wiz trial account → WizCLI auth flow to get valid Bearer token
- **SSRF value:** If SSRF discovered via webhook, probe `http://forensics-package.app.wiz.io/internal/...` — Lambda@Edge not applied to internal VPC requests

### [NEW / FINGERPRINTED] events-ingestion.eu21.app.wiz.io (API Gateway, 403 gated)
- AWS API Gateway in eu21 region
- GET root → 403 `{"message":"Forbidden"}` (ForbiddenException)
- POST `/events` → 403 empty body; POST `/` → 403 empty body
- **Attack hypothesis:** With tenant auth token, test if `tenant_id` in event payload can be spoofed to inject events attributable to another tenant. Also probe for unauthenticated bulk ingest paths.
- **Blocker:** Requires auth token

### [NEW / FINGERPRINTED] cli-results.us1.integration.wiz.io (S3/CloudFront, gated)
- Amazon S3 bucket + CloudFront; listing disabled (AccessDenied XML response)
- `?list-type=2` probe confirmed bucket exists but listing blocked
- **Attack hypothesis:** If WizCLI scan result paths follow a guessable pattern (e.g., `/results/<tenant-id>/<uuid>.json`), try cross-tenant path traversal with a valid token
- **Blocker:** Requires WizCLI token and known path pattern

### [NEW BATCH 2 — 2026-06-12] no-cdn-version-backup / diskanalyzer / a2a — INVESTIGATED

**no-cdn-version-backup.wiz.io** — DEAD END
- DNS → AWS Global Accelerator IPs (75.2.70.75, 99.83.190.102)
- Port 80: nginx 301 redirect to HTTPS on every path
- Port 443: connection refused (000) — TLS listener not configured
- Conclusion: VPC-internal nginx origin, only accessible through CloudFront; "no-cdn" means it IS the origin behind the CDN, not a public bypass

**diskanalyzer-results-source.me-south-1.{app,e2e}.wiz.io** — PARKED
- CloudFront 504 Gateway Timeout — origin unreachable
- Response headers: `via: 1.1 b2449cb00a927a35244993c45d8637d4.cloudfront.net`, PoP CCU50-P5 (Kolkata)
- Error body is generic CloudFront page — no S3 bucket name revealed
- S3 bucket name guesses (diskanalyzer-results-source, diskanalyzer-results-source-me-south-1) — connection timeout to me-south-1 from Pi
- Cannot progress without knowing exact bucket name; PARKED

**a2a.eu1.test.wiz.io** — PARKED (confirmed architecture: direct ELB, no WAF)
- httpx: `[403] [403 Forbidden] [awselb/2.0] [Amazon ELB, Amazon Web Services]`
- 17 paths probed — all 403 from ELB itself (no listener rule matches, not app-level)
- "a2a" = agent-to-agent, "eu1.test" = test environment EU region 1
- Direct ELB without CloudFront/WAF confirmed (no x-cache header)
- PARKED — needs valid auth token or mTLS client cert to proceed

### [NEW BATCH — 2026-06-12] 8 more subdomains fingerprinted

**S3 + CloudFront buckets (all 403 AccessDenied, listing disabled):**
- `file-upload.eu1.e2e.wiz.io` — e2e file upload bucket (name suggests direct file upload target)
- `outpost-storage.eu1.e2e.wiz.io` — Wiz Outpost on-prem agent storage in e2e env
- `netscanner-v2-results.us3.integration.wiz.io` — network scanner v2 results
- `netscanner-results.us23.app.wiz.io` — network scanner results

**AWS API Gateway (403 "Missing Authentication Token"):**
- `prod-us116-outpost-storage.app.wiz.io` — production Outpost storage API (different from e2e S3 bucket; this is an API)
- `prod-eu32-sensor.app.wiz.io` — sensor API endpoint EU

**CloudFront WAF bot-block (same pattern as forensics-package):**
- `prod-us106.sensor-forensics.app.wiz.io` — combined sensor+forensics service; browser UA likely bypasses to Lambda@Edge auth

**Pattern emerging:** Wiz has a consistent microservice fleet:
- `*.sensor.app.wiz.io` — cloud security sensor (data collection from customer cloud)
- `*.forensics-package.app.wiz.io` — forensic scan package storage
- `*.sensor-forensics.app.wiz.io` — combined sensor+forensics
- `*-outpost-storage.app.wiz.io` — Wiz Outpost on-prem data storage
- `netscanner*-results.*.wiz.io` — network scan result storage

All follow the same auth pattern: valid Wiz tenant token required. The cross-tenant IDOR hypothesis (Chain 9) applies to the entire fleet — if any one endpoint fails to validate tenant-path ownership, the entire fleet of result buckets is vulnerable to cross-tenant read.

## Decision Log

- Chose Wiz: TIER1, blackout-exempt, zero prior VRP research, CNAPP = rich attack surface
- Remote cloud env (claude.ai/code) uses Anthropic egress gateway — CANNOT be used for active probing
- All active probing MUST run on Pi — cloud env only good for analysis/code
- Grafana instances all VPC-internal → save as SSRF targets, not direct targets
- api.internal.integration.wiz.io (AWS API Gateway) — paths all 403/empty without auth; park until trial JWT available
- api.digitaltrust.*.wiz.io — confirmed S3 static buckets, not real APIs; closed
- downloads.wiz.io root = S3 403; /v1/wizcli/* = public binary; no bucket listing
- Webhook SSRF (H1) remains #1 priority — needs trial account
- no-cdn-version-backup.wiz.io — confirmed DEAD END (VPC-internal origin, port 443 closed externally)
- diskanalyzer-results-source — PARKED (504, can't determine S3 origin without AWS console access)
- a2a.eu1.test.wiz.io — PARKED (blanket ELB 403, interesting no-WAF target but needs auth)
- All new host investigations bottlenecked on trial account / Wiz JWT

## Environment Constraint (IMPORTANT)
The cloud execution environment (where this Claude session runs) routes ALL outbound
connections through `Anthropic Egress Gateway SDS (production)`. This proxy blocks
connections to external hosts with `x-deny-reason: host_not_allowed`. TLS cert
issuer confirms: `O=Anthropic; CN=Egress Gateway SDS Issuing CA (production)`.

**Consequence:** All active reconnaissance and probing must run on the Pi.
This cloud env is for: analysis, code, config, planning, git operations only.

---

## Next Actions — Run These on the Pi

### PATH fix (if new terminal — run first)
```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin
curl --version | head -1 && echo "PATH OK"
```

---

### PHASE 4 SCRIPTS (NEW — run these next)

**Goal: Extract Auth0 client_id → test Chain 2 (OAuth redirect_uri bypass → Critical)**

```zsh
# Terminal 1: Phase 3 baseline (if not run yet)
zsh ~/bug-bounty-hunting-/scripts/phase3-wiz-pi.sh 2>&1 | tee ~/phase3-output.txt

# Terminal 2: Phase 4a — Auth0 client_id extraction
zsh ~/bug-bounty-hunting-/scripts/phase4-auth0-clientid-wiz.sh 2>&1 | tee ~/phase4-auth0-output.txt

# Terminal 3: Phase 4b — Trial account attacks (run AFTER registering at app.wiz.io)
# export WIZ_JWT="eyJ..."   # paste JWT from browser DevTools
# zsh ~/bug-bounty-hunting-/scripts/phase4-trial-account-wiz.sh
```

**Critical path to finding a confirmed High+ bug TODAY:**

```
1. Run phase4-auth0-clientid-wiz.sh
   → If client_id found → redirect_uri bypass is auto-tested (Chain 2)
   → If chain 2 fires → CRITICAL bug, submit immediately

2. Register Wiz trial account (https://app.wiz.io free trial)
   → Get JWT from browser DevTools
   → Run phase4-trial-account-wiz.sh with WIZ_JWT set
   → Webhook SSRF payload list ready in script
   → Cross-tenant IDOR test guide in script
```

---

### ACTION A — WizCLI Binary Strings Extraction (HIGH VALUE)
Extract internal API endpoints hardcoded in the publicly downloadable CLI binary.

```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

# Download if not already present
[ -f /tmp/wizcli ] || curl -s "https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-arm64" -o /tmp/wizcli
ls -lh /tmp/wizcli

# Version check (no network calls)
chmod +x /tmp/wizcli
/tmp/wizcli version 2>/dev/null | head -5

# Extract ALL wiz.io URLs hardcoded in binary
echo "=== HARDCODED wiz.io URLs ==="
strings /tmp/wizcli | grep -Ei "https?://[a-z0-9._-]*wiz\.io" | sort -u | head -60

echo "=== GRAPHQL / API PATHS ==="
strings /tmp/wizcli | grep -Ei "(/graphql|/api/v[0-9]|/v[0-9]+/|/internal/|/admin/)" | grep -v "\.png\|\.svg\|\.js\b\|\.css\b" | sort -u | head -40

echo "=== CLOUD METADATA URLS ==="
strings /tmp/wizcli | grep -Ei "(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|imds)" | sort -u

echo "=== AUTH / JWT / CLIENT_ID ==="
strings /tmp/wizcli | grep -Ei "(client_id|client_secret|audience|tenant_id|auth0|jwks|issuer)" | sort -u | head -30

echo "=== INTERNAL / PRIVATE ENDPOINTS ==="
strings /tmp/wizcli | grep -Ei "(internal|private|localhost|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | grep -v "golang\|\.go\b\|internal/race\|internal/cpu" | sort -u | head -40
```

---

### ACTION B — gh-109705.pr.test.wiz.io GraphQL Introspection
PR preview with apollo-client-dev — check for enabled introspection and exposed schema.

```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

TARGET="https://gh-109705.pr.test.wiz.io"

echo "=== RESPONSE HEADERS ==="
curl -sI "${TARGET}/" 2>/dev/null | head -20

echo "=== GRAPHQL ENDPOINT DISCOVERY ==="
for ep in /graphql /api/graphql /v1/graphql /query /api/query; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "${TARGET}${ep}")
  echo "${code}  ${ep}"
done

echo "=== GRAPHQL INTROSPECTION (no auth) ==="
curl -sk --connect-timeout 10 -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}' \
  2>/dev/null | python3 -m json.tool 2>/dev/null | head -60

echo "=== FIND API ENDPOINTS IN JS BUNDLE ==="
# Get main page, extract JS bundle URLs
JSURLS=$(curl -sk "${TARGET}/" | grep -oE 'src="(/[^"]+\.js[^"]*)"' | sed 's/src="//;s/"//')
echo "JS bundles found:"
echo "$JSURLS" | head -10

# Fetch first JS bundle, look for API endpoint strings
FIRSTJS=$(echo "$JSURLS" | head -1)
if [ -n "$FIRSTJS" ]; then
  curl -sk "${TARGET}${FIRSTJS}" | grep -oE '"(https?://[^"]+wiz\.io[^"]*|/api/[^"]+|/graphql[^"]*)"' | sort -u | head -40
fi

echo "=== CSP HEADER (check for win-test.wiz.io in CSP) ==="
curl -sI "${TARGET}/" 2>/dev/null | grep -i "content-security-policy"
```

---

### ACTION C — www.wiz.io Full CSP Dump + win-test Chain Check
Determine if win-test.wiz.io or *.wiz.io appears in CSP → would escalate F001 to Critical.

```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

echo "=== FULL CSP from www.wiz.io ==="
curl -sI "https://www.wiz.io/" 2>/dev/null | tr ',' '\n' | grep -i "security-policy" -A 999 | head -80

echo ""
echo "=== Does CSP reference wiz.io subdomains (takeover chain check) ==="
curl -sI "https://www.wiz.io/" 2>/dev/null | grep -i "content-security-policy" | grep -oE "[a-z0-9.*-]+\.wiz\.io" | sort -u

echo ""
echo "=== Does CSP reference vercel.app (takeover chain check) ==="
curl -sI "https://www.wiz.io/" 2>/dev/null | grep -i "content-security-policy" | grep -oE "[a-z0-9.*-]+\.vercel\.app" | sort -u

echo ""
echo "=== FULL CSP from app.wiz.io (portal) ==="
curl -sI "https://app.wiz.io/" 2>/dev/null | tr ',' '\n' | grep -i "security-policy" -A 999 | head -80
```

---

### ACTION D — blog.wiz.io Ghost CMS Content API Key Extraction
Ghost Content API keys are often embedded in page source / JS. If found: unauthenticated read of all posts, tags, member data.

```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

echo "=== FIND CONTENT API KEY IN PAGE SOURCE ==="
curl -sk "https://blog.wiz.io/" | grep -oE '[a-f0-9]{26}' | sort -u | head -10

echo ""
echo "=== FIND API KEY IN SCRIPT TAGS ==="
curl -sk "https://blog.wiz.io/" | grep -oEi '(content.?api.?key|apiKey|ghost.?key)[^a-z][^"]*"[^"]+' | head -10

echo ""
echo "=== GHOST SDK JS ==="
curl -sk "https://blog.wiz.io/public/ghost-sdk.min.js" 2>/dev/null | grep -oE 'key:[^,}]+' | head -5
curl -sk "https://blog.wiz.io/public/ghost-sdk.js" 2>/dev/null | grep -oE 'key:[^,}]+' | head -5

echo ""
echo "=== GHOST ADMIN API EXPOSURE (should 403/redirect) ==="
curl -sI "https://blog.wiz.io/ghost/api/v3/admin/site/" 2>/dev/null | head -8
curl -sI "https://blog.wiz.io/ghost/api/admin/site/" 2>/dev/null | head -8

echo ""
echo "=== GHOST MEMBERS API ==="
curl -sk "https://blog.wiz.io/members/api/site/" 2>/dev/null | head -c 300

echo ""
echo "=== GHOST CONTENT API (unauthenticated — should require key) ==="
curl -sk "https://blog.wiz.io/ghost/api/content/posts/" 2>/dev/null | head -c 300
curl -sk "https://blog.wiz.io/ghost/api/v5.0/content/posts/" 2>/dev/null | head -c 300
```

---

### ACTION E — tracking.wiz.io + team.wiz.io Deep Probe
tracking.wiz.io returned 200 (no redirect, Cloudflare). team.wiz.io returned 204. Neither classified yet.

```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

echo "=== tracking.wiz.io ==="
curl -sv "https://tracking.wiz.io/" 2>&1 | head -30
curl -sk "https://tracking.wiz.io/" | head -c 500
echo ""
# Path probe
for p in /health /api /v1 /status /pixel /t /track /collect; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 5 "https://tracking.wiz.io${p}")
  echo "${code}  ${p}"
done

echo ""
echo "=== team.wiz.io ==="
curl -sI "https://team.wiz.io/" 2>/dev/null | head -15
curl -sk "https://team.wiz.io/" | head -c 300
for p in /health /api /v1 /users /members /teams; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 5 "https://team.wiz.io${p}")
  echo "${code}  ${p}"
done
```

---

### ACTION F — HIGHEST PRIORITY: Register Wiz Trial Account
Unlocks: GraphQL API JWT, webhook SSRF test (H1), connector SSRF, OAuth flow analysis.

1. Go to `https://app.wiz.io` → "Start Free Trial" (or "Get a demo" → request sandbox)
2. Use email: zahinshahriar3@gmail.com
3. Once logged in → open browser DevTools → Network → capture any XHR/fetch request
4. Copy the `Authorization: Bearer <JWT>` header value → save it
5. Then run SSRF test:

```zsh
# Save your JWT from browser DevTools
JWT="eyJ..."  # paste full token here

# Confirm GraphQL API works with your JWT
curl -sk -X POST "https://api.us1.app.wiz.io/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ serverInfo { version } }"}' | python3 -m json.tool | head -30

# Try GraphQL introspection
curl -sk -X POST "https://api.us1.app.wiz.io/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ __schema { queryType { name } types { name kind } } }"}' \
  | python3 -m json.tool | head -80
```

---

### ACTION G — RDE Webhook Endpoints Probe
```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

for host in \
  webhooks.guy.goldenberg.rde.wiz.io \
  webhooks.roey.dror-us.rde.wiz.io \
  webhooks.roy5.rde.wiz.io \
  webhooks.cfir.rde.wiz.io \
  webhooks.or.bin.rde.wiz.io \
  webhooks.on-demand-1.rde.wiz.io \
  webhooks.on-demand-5.rde.wiz.io \
  webhooks.bootstrap-rde-001.rde.wiz.io; do
  echo "=== $host ==="
  curl -sI --connect-timeout 8 "https://${host}/" 2>/dev/null | head -8
  echo "body: $(curl -sk --connect-timeout 8 "https://${host}/" 2>/dev/null | head -c 200)"
  echo ""
done
```
[2026-06-11 16:26:42][INFO ] ══ Bug Bounty Orchestrator v2.0 ══  target=wiz.io  phases=0-0  bg=false  dry=true
[2026-06-11 16:26:42][INFO ] Initializing new orchestrator state

══════════════════════════════════════════════════════════════════════
[2026-06-11 16:26:42][PHASE] 0 — Scope Gate & Hunt Plan
══════════════════════════════════════════════════════════════════════[2026-06-11 16:26:42][INFO ] Scope OK: wiz.io
[2026-06-11 16:26:42][INFO ] Created 00-plan.md
[2026-06-11 16:26:42][INFO ] Phase 0 DONE
[2026-06-11 16:26:42][INFO ] Intelligence re-plan after phase 0
[2026-06-11 16:27:39][INFO ] ══ Bug Bounty Orchestrator v2.0 ══  target=wiz.io  phases=0-0  bg=false  dry=false
[2026-06-11 16:27:39][INFO ] Initializing new orchestrator state

══════════════════════════════════════════════════════════════════════
[2026-06-11 16:27:39][PHASE] 0 — Scope Gate & Hunt Plan
══════════════════════════════════════════════════════════════════════[2026-06-11 16:27:39][INFO ] Scope OK: wiz.io
[2026-06-11 16:27:39][INFO ] 00-plan.md exists — resuming
[2026-06-11 16:27:39][INFO ] Phase 0 DONE
[2026-06-11 16:27:39][INFO ] Intelligence re-plan after phase 0
[2026-06-11 16:27:42][INFO ] ══ Bug Bounty Orchestrator v2.0 ══  target=wiz.io  phases=0-6  bg=false  dry=false
[2026-06-11 16:27:42][INFO ] Resuming from existing state
[2026-06-11 16:27:49][INFO ] ══ Bug Bounty Orchestrator v2.0 ══  target=wiz.io  phases=3-3  bg=false  dry=true
[2026-06-11 16:27:49][INFO ] Resuming from existing state

══════════════════════════════════════════════════════════════════════
[2026-06-11 16:27:49][PHASE] 3 — Vulnerability Discovery + Lead Qualification
══════════════════════════════════════════════════════════════════════[2026-06-11 16:27:50][INFO ] Pi5 resources — CPU:12% RAM:3% TEMP:0°C
[2026-06-11 16:27:50][INFO ] Phase 3 scanning 1 targets
[2026-06-11 16:27:50][INFO ] Pi5 resources — CPU:3% RAM:3% TEMP:0°C
[2026-06-11 16:27:50][INFO ] [DRY-RUN] nuclei -u https://wiz.io (would write → /home/user/Bug-Bounty-Hunting-/results/wiz.io/03-candidates/nuclei-wiz_io.txt)
[2026-06-11 16:27:50][INFO ] Running lead qualification gate on all nuclei output
[2026-06-11 16:27:50][INFO ] Lead gate: 0 pursuing / 0 auto-closed
[2026-06-11 16:27:50][INFO ] Phase 3 DONE
[2026-06-11 16:27:50][INFO ] Intelligence re-plan after phase 3
[2026-06-11 16:27:50][DECIDE] Phase 3 result: 0
0 pursuing (0
0 HIGH confidence)
