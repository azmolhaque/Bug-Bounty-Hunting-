# Attack Chains — wiz.io
# Status: hypotheses ranked by probability × impact
# Updated: 2026-06-14

## Chain 1 — Subdomain Takeover → CSP Bypass → Critical ✗ CLOSED

**Status:** CLOSED 2026-06-15
**Reason:** app.wiz.io `script-src` = `'self' 'sha384-...'` only — no `*.wiz.io`
  wildcard. www.wiz.io `script-src` = `'self' 'unsafe-inline' 'unsafe-eval'` +
  CDN domains only. win-test.wiz.io is NOT in any script-src or connect-src.
  Frame-src includes `*.wiz.io` (win-test CAN be framed) but framing alone ≠
  code execution.

**Components:** F001 (win-test.wiz.io takeover) + CSP allowlist entry for win-test
**Probability:** ZERO — confirmed by Pi ACTION C 2026-06-15
**Potential severity:** N/A

---

## Chain 2 — Subdomain Takeover → OAuth redirect_uri Hijack → Critical ✗ INCONCLUSIVE/CLOSED

**Status:** INCONCLUSIVE → treated as CLOSED for F001 submission 2026-06-15
**Reason:** Auth0 validates `client_id` before `redirect_uri`. Probe with FAKE_PROBE_TEST
  returned "Oops!" HTML error page (unknown client_id) on both auth0.demo.wiz.io and
  auth0.e2e.wiz.io — cannot determine redirect_uri allowlist without a valid client_id
  registered in these tenants. Cannot safely probe further without actual demo/e2e account.
  auth.app.wiz.io (production Auth0) returns HTTP 403 from awselb/2.0 (VPC-internal, not
  publicly accessible).
**Side note:** Auth0 error page references `https://test.wiz.io/static/assets/wiz_auth0_logo.png`
  → `test.wiz.io` is a live subdomain worth adding to recon list.

**Components:** F001 (win-test.wiz.io) + Auth0 OAuth misconfiguration
**Probability:** UNKNOWN — cannot probe without valid client_id
**Potential severity:** Critical (account takeover) — IF redirect_uri allowlist contains win-test
**Included in F001 report:** YES — documented as unconfirmed escalation path for triager to
  evaluate with internal Auth0 tenant knowledge.

---

## Chain 3 — Webhook SSRF → Internal Grafana → Credential Exfil (HIGH PRIORITY)

**Components:** Webhook integration feature + confirmed VPC-internal Grafana instances
**Probability:** High — webhook SSRF is a common class; Grafana commonly misconfigured
**Potential severity:** Critical (cross-tenant data, cloud credentials in Grafana)

**How it works:**
1. Register trial account → Settings → Integrations → Custom Webhooks
2. Create webhook pointing to `http://us1.grafana.wiz.io/api/health` (internal only)
3. Trigger an alert → webhook service makes server-side HTTP request to Grafana
4. If Grafana has anon access enabled: read metric dashboards → cloud credentials visible
5. If Grafana has default creds: `admin/admin` → full datasource credential exfil

**SSRF escalation payloads (try in order):**
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDSv1)
- `http://169.254.169.254/latest/api/token` + IMDSv2 flow
- `http://metadata.google.internal/computeMetadata/v1/?recursive=true`
- `http://us1.grafana.wiz.io/api/health`
- `http://us1.grafana.wiz.io/api/datasources` (Grafana datasource list = DB/cloud creds)
- `http://us1.grafana.wiz.io/api/dashboards/home`
- `http://auth.app.wiz.io/` (VPC-internal auth service — confirmed AWS ELB behind internal ALB)
- `http://auth.app.wiz.io/.well-known/openid-configuration` (may expose Auth0 client_id!)
- `http://languageserver.app.wiz.io/` (VPC-internal language server — may exec code or read files)
- `http://languageserver.app.wiz.io/health`

**Setup needed:** Wiz trial account + interactsh listener
**Script:** `scripts/phase3-wiz-pi.sh` (ACTION F)

---

## Chain 4 — GraphQL Schema → Cross-Tenant IDOR → Critical

**Components:** GraphQL API (live, auth-required) + CNAPP multi-tenant architecture
**Probability:** Medium — cross-tenant isolation bugs common in complex GraphQL APIs
**Potential severity:** Critical (cross-tenant cloud asset access)

**How it works:**
1. Get trial JWT from app.wiz.io
2. Run full schema introspection: `scripts/graphql-attack-wiz.sh`
3. Identify queries that accept object IDs without tenant scoping
4. Probe with IDs from a second test account (different tenant)
5. If IDs are guessable (UUID) or enumerable, cross-tenant data access is possible

**Key IDOR targets in Wiz domain model:**
- `project(id: ...)` — cross-tenant project visibility
- `connector(id: ...)` — cloud connector = cloud credentials
- `issue(id: ...)` — security findings from another tenant
- `node(id: ...)` — Relay-style global ID lookup (most dangerous if exists)
- `cloudResource(id: ...)` — direct cloud asset access across tenants

**Script:** `scripts/graphql-idor-wiz.sh`

---

## Chain 5 — WizCLI Binary → Hardcoded Internal Endpoint → Auth Bypass

**Components:** Publicly downloadable WizCLI binary + internal API endpoints
**Probability:** Medium — Go binaries commonly contain hardcoded staging/debug endpoints
**Potential severity:** High (unauthenticated internal API access)

**How it works:**
1. Download public wizcli-linux-arm64 (already done, 247MB)
2. Extract strings: `strings /tmp/wizcli | grep -E "wiz.io|/api/|/graphql"`
3. Look for: staging API endpoints, debug endpoints, internal service URLs, auth bypass parameters
4. Probe discovered endpoints without auth

**Script:** `scripts/phase3-wiz-pi.sh` (ACTION A)

---

## Chain 6 — Ghost CMS Content API Key → Member Data Exposure

**Components:** blog.wiz.io Ghost CMS + exposed Content API key (common misconfiguration)
**Probability:** Medium — Ghost embeds content API key in page source by design (read-only, but still)
**Potential severity:** Low-Medium (PII if member emails exposed)

**How it works:**
1. Ghost Content API keys are embedded in frontend JS by design (they're public read-only)
2. But if a Ghost "members" API key is exposed: access member emails (subscribers)
3. If Ghost admin API key leaked: full content management access

**Script:** `scripts/phase3-wiz-pi.sh` (ACTION D)

---

## Chain 7 — dynamic-dns-checker.wiz.io → SSRF

**Components:** Unknown internal DNS checker service
**Probability:** Unknown — needs fingerprinting
**Potential severity:** High if it makes HTTP requests to user-supplied hosts

**How it works:**
1. Service checks if DNS records are correctly pointing to Wiz infrastructure
2. If it accepts hostname input and makes HTTP requests to verify
3. Supply hostname resolving to cloud metadata IP (169.254.169.254) or internal Grafana
4. Server-side request hits internal service → SSRF

**Script:** `scripts/oauth-redirect-probe-wiz.sh` (last section)

---

## Chain 8 — PR Preview Environments → Test GraphQL Schema Exposure

**Components:** gh-NNNNNN.pr.test.wiz.io + apollo-client-dev builds
**Probability:** High for schema exposure (dev builds enable introspection); Medium for auth bypass
**Potential severity:** Medium (schema leak) to High (if test env has relaxed auth)

**How it works:**
1. PR preview loads full portal with apollo-client-dev (debug GraphQL client)
2. GraphQL introspection typically enabled in development builds
3. Access test API backend without valid production credentials
4. Find differences in test vs production schema → hidden fields, debug mutations

**Script:** `scripts/phase3-wiz-pi.sh` (ACTION B)

---

---

## Chain 9 — WizCLI Token → forensics-package Cross-Tenant IDOR → High

**Components:** `prod-us52.forensics-package.app.wiz.io` (Lambda@Edge auth) + WizCLI Bearer token + guessable tenant/scan ID paths
**Probability:** Medium — forensic scan results are sensitive; path-based tenant isolation is a recurring class in CNAPP products
**Potential severity:** High (cross-tenant forensic data read — another tenant's cloud environment scan results)

**Architecture confirmed:**
- CloudFront WAF → blocks bots (bypassed with browser UA)
- Lambda@Edge → validates `Authorization: Bearer <token>` before routing to backend
- Backend likely S3 or internal API serving forensic scan packages by path

**How it works:**
1. Register Wiz trial account → run a WizCLI container scan: `wizcli container scan --image ...`
2. WizCLI authenticates to `forensics-package.app.wiz.io` to upload/retrieve scan package
3. Capture the Bearer token and path pattern from WizCLI network traffic (`mitmproxy` or `strace`)
4. Observe your own scan's path: likely `/packages/<your-tenant-id>/<scan-id>/result.json`
5. Substitute another tenant's ID (enumerate via GraphQL if accessible, or via sequential UUID guess)
6. Request cross-tenant path with your valid Bearer token:
   `GET /packages/<other-tenant-id>/<scan-id>/result.json`
   `Authorization: Bearer <your-valid-wiz-token>`
7. If Lambda@Edge validates only token authenticity (not tenant scope): cross-tenant read

**Key insight:** Lambda@Edge validates "is this a valid Wiz Bearer token?" but may NOT validate
"does this token's tenant match the tenant-id in the path?" — a classic authN vs authZ split bug.

**Escalation potential:**
- Forensic scan results contain: container filesystem contents, process lists, network connections, IaC configs, secrets found by scanner
- Cross-tenant read of another org's forensic data = Critical-level business impact even without code execution

**Setup needed:**
- Wiz trial account + WizCLI installed on Pi
- mitmproxy or Wireshark on Pi to capture WizCLI HTTP traffic
- A second trial account in a different tenant (friend's email) to generate a target scan

**Pi test commands (after getting token):**
```zsh
export WIZ_TOKEN="eyJ..."
export YOUR_TENANT_ID="<from-WizCLI-observed-path>"
export OTHER_TENANT_ID="<second-account-tenant>"

# Test your own path (baseline — should 200)
curl -sk -H "Authorization: Bearer $WIZ_TOKEN" \
  "https://prod-us52.forensics-package.app.wiz.io/packages/$YOUR_TENANT_ID/" | head -c 500

# Cross-tenant probe (the IDOR test)
curl -sk -H "Authorization: Bearer $WIZ_TOKEN" \
  "https://prod-us52.forensics-package.app.wiz.io/packages/$OTHER_TENANT_ID/" | head -c 500
```

---

## Chain 10 — events-ingestion Tenant Spoofing → Data Integrity / Confusion

**Components:** `events-ingestion.eu21.app.wiz.io` (API Gateway) + forged event payloads
**Probability:** Low-Medium — depends on event payload schema and server-side tenant validation
**Potential severity:** Medium (data integrity — injecting false security events into another tenant's Wiz instance)

**How it works:**
1. With trial auth token, POST a valid event to `/events`
2. Observe event payload schema — likely contains `tenant_id` or `org_id` field
3. Substitute another tenant's ID in the payload
4. If server trusts the client-supplied tenant ID without re-validating against the Bearer token: event injected into another org's security event stream
5. False positive injection or alert suppression = security product integrity violation

---

## Chain 11 — AI Remediation Cross-Tenant PR Injection / Action Runner (CRITICAL CANDIDATE)

**Source:** WizCLI binary strings extraction — embedded Go proto symbols from `github.com/wiz-sec/wiz/grpclib/rpc/ai` package (publicly downloadable binary)
**Components:** Wiz AI Remediation feature (gRPC `IssueRemediationResult`) + GitHub/GitLab connector + trial account
**Probability:** Medium-High — `repositoryId` + `scanId` + `patches` pattern is a classic cross-tenant IDOR; `inputJson` on `RunResponseAction` is a potential injection vector
**Potential severity:** Critical (cross-tenant code injection into victim's VCS repo via Wiz integration)
**Added:** 2026-06-14 (from WizCLI binary strings ACTION A output)

### What the binary reveals

The WizCLI binary embeds reflection data for these proto types at package `github.com/wiz-sec/wiz/grpclib/rpc/ai`:

```
IssueRemediationResult
  RemediationStep
    Action (one-of):
      CreateVcsRemediationIssue   (label, inputJson)
      RequestCustomPullRequest    (repositoryId, scanId, patches, inputJson)  ← HIGH VALUE
      RequestRemediationPullRequest (inputJson)
      RunResponseAction           (label, inputJson)                          ← INJECTION CANDIDATE
      UpdateIssue                 (label, inputJson)
      UpdateIssuesAssignee        (label, inputJson)
  Severity   (enum: GetReasoning, GetRecommendedSeverity, GetVerdict)
  Verdict    (enum)

PostureIssueRemediationResult
  FindingsCoverage (coveredFindings, totalFindingsCount)
  ConfidenceLevel (enum)
```

### Attack vector A — Cross-tenant PR injection via `RequestCustomPullRequest`

1. Register Wiz trial → connect your own GitHub repo → trigger AI remediation on a Wiz issue
2. Observe the GraphQL mutation that creates a remediation PR (capture with DevTools)
3. Extract `repositoryId` structure (likely a Wiz-internal UUID referencing a VCS integration)
4. Register second Wiz trial account (different tenant) → connect their GitHub repo
5. Using Account A's JWT, call the mutation with Account B's `repositoryId` + Account B's `scanId`
6. If Wiz validates JWT authenticity but NOT `repositoryId` tenant ownership → PR injected into Account B's repo with Account A's patches

**Why this matters:** Wiz has deep GitHub integration (full repo read+write for IaC remediation). A cross-tenant `repositoryId` bypass means an attacker can inject arbitrary code PRs into any Wiz customer's connected GitHub repo — supply chain attack at scale.

### Attack vector B — `RunResponseAction` inputJson injection

`RunResponseAction(label, inputJson)` takes raw JSON as input to execute arbitrary "response actions". If this JSON feeds into:
- A template engine → SSTI
- A subprocess call → command injection
- A GitHub API call → parameter injection into API payloads

Test: supply `{"action": "...", "param": "{{7*7}}"}` and `{"action": "'; sleep 5 #"}` to check for SSTI/injection.

### GraphQL probes (run with trial JWT)

```bash
# 1. Find AI remediation mutations in schema
gql_query '{ __schema { mutationType { fields { name description args { name type { name kind ofType { name kind } } } } } } }' \
  | python3 -c "import json,sys; fields=json.load(sys.stdin)['data']['__schema']['mutationType']['fields']; [print(f['name'],f.get('description','')) for f in fields if any(k in f['name'].lower() for k in ['remedi','action','pullrequest','pr','vcs','ai'])]"

# 2. Probe AI remediation query type
gql_query '{ __type(name: "RequestCustomPullRequestInput") { fields { name type { name kind } description } } }'
gql_query '{ __type(name: "RunResponseActionInput") { fields { name type { name kind } description } } }'
gql_query '{ __type(name: "IssueRemediationInput") { fields { name type { name kind } description } } }'

# 3. List your own VCS integrations (to get repositoryId format)
gql_query '{ vcsRepositories(first: 5) { nodes { id name url integration { id } } } }'
gql_query '{ connectors(first: 10, filterBy: { type: [GITHUB, GITLAB, BITBUCKET] }) { nodes { id name type } } }'
```

### Setup needed

- Wiz trial account + GitHub repo connected for IaC scanning
- Second trial account (different tenant, different GitHub repo)
- Capture `repositoryId` values from DevTools Network tab when AI remediation triggers

### Also: Package path disclosure

`github.com/wiz-sec/wiz/grpclib/rpc/ai` embedded in public binary confirms:
- Wiz monorepo lives at `github.com/wiz-sec/wiz` (private, out of scope to access)
- gRPC is used for internal AI service communication
- This is informational value (confirms architecture) but not itself reportable

---

---

## Chain 12 — Cognito + Auth0 Dual Auth → JWT Audience Confusion (NEW — from HTML config)

**Source:** `app.wiz.io` SPA HTML `environment-variables-config` block
**Components:** `VITE_APP_COGNITO_AUDIENCE: "wiz-api"` + Auth0 login flow
**Probability:** Low-Medium — dual auth systems are a well-known attack surface; depends on whether backend accepts both issuers
**Potential severity:** Critical (auth bypass → unauthenticated GraphQL API access)
**Added:** 2026-06-14

### What was found

The Wiz portal HTML embeds this production config at every path (SPA pattern):
```json
"VITE_APP_COGNITO_AUDIENCE": "wiz-api"
```
Alongside `VITE_APP_AUTH_URL: "https://auth.app.wiz.io"` which resolves to an AWS ELB.

The login UI presents an email challenge flow (not a standard Auth0 OIDC redirect), suggesting a custom auth layer. The backend API (`api.*.app.wiz.io/graphql`) validates JWT tokens with `aud: wiz-api`. If the backend validates ONLY the audience claim and NOT the issuer (`iss`), a self-signed JWT or a Cognito JWT from a different user pool claiming `aud: wiz-api` might be accepted.

### Also extracted from config

| Asset | Value | Action |
|-------|-------|--------|
| `wizio-public.s3.amazonaws.com` | Public S3 bucket | Check listing → `curl https://wizio-public.s3.amazonaws.com/` |
| CloudFormation template | `s3://wizio-public/deployment-v2/aws/wiz-aws-standard-org.json` | Fetch → analyze IAM permissions |
| LaunchDarkly client ID | `5f2bbaa730af0f08855ad7e9` | Enumerate all feature flags (hidden features) |
| Sentry DSN | `https://09635e866c684...@o454224.ingest.sentry.io/5443862` | Client-side, informational |
| Datadog RUM token | `pub4e58628c5a89e58041122368f7acc277` | Client-side, informational |
| App version | `4553dc648e2ab5a5a90cd26d4fd2eabe2209f0c2` | Live git commit hash |

### LaunchDarkly feature flag enumeration

```bash
# From Pi — enumerate all flags with LD client ID
curl -s "https://clientsdk.launchdarkly.com/sdk/evalx/5f2bbaa730af0f08855ad7e9/users/eyJrZXkiOiJ0ZXN0In0=" \
  | python3 -m json.tool 2>/dev/null
```

Flags of interest: any flag named `*admin*`, `*internal*`, `*debug*`, `*bypass*`, `*dev*`, `*beta*` that is `false` in production — may have different value in test/fedRAMP environment, revealing gated features with potentially weaker auth.

### S3 bucket analysis

```bash
# Check public bucket listing
curl -s "https://wizio-public.s3.amazonaws.com/" | python3 -c "import sys; [print(l) for l in sys.stdin if 'Key' in l or 'Contents' in l or 'Error' in l]"

# Fetch CloudFormation template — analyze IAM permissions Wiz requests
curl -s "https://wizio-public.s3.amazonaws.com/deployment-v2/aws/wiz-aws-standard-org.json" \
  | python3 -m json.tool | grep -A3 '"Action"' | head -80
```

If CloudFormation template contains `"Action": "*"` or overly permissive `iam:*` → reportable misconfiguration.

---

## Chain 13 — CopyResourceForensicsToExternalAccount → Cross-Tenant Forensic Data Exfil (CRITICAL)

**Source:** `graphqlTypes-N1XN-ltn.js` production bundle (line 28335) — confirmed in live schema
**Mutation:** `mutation CopyResourceForensicsToExternalAccount($input: CopyResourceForensicsToExternalAccountInput!)`
**Probability:** High — the mutation explicitly copies data cross-account; IDOR likely if `resourceId` not tenant-scoped
**Potential severity:** Critical (cross-tenant forensic data → attacker external account)
**Added:** 2026-06-14

### What this does

Copies forensic scan data (container filesystems, process lists, network connections, IaC configs, secrets found by scanner) from a cloud resource to an external account supplied by the caller. Designed for customers to export their own forensics. **IDOR risk:** if `resourceId` is not validated against the calling JWT's tenant, attacker copies another tenant's data.

```bash
# Probe input fields
gql_query '{"query":"{ __type(name: \"CopyResourceForensicsToExternalAccountInput\") { inputFields { name type { name kind } } } }"}'
# List your resources (baseline)
gql_query '{"query":"{ cloudResources(first: 5) { nodes { id name type } } }"}'
# Then substitute other tenant resourceId with your JWT → Critical if 200
```

---

## Chain 14 — CreateMemberTenantRequest → Unauthorized MSSP Tenant Access

**Source:** `graphqlTypes-N1XN-ltn.js` — `mutation CreateMemberTenantRequest` + `fragment MemberTenantRequestFields`
**Probability:** Medium — depends on whether target tenant auto-approves or must accept
**Potential severity:** Critical (unauthorized access to another customer's Wiz admin panel)
**Added:** 2026-06-14

### What this does

Wiz has an MSSP (Managed Service Provider) feature. `CreateMemberTenantRequest` sends a request to become the manager of another Wiz tenant. Fields: `id`, `name`, `location`, `dataCenter`, `status`.

**Attack:** Does the target tenant need to explicitly approve? If not (auto-accept) or if approval notification is spoofable → attacker gains admin visibility into any Wiz customer's cloud environment.

```bash
gql_query '{"query":"{ __type(name: \"CreateMemberTenantRequestInput\") { inputFields { name type { name } } } }"}'
```

---

## Priority Matrix (updated 2026-06-14 — graphqlTypes bundle confirmed)

| Chain | Priority | Mutation Confirmed | Blocker |
|-------|----------|--------------------|---------|
| **13 — CopyResourceForensics cross-tenant exfil** | **P0** | `CopyResourceForensicsToExternalAccount` | Trial + 2nd account |
| **14 — CreateMemberTenantRequest MSSP access** | **P0** | `CreateMemberTenantRequest` | Trial account |
| **11 — AI Remediation cross-tenant PR injection** | **P0** | `RequestRemediationPullRequest`, `FindingPullRequestRemediation` | Trial + VCS + 2nd account |
| **12 — JWT audience confusion (Cognito vs Auth0)** | **P0** | all mutations | Trial JWT to test |
| 3 — Webhook SSRF → Grafana | P0 | `WebhookIntegrationParams` confirmed | Trial account |
| 4 — GraphQL cross-tenant IDOR | P0 | `issueId`/`scanId`/`resourceId` params | Trial + 2nd account |
| 9 — forensics-package cross-tenant IDOR | P0 | HTTP-level (not GraphQL) | WizCLI token + 2nd account |
| RunResponseAction injection | P1 | `RunResponseActionFix` (`inputJson`) | Trial account |
| 1 — F001 → CSP bypass | P1 | — | Pi ACTION C |
| 2 — F001 → OAuth hijack (FedRAMP) | P1 | — | Pi probe |
| 10 — events-ingestion tenant spoof | P1 | — | Trial account |
| LD flag → hidden API feature access | P2 | — | No account needed |
| S3 wizio-public / CloudFormation IAM | P2 | — | No account needed |
| 7 — dynamic-dns-checker SSRF | P2 | — | Pi probe |
| 8 — PR preview introspection | P2 | — | Pi ACTION B |
| 6 — Ghost CMS key | P3 | — | Pi ACTION D |
