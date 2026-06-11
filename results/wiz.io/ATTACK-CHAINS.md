# Attack Chains — wiz.io
# Status: hypotheses ranked by probability × impact
# Updated: 2026-06-11

## Chain 1 — Subdomain Takeover → CSP Bypass → Critical (PENDING PI OUTPUT)

**Components:** F001 (win-test.wiz.io takeover) + CSP misconfiguration
**Probability:** Medium-High — CSP commonly references own subdomains
**Potential severity:** Critical (9.3+)

**How it works:**
1. Attacker claims win-test.wiz.io via Vercel (F001, already confirmed exploitable)
2. If win-test.wiz.io or `*.wiz.io` appears in www.wiz.io / app.wiz.io CSP `script-src`
3. Attacker serves malicious JS at win-test.wiz.io
4. www.wiz.io/app.wiz.io loads and executes that JS in origin context
5. Steal session cookies, capture keystrokes, exfiltrate tokens

**Validation step:** Run ACTION C on Pi → check CSP output in `results/03-vulns/csp-audit.txt`
**Script:** `scripts/phase3-wiz-pi.sh` (ACTION C)

---

## Chain 2 — Subdomain Takeover → OAuth redirect_uri Hijack → Critical

**Components:** F001 (win-test.wiz.io) + Auth0 OAuth misconfiguration
**Probability:** Low-Medium — Auth0 typically validates redirect_uri strictly, but test envs often don't
**Potential severity:** Critical (account takeover)

**How it works:**
1. Attacker claims win-test.wiz.io
2. Wiz uses Auth0 (`auth0.demo.wiz.io`, `auth0.e2e.wiz.io`) for SSO across portal + community
3. If `win-test.wiz.io` appears in any application's redirect_uri allowlist in Auth0
4. Craft OAuth link: `https://auth0.*.wiz.io/authorize?...&redirect_uri=https://win-test.wiz.io/callback`
5. Victim clicks link → Auth0 redirects with `?code=<auth_code>` to win-test.wiz.io
6. Attacker exchanges code for access token → full account takeover

**Validation steps:**
1. Run ACTION C: check if win-test.wiz.io in OAuth callback lists
2. Run `scripts/oauth-redirect-probe-wiz.sh`: test redirect_uri manipulation
3. Check Auth0 OIDC discovery: `https://auth0.demo.wiz.io/.well-known/openid-configuration`

**Note:** Even if Auth0 strict — check community.wiz.io, app.wiz.io, gh-109705.pr.test.wiz.io OAuth endpoints

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

## Priority Matrix

| Chain | Priority | Blocker |
|-------|----------|---------|
| 3 — Webhook SSRF → Grafana | P0 | Trial account needed |
| 4 — GraphQL IDOR | P0 | Trial account needed |
| 1 — F001 → CSP bypass | P1 | Pi ACTION C results |
| 2 — F001 → OAuth hijack | P1 | Pi probe results |
| 5 — WizCLI binary analysis | P1 | Pi ACTION A (run now) |
| 8 — PR preview introspection | P2 | Pi ACTION B (run now) |
| 7 — dynamic-dns-checker SSRF | P2 | Pi probe results |
| 6 — Ghost CMS key | P3 | Pi ACTION D (run now) |
