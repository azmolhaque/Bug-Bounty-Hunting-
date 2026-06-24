# Next Hunt Session — Priority Queue
**Updated:** 2026-06-24
**Programs:** Google VRP (bughunters.google.com) + Marriott (HackerOne)

---

## Open Reports — Handle First

| Report | Program | Status | Action needed |
|--------|---------|--------|---------------|
| M002 #3817499 | Marriott HackerOne | OPEN | Post evidence supplement comment + 9 attachments (DONE — ready to post) |
| M018 #3816825 | Marriott HackerOne | CLOSED/SPAM | Post appeal comment + evidence attachments |
| VT F001 #523823039 | Google VRP | Submitted/New | Monitor — no action until triage responds |
| Wiz F001 #524181553 | Google VRP | **TRIAGING — P2** | Priority upgraded P4→P2 (2026-06-24). Component routed to Wiz product security team (3 hops). DO NOT comment — wait for triager response. |
| AppSheet F003 | Google VRP | Submitted | Monitor |

---

## Active Chains — Blocked Pending Account/Access

These are LIVE chains confirmed by recon. The only blocker is a trial/free account.

| # | Chain | Target | Blocker | EV if confirmed |
|---|-------|--------|---------|-----------------|
| **1** | Webhook SSRF → GCP IMDS | Wiz Chain 3 | Need Wiz trial account | Critical ($31K–$101K) |
| **2** | GraphQL cross-tenant IDOR | Wiz Chain 4 | Need Wiz trial + 2nd account | Critical ($31K+) |
| **3** | CopyResourceForensics IDOR | Wiz Chain 13 | Need Wiz trial + 2nd account | High ($13K–$31K) |
| **4** | 300+ connector SSRF → IMDS | Siemplify/Chronicle | Need Chronicle free trial | High ($13K–$31K) |
| **5** | Multi-org IDOR on threat intel | Mandiant Advantage | Need two trial orgs | High ($13K–$31K) |

**Immediate action: Sign up for Wiz trial at app.wiz.io.** All 3 Wiz chains can be tested in a single session with a trial account.

---

## Session A — Marriott Session 22 (Pi runbook ready)

**Goal:** Probe gatewaydsapuat2 + apcgateway for API exposure.
**Runbook:** `results/marriott/runbooks/PI-RUNBOOK-marriott-session8.md` covers psp + Aura chain.
**Session 22 specific targets** (next runbook to create):

```
gatewaydsapuat2.marriott.com   # UAT API gateway — check actuator, swagger, OPTIONS
apcgateway.marriott.com        # APC gateway — 503 in session 1; retry + path probe
```

**Bug classes:**
- Spring Boot Actuator: `/actuator`, `/actuator/env`, `/actuator/heapdump`
- OpenAPI/Swagger: `/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`
- SAP DSP paths: `/sap/opu/odata/`, `/sap/bc/rest/`
- Method confusion: GET vs POST auth differential

---

## Session B — Wiz Trial Account (sign up today)

**Sign up:** https://app.wiz.io/signup (free trial available)
**After signup, immediately test:**

### Chain 3 — Webhook SSRF

1. Login → Settings → Integrations → Webhooks → Create new
2. Set Webhook URL to: `http://169.254.169.254/latest/meta-data/` (AWS IMDS)
   or your interactsh OOB listener
3. Trigger a test notification
4. If OOB callback received from Wiz's IP range → SSRF confirmed
5. Then test: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
   with `Metadata-Flavor: Google` header injection via CRLF or redirect

### Chain 4 — GraphQL Cross-Tenant IDOR

1. Create Wiz trial Org A (account 1)
2. Create Wiz trial Org B (account 2 — different email)
3. Get Org A JWT from browser DevTools (Authorization header)
4. Enumerate finding IDs in Org A via GraphQL `issues(first: 5)`
5. Use Org A JWT to query Org B's finding IDs
6. `200 + Org B's data` = cross-tenant IDOR (Critical)

### Chain 13 — Forensics Package IDOR

1. In Org A: trigger a forensics collection (if available on trial)
2. Note the forensics package ID
3. Use Org B's token to fetch `forensicsPackage(id: <OrgA_ID>)`
4. Access = IDOR

---

## Session C — AppSheet Remaining Connector SSRF

**Recurring pattern:** OData (F002), Apigee (F003) both vulnerable. Untested:
- REST API data connector
- Salesforce connector (if available on free plan)
- MySQL/Postgres connector URL field

**Quick test (5 min each):**
```
App → Data → Add Source → [connector type]
→ Server URL: https://<interactsh-id>.oast.fun
→ Click Test Connection
→ OOB hit within 5 sec = SSRF confirmed → run Phase 4 evidence collection
```

If any connector triggers OOB → same evidence template as F002/F003.
File as F004 (same root cause, new connector surface).

---

## Session D — Photomath IDOR (needs desktop + expert account)

**Target:** `portal.photomath.net`
**Setup:**
1. Register as expert at portal.photomath.net (requires application)
   OR use taportal.photomath.net (Teacher Portal — open registration)
2. Login → Burp Suite intercept
3. Find integer user/quiz IDs in URLs or API calls
4. Test: substitute adjacent integer IDs — is another user's data returned?
5. `/expert-training/qualification-quiz/[N]` — increment N

**This needs a desktop session (Burp). Cannot run from Pi.**

---

## Session E — Nest *.phoenix.nest.com (internal host from CSP)

**Discovery:** `home.ft.nest.com` CSP contains `connect-src ... https://*.phoenix.nest.com:*`
This is an undocumented internal API host. **This is recon signal, not a confirmed bug.**

**Test:**
```bash
# DNS resolution
for sub in api app auth internal; do
  host "$sub.phoenix.nest.com"
done

# HTTP probe (scope-check first)
./scripts/scope-check.sh phoenix.nest.com
httpx -u https://api.phoenix.nest.com -td -sc -cl
```

If phoenix.nest.com resolves publicly: treat as a discovered asset, run Phase 1-2 recon.
It may be a staging/internal API with weaker auth.

---

## Priority Ranking

| Rank | Session | EV | Effort | Blocker |
|------|---------|----|--------|---------|
| 1 | **Post M002 + M018 to HackerOne** | Maximize existing reports | 30 min | None |
| 2 | **Wiz trial signup + Chain 3 SSRF** | $31K–$101K | 2 hr | Sign up |
| 3 | **Marriott Session 22** | $1K–$8K | 1 hr Pi | None |
| 4 | **AppSheet connector SSRF** | $7K–$13K | 30 min | None |
| 5 | **Nest phoenix.nest.com** | Unknown | 30 min | Scope check |
| 6 | **Siemplify trial** | $13K–$31K | 2 hr | Sign up |
| 7 | **Photomath portal IDOR** | $3K–$13K | 2 hr | Desktop + expert account |

---

## Hunt Thesis — Next 48 Hours

The highest-value unblocked work is **Wiz Chains 3/4/13** (a single trial account
unlocks three Critical/High candidates with confirmed attack surfaces). After that,
**AppSheet connector SSRF** is a 5-minute-per-connector test following a proven
recurring pattern — minimum-effort extension of submitted findings.

Marriott Session 22 runs in parallel on the Pi with no context switching cost.

The two submitted Google VRP reports (VT SSRF, Wiz takeover) are passive —
no action needed until triage responds.
