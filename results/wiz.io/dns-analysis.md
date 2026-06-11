# Wiz.io Recon Analysis — Phase 1 DNS (2026-06-11)
# Source: dnsx resolution output from Pi recon scan
# Status: SCAN IN PROGRESS (gau/wayback still running)

## Infrastructure Map (from DNS A records)

### Environment Structure Revealed
wiz.io uses a clear environment-naming convention:
- `.app.wiz.io`         → Production
- `.test.wiz.io`        → Testing
- `.stage.wiz.io`       → Staging
- `.demo.wiz.io`        → Demo
- `.e2e.wiz.io`         → End-to-end tests
- `.integration.wiz.io` → Integration testing
- `.integration2.wiz.io`→ Integration testing (v2)
- `.fedtest.wiz.io`     → FedRAMP testing
- `.fedint.wiz.io`      → FedRAMP internal
- `.fedstg1.wiz.io`     → FedRAMP staging
- `.gov.wiz.io`         → US Government (FedRAMP production)
- `.rde.wiz.io`         → Remote Development Environments (per-developer)

### Scale Observed
- US production tenants:  us1–us117 app.wiz.io
- EU production tenants:  eu1–eu32 app.wiz.io
- AP/CA/SA/ME/IL regions: present
- RDE environments:       on-demand-1 through on-demand-111 + named developer RDEs

---

## HIGH-PRIORITY FINDINGS

### [P0] Exposed Grafana instances — CHECK FOR DEFAULT CREDS / ANON ACCESS / SSRF
- `us1.grafana.wiz.io`          → 3.86.124.109 / 44.208.172.120 / 44.196.211.2
- `us2.grafana.wiz.io`          → 3.15.250.182 / 3.139.39.161 / 3.150.108.131
- `us1.grafana.test.wiz.io`     → 3.88.253.30 / 44.216.29.199 / 52.45.110.14
- `us1.grafana.fedtest.wiz.io`  → 56.137.199.246 / 56.137.91.117 / 3.31.176.74

**Why critical:** Grafana frequently exposed with:
  - Anonymous viewer access enabled (common misconfiguration)
  - Default credentials (admin/admin or admin/wiz)
  - SSRF via datasource plugin URL configuration (Grafana datasources can reach internal hosts)
  - Internal metric dashboards revealing architecture/secrets
**Next:** httpx probe → check /api/health, /login, /api/datasources (anon endpoint)

### [P0] Developer Personal RDE Environments — POTENTIALLY LESS HARDENED
- `webhooks.guy.goldenberg.rde.wiz.io`  → 51.17.56.203
- `webhooks.roey.dror-us.rde.wiz.io`    → 3.135.156.35
- `webhooks.roy5.rde.wiz.io`            → 51.16.126.69
- `webhooks.cfir.rde.wiz.io`            → 3.12.135.191
- `webhooks.or.bin.rde.wiz.io`          → 51.17.176.76
- `webhooks.on-demand-{N}.rde.wiz.io`   → 100+ on-demand environments
- `webhooks.bootstrap-rde-001.rde.wiz.io` → 13.62.170.141

**Why valuable:** Developer RDEs often have debug interfaces, less strict auth,
and expose internal APIs not visible in production. The named environments
(guy.goldenberg, roey.dror, roy5) are developer-specific — these may be running
test builds with debug flags.
**Next:** httpx probe for open ports, debug endpoints, swagger UI exposure

### [P1] WizCLI non-production endpoints
- `wizcli.e2e.wiz.io`        → 54.192.151.x (CloudFront)
- `wizcli.test.wiz.io`       → 54.192.151.x
- `wizcli.stage.wiz.io`      → 13.35.20.x
- `wizcli.demo.wiz.io`       → 54.192.151.x
- `wizcli.integration.wiz.io`→ 18.66.57.x
- `wizcli.integration2.wiz.io`→ 18.172.64.x

**Why valuable:** WizCLI is the command-line cloud scanner with deep IAM permissions.
Non-production endpoints may have relaxed auth or expose debug endpoints.
**Next:** GET /version, /health, check for unauthenticated API discovery

### [P1] Webhook infrastructure — PRIMARY SSRF TARGET
- 100+ regional webhook endpoints: `webhooks.{us/eu/ap/ca/sa/me/il}{N}.app.wiz.io`
- Also: integration/test/stage/e2e/demo/fedtest/gov variants

**Why valuable:** Webhook delivery services make outbound HTTP requests to
user-configured URLs. If the webhook configuration doesn't prevent SSRF,
a malicious URL (cloud metadata, internal service) gets requested server-side.
This is exactly hypothesis H1 (SSRF via connector configuration).
**Next:** Register a Wiz trial → configure a webhook integration → set URL to
Burp Collaborator / interactsh → trigger → observe if request comes from
these IPs.

### [P1] Internal project "Peach"
- `www.peach.wiz.io` → 34.149.87.45 (GCP! — post-acquisition Google infra)

**Why notable:** Hosted on GCP (post-acquisition), suggesting an internal project
migrated to Google infrastructure. The GCP IP may expose GCP metadata to SSRF.
**Next:** httpx probe → check response, headers, any exposed API

### [P2] Unknown services
- `unity.wiz.io`       → 13.225.5.x (CloudFront)
- `win.wiz.io`         → 64.239.123.1 (Fastly)
- `win-test.wiz.io`    → 64.239.123.65 (Fastly)
- `whatsnew.wiz.io`    → 52.85.118.x (CloudFront)

**win.wiz.io / win-test.wiz.io on Fastly:** Could be a Windows-specific agent
download endpoint or a Windows-focused integration.

### [P2] FedRAMP Government environment
- `webhooks.us1.gov.wiz.io` → 40.38.124.121 / 40.38.155.124
- `webhooks.us2.gov.wiz.io` → 160.1.109.84 / 52.222.20.201
- `tunnel.us1.fedint.wiz.io` → 3.30.147.234
- `workflows.us1.fedtest.wiz.io`
- `workflows.us2.fedtest.wiz.io`

**Note:** FedRAMP scope — likely a separate compliance boundary. Verify with
scope.yaml before any active testing (federal systems may have stricter rules).

### [P2] Developer Azure sandboxes
- `www.guysi.azure.dev.wiz.io`    → 13.75.66.141 (Azure, Southeast Asia)
- `www.guysiapp.azure.dev.wiz.io` → 13.75.66.141

Personal developer sandboxes on Azure. May expose test apps or internal tools.

### [P3] Email infrastructure
- `url3216.wiz.io` → 54.192.151.x (CloudFront — SendGrid email tracking)
- `view.email.wiz.io` → 159.92.145.239 (email view service)

---

## NEXT ACTIONS (in order)

1. **Let the scan finish** — wait for gau/waybackurls to complete, then httpx probe
   all discovered hosts. The Grafana endpoints are the highest priority.

2. **httpx the Grafana instances** (when scan completes):
   ```bash
   echo "us1.grafana.wiz.io
   us2.grafana.wiz.io
   us1.grafana.test.wiz.io
   us1.grafana.fedtest.wiz.io" | httpx -silent -status-code -title -follow-redirects
   ```

3. **Check Grafana for anon access:**
   ```bash
   curl -s https://us1.grafana.wiz.io/api/health
   curl -s https://us1.grafana.wiz.io/api/datasources
   curl -s https://us1.grafana.wiz.io/login
   ```

4. **httpx the RDE environments** (sampled):
   ```bash
   echo "webhooks.guy.goldenberg.rde.wiz.io
   webhooks.roey.dror-us.rde.wiz.io
   www.peach.wiz.io
   unity.wiz.io
   win.wiz.io
   win-test.wiz.io" | httpx -silent -status-code -title -follow-redirects
   ```

5. **Register a Wiz trial** → test SSRF via webhook configuration (Hypothesis H1)

6. **Scope-check all new hosts before active testing** (they are all *.wiz.io = IN-SCOPE)
