# Pi Runbook — Marriott Session 2
# Goal: Active HTTP probe of raw EC2 (no WAF) + APC cluster + DEV gateways + CT wildcard enum
# Date: 2026-06-21
# Based on: Recon Session 1 findings (RECON-SESSION1.md)
# Scope: config/marriott-scope.yaml
# Scope check: SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml ~/bug-bounty-hunting-/scripts/scope-check.sh <host>

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin
BB="${BB:-$HOME/bug-bounty-hunting-}"
mkdir -p "$HOME/hunt"
cd "$HOME/hunt"
RESULTS="$BB/results/marriott"
OUTDIR="$RESULTS/session2"
mkdir -p "$OUTDIR"

section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }
probe() {
  local h="$1" path="${2:-/}"
  echo -n "  https://$h$path: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | redir=%{redirect_url}\n" "https://$h$path"
}
hdr() {
  local h="$1"
  echo "  --- $h headers ---"
  curl -sk --max-time 10 -I "https://$h/" 2>&1 | grep -iE "^(server|x-powered-by|content-type|location|www-authenticate|x-frame-options|x-amz|cf-ray|x-akamai|via)" | head -10
}

exec > >(tee "$OUTDIR/session2-output.txt") 2>&1
echo "=== Marriott Session 2 — $(date) ==="

# ============================================================
# PHASE 1 — CT LOG WILDCARD ENUMERATION (fill the gaps)
# Run these FIRST — they feed later phases
# ============================================================

section "PHASE 1 — CT Log Wildcard Enum"

ct_enum() {
  local label="$1" pattern="$2" outfile="$3"
  echo -n "  crt.sh [$label]: "
  curl -sk --max-time 45 "https://crt.sh/?q=${pattern}&output=json" \
    | python3 -c "
import sys,json
try:
    seen=set()
    for e in json.load(sys.stdin):
        for n in e.get('name_value','').split('\n'):
            n=n.strip().lstrip('*. ')
            if n and '.' in n and n not in seen:
                seen.add(n); print(n.lower())
except Exception as ex:
    import sys; print(f'# error: {ex}', file=sys.stderr)
" 2>/dev/null | sort -u >> "$outfile"
  echo "$(wc -l < "$outfile" 2>/dev/null || echo 0) subs"
}

# Correct crt.sh patterns (% = wildcard in crt.sh; %25 = URL-encoded %):
#   *.sub.marriott.com   → %25.sub.marriott.com  (third-level subdomains)
#   gateway*.marriott.com → %25gateway%25.marriott.com  (prefix match at 2nd level)
ct_enum "*.apigwc.marriott.com"       "%25.apigwc.marriott.com"        "$OUTDIR/ct-apigwc.txt"
ct_enum "*.apigatewayc.marriott.com"  "%25.apigatewayc.marriott.com"   "$OUTDIR/ct-apigatewayc.txt"
ct_enum "*.dcfgateway.marriott.com"   "%25.dcfgateway.marriott.com"    "$OUTDIR/ct-dcfgateway.txt"
ct_enum "gateway*.marriott.com"       "%25gateway%25.marriott.com"     "$OUTDIR/ct-gateway.txt"
ct_enum "*gateway-apc.marriott.com"   "%25gateway-apc.marriott.com"    "$OUTDIR/ct-gateway-apc.txt"
ct_enum "*uat.marriott.com"           "%25uat.marriott.com"             "$OUTDIR/ct-uat.txt"
ct_enum "*.artifactory.marriott.com"  "%25.artifactory.marriott.com"   "$OUTDIR/ct-artifactory.txt"
ct_enum "*.sba.marriott.com"          "%25.sba.marriott.com"           "$OUTDIR/ct-sba.txt"
ct_enum "*.mgs.marriott.com"          "%25.mgs.marriott.com"           "$OUTDIR/ct-mgs.txt"

echo ""
echo "=== UAT environments discovered ==="
cat "$OUTDIR/ct-uat.txt" 2>/dev/null || echo "(none)"
echo ""
echo "=== API Gateway subdomains ==="
cat "$OUTDIR/ct-apigwc.txt" "$OUTDIR/ct-apigatewayc.txt" 2>/dev/null | sort -u || echo "(none)"
echo ""
echo "=== Artifactory instances ==="
cat "$OUTDIR/ct-artifactory.txt" 2>/dev/null || echo "(none)"

# Resolve CT-discovered subdomains that are in wildcard scope
for CTF in "$OUTDIR"/ct-*.txt; do
  [ -f "$CTF" ] || continue
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    IP=$(dig +short "$host" A 2>/dev/null | head -1)
    [ -z "$IP" ] && continue
    echo "  LIVE: $host → $IP"
  done < "$CTF"
done

# ============================================================
# PHASE 2 — RAW EC2 HOSTS (No WAF — highest direct exposure)
# ============================================================

section "PHASE 2 — Raw EC2 Hosts (No WAF)"

echo "NOTE: These hosts have NO Akamai/CloudFront WAF — payloads reach server unfiltered"
echo ""

# --- esupplier.marriott.com [3.219.138.243] Critical, 0 reports ---
echo "=== esupplier.marriott.com [Critical, 0 reports, DIRECT EC2] ==="
hdr "esupplier.marriott.com"
echo ""
for PATH in / /login /admin /supplier /api /api/v1 /api/v2 \
  /health /healthz /ping /status /actuator /actuator/health /actuator/env \
  /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json \
  /suppliers /invoices /purchase-orders /orders \
  /robots.txt /.well-known/security.txt /.env /.git/HEAD \
  /graphql /graphiql /console /debug /trace; do
  probe "esupplier.marriott.com" "$PATH"
done

# Port scan (naabu — no WAF, direct EC2)
echo ""
echo "  Port scan: 3.219.138.243"
naabu -host 3.219.138.243 -p 80,443,8080,8443,8000,8001,8008,8090,9000,9090,9200,9300,3000,4000,5000,6000,7000,8888 \
  -silent -rate 50 -timeout 5 2>/dev/null | tee "$OUTDIR/esupplier-ports.txt"

# --- device.marriott.com [54.243.246.159] High, 0 reports ---
echo ""
echo "=== device.marriott.com [High, 0 reports, DIRECT EC2] ==="
hdr "device.marriott.com"
for PATH in / /login /admin /api /api/v1 \
  /health /actuator /actuator/env \
  /swagger-ui.html /v2/api-docs \
  /mdm /devices /enroll /enrollment \
  /profiles /configuration /certificates \
  /robots.txt /.env; do
  probe "device.marriott.com" "$PATH"
done

naabu -host 54.243.246.159 -p 80,443,8080,8443,8000,8443,9090,9000,5000,4443 \
  -silent -rate 50 -timeout 5 2>/dev/null | tee "$OUTDIR/device-ports.txt"

# --- marrtool.com [34.203.116.40] Critical, 1 report ---
echo ""
echo "=== marrtool.com [Critical, 1 report, DIRECT EC2] ==="

# First verify this is Marriott-owned (required by program rules)
echo "  WHOIS check (confirm Marriott ownership):"
whois marrtool.com 2>/dev/null | grep -iE "registrant|organization|admin|email|creation|registrar" | head -8

hdr "marrtool.com"
for PATH in / /login /admin /tool /api /api/v1 \
  /health /actuator /swagger-ui.html \
  /dashboard /reports /management \
  /robots.txt /.env /.git/HEAD; do
  probe "marrtool.com" "$PATH"
done

# --- marriottfranchisetransactions.marriott.com [54.204.97.74] Critical, 1 report ---
echo ""
echo "=== marriottfranchisetransactions.marriott.com [Critical, 1 report, DIRECT EC2] ==="
hdr "marriottfranchisetransactions.marriott.com"
for PATH in / /login /auth /transactions /payments /invoices /reports \
  /api /api/v1 /health /actuator /swagger-ui.html \
  /admin /dashboard /franchise /management; do
  probe "marriottfranchisetransactions.marriott.com" "$PATH"
done

# --- mgs.marriott.com [34.198.35.55] Critical, 3 reports ---
echo ""
echo "=== mgs.marriott.com [Critical, 3 reports, AWS EC2 multi-IP] ==="
hdr "mgs.marriott.com"
for PATH in / /login /api /api/v1 /api/v2 \
  /health /actuator /swagger-ui.html /v2/api-docs \
  /messages /groups /meetings /gateway \
  /robots.txt /.env; do
  probe "mgs.marriott.com" "$PATH"
done

# --- splunk-phantom-nlb.marriott.com [34.205.160.170] Low tier, DIRECT EC2 ---
echo ""
echo "=== splunk-phantom-nlb.marriott.com [DIRECT EC2, Low scope but Critical impact if exposed] ==="
echo "  NOTE: If Splunk SOAR admin is accessible externally → Critical finding"
hdr "splunk-phantom-nlb.marriott.com"
for PATH in / /login /admin \
  /console /ui /phantom \
  /rest/version /rest/ph_user \
  /api /api/v1 /health; do
  probe "splunk-phantom-nlb.marriott.com" "$PATH"
done

# Direct IP probe (bypasses Host-based routing)
echo ""
echo "  Direct IP probe: 34.205.160.170"
for PORTP in 443 8443 9999 8000 8080; do
  echo -n "  :$PORTP: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
    --resolve "splunk-phantom-nlb.marriott.com:$PORTP:34.205.160.170" \
    "https://splunk-phantom-nlb.marriott.com:$PORTP/"
done

# ============================================================
# PHASE 3 — APC Cluster Host-Header Routing Attack
# auth-apc + apcgateway + gateway-apc all resolve to 23.61.96.201
# Virtual host routing — test each hostname for different responses
# ============================================================

section "PHASE 3 — APC Cluster Host-Header Probe"

APC_IP="23.61.96.201"
echo "All three APC hosts resolve to: $APC_IP (Akamai)"
echo "Testing Host-header routing — compare responses per hostname"
echo ""

for APC_HOST in auth-apc.marriott.com apcgateway.marriott.com gateway-apc.marriott.com; do
  echo "=== Host: $APC_HOST ==="
  hdr "$APC_HOST"
  for PATH in / /login /auth /authorize /token /api /api/v1 /api/v2 \
    /health /healthz /ping /actuator \
    /swagger-ui.html /v2/api-docs \
    /oauth2 /oauth2/authorize \
    /.well-known/openid-configuration \
    /saml/metadata /saml/SSO \
    /gateway /proxy /forward \
    /robots.txt; do
    echo -n "  $PATH: "
    curl -sk --max-time 8 -H "Host: $APC_HOST" \
      -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
      "https://$APC_HOST$PATH"
  done
  echo ""
done

# Cross-host routing test — does auth-apc's backend respond to gateway-apc's Host?
echo "=== Host-header cross-routing test ==="
for REAL_HOST in auth-apc.marriott.com apcgateway.marriott.com; do
  for SPOOFED_HOST in auth-apc.marriott.com apcgateway.marriott.com gateway-apc.marriott.com; do
    [ "$REAL_HOST" = "$SPOOFED_HOST" ] && continue
    CODE=$(curl -sk --max-time 8 -H "Host: $SPOOFED_HOST" \
      -o /dev/null -w "%{http_code}" "https://$REAL_HOST/")
    echo "  real=$REAL_HOST spoofed=$SPOOFED_HOST → HTTP $CODE"
  done
done

# CORS check
echo ""
echo "=== CORS check on APC cluster ==="
curl -sk --max-time 10 \
  -H "Origin: https://attacker.com" \
  -H "Host: auth-apc.marriott.com" \
  -I "https://auth-apc.marriott.com/api/v1" 2>&1 | grep -i "access-control"

# ============================================================
# PHASE 4 — DEV Gateways (SAP/Spring Boot debug surface)
# ============================================================

section "PHASE 4 — SAP DEV Gateways"

for GW in gatewaydsapdev2.marriott.com gatewaydsapdev1.marriott.com gatewaydsaptst1.marriott.com gatewaydsaptst2.marriott.com; do
  echo "=== $GW ==="
  hdr "$GW"
  
  for PATH in / /ping /health /healthz /status \
    /actuator /actuator/health /actuator/info /actuator/env \
    /actuator/heapdump /actuator/threaddump /actuator/logfile \
    /actuator/metrics /actuator/beans /actuator/mappings \
    /swagger-ui.html /swagger-ui /v2/api-docs /v3/api-docs \
    /openapi.json /openapi.yaml /api-docs \
    /sap/opu/odata/ /sap/bc/ /sap/public/ \
    /odata/v1/ /odata/v2/ /odata/v4/ \
    /api /api/v1 /api/v2 /api/v3 \
    /rest/api/ /rest/v1/ \
    /.env /.git/HEAD /robots.txt \
    /debug /console /trace /info \
    /management /management/health \
    /login /auth /token \
    /graphql /graphiql; do
    echo -n "  $PATH: "
    curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
      "https://$GW$PATH"
  done
  
  # If any path returns 200 with JSON, dump it:
  echo ""
  echo "  Checking for JSON responses on /actuator:"
  RESP=$(curl -sk --max-time 10 -H "Accept: application/json" "https://$GW/actuator" 2>/dev/null)
  if echo "$RESP" | python3 -m json.tool >/dev/null 2>&1; then
    echo "  *** ACTUATOR JSON FOUND — CRITICAL ***"
    echo "$RESP" | python3 -m json.tool | head -30
  else
    echo "  (no JSON actuator)"
  fi
  echo ""
done

# ============================================================
# PHASE 5 — PSP Deep Probe
# ============================================================

section "PHASE 5 — PSP (Payment Service Provider)"

echo "=== psp.marriott.com ==="
curl -sv --max-time 12 "https://psp.marriott.com/" 2>&1 | grep -E "^[<>* ]" | head -20
echo ""
for PATH in / /api /api/v1 /api/v2 /v1 /v2 \
  /health /healthz /ping /status \
  /payments /payment /transactions /transaction \
  /sessions /session /checkout \
  /webhook /webhooks /callback \
  /customers /accounts \
  /swagger-ui.html /v2/api-docs /openapi.json \
  /robots.txt /.well-known/security.txt \
  /actuator /actuator/env; do
  probe "psp.marriott.com" "$PATH"
done

# Full verbose probe of any 200 endpoints
RESP_V1=$(curl -sk --max-time 10 "https://psp.marriott.com/api/v1" 2>/dev/null)
if echo "$RESP_V1" | python3 -m json.tool >/dev/null 2>&1; then
  echo ""
  echo "*** /api/v1 returned JSON — PURSUE ***"
  echo "$RESP_V1" | python3 -m json.tool | head -40
fi

# ============================================================
# PHASE 6 — Saviynt IAM (ssm-marriottms.saviyntcloud.com)
# ============================================================

section "PHASE 6 — Saviynt IAM"

SAVIYNT="ssm-marriottms.saviyntcloud.com"
echo "=== $SAVIYNT ==="
hdr "$SAVIYNT"
echo ""
# Saviynt API paths (from Saviynt ECM product documentation)
for PATH in / /ECM /ECM/login \
  /ECM/api/v5/user/getUser \
  /ECM/api/v5/role \
  /ECM/api/v5/roles \
  /ECM/api/v5/access \
  /ECM/api/v5/account \
  /ECM/api/v5/entitlement \
  /ECM/api/v5/request \
  /api /api/v1 /api/v5 \
  /ECM/saml/idpinit \
  /health /swagger-ui.html \
  /.well-known/openid-configuration; do
  echo -n "  $PATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
    "https://$SAVIYNT$PATH"
done

# If /ECM/api/v5/user/getUser returns 200 → unauthenticated user enumeration (Critical)
RESP=$(curl -sk --max-time 10 "https://$SAVIYNT/ECM/api/v5/user/getUser" 2>/dev/null)
if echo "$RESP" | python3 -m json.tool >/dev/null 2>&1; then
  echo ""
  echo "*** SAVIYNT API JSON WITHOUT AUTH — CRITICAL ***"
  echo "$RESP" | python3 -m json.tool | head -30
fi

# ============================================================
# PHASE 7 — OWA NTLM Hash Disclosure
# ============================================================

section "PHASE 7 — OWA Exchange (NTLM disclosure)"

echo "=== owa.marriott.com [162.130.196.138 Zscaler-CDN] ==="
hdr "owa.marriott.com"
echo ""

# Check what Exchange paths are accessible
for PATH in / /owa /owa/auth/logon.aspx \
  /autodiscover/autodiscover.xml \
  /EWS/Exchange.asmx \
  /EWS/Services.wsdl \
  /Microsoft-Server-ActiveSync \
  /mapi /oab /rpc/rpcproxy.dll; do
  echo -n "  $PATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" \
    "https://owa.marriott.com$PATH"
done

echo ""
echo "  NTLM disclosure check — sending NTLM negotiate token:"
# Safe probe: sends NTLM Type 1 (negotiate) message, reads WWW-Authenticate back
# If server responds with NTLM Type 2 (challenge), it leaks domain/server info
curl -sk --max-time 15 \
  -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  -I "https://owa.marriott.com/EWS/Exchange.asmx" 2>&1 \
  | grep -iE "www-auth|x-powered|server"

# Try autodiscover (internal host enumeration via SSRF in some configs)
echo ""
echo "  Autodiscover response:"
curl -sk --max-time 10 \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>test@marriott.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' \
  "https://owa.marriott.com/autodiscover/autodiscover.xml" \
  | python3 -m json.tool 2>/dev/null \
  || curl -sk --max-time 10 "https://owa.marriott.com/autodiscover/autodiscover.xml" | head -20

# ============================================================
# PHASE 7b — Salesforce Community Cloud (cpp.marriott.com)
# cpp.marriott.com redirects to cpp.marriott.com/s/ = Salesforce Experience Cloud
# Bug class: Salesforce Guest User Object Exposure (unauthenticated sObject API access)
# ============================================================

section "PHASE 7b — Salesforce (cpp.marriott.com)"

CPP="cpp.marriott.com"
echo "=== $CPP — Salesforce Community Cloud ==="
hdr "$CPP"
echo ""

# Test Salesforce API endpoints accessible without auth (Guest User)
# These are common Salesforce misconfiguration vectors
for SFPATH in \
  /s/ \
  /s/sfsites/aura \
  /aura \
  /auraFW/javascript/randomid/aura_prod.js \
  /services/data/ \
  /services/data/v55.0/ \
  /services/data/v55.0/sobjects/ \
  /services/data/v55.0/query/?q=SELECT+Id,Name+FROM+Account+LIMIT+5 \
  /services/apexrest/ \
  /services/oauth2/authorize \
  /services/oauth2/token \
  /guest/user \
  /lightning/r/Account/ \
  /s/login \
  /s/profile \
  /s/article/ \
  /robots.txt; do
  echo -n "  $SFPATH: "
  curl -sk --max-time 10 -o /dev/null \
    -w "HTTP %{http_code} | %{size_download}B\n" \
    "https://$CPP$SFPATH"
done

# Salesforce Aura API — test for Guest User data exposure
echo ""
echo "  Salesforce Aura descriptor test:"
AURA_RESP=$(curl -sk --max-time 15 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "message=%7B%22actions%22%3A%5B%7B%22id%22%3A%221%3Ba%22%2C%22descriptor%22%3A%22serviceComponent%3A%2F%2Fui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController%2FACTION%24getItems%22%2C%22callingDescriptor%22%3A%22UNKNOWN%22%2C%22params%22%3A%7B%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22unknown%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%7D&aura.pageURI=%2Fs%2F&aura.token=undefined" \
  "https://$CPP/s/sfsites/aura" 2>/dev/null)
echo "  Response size: ${#AURA_RESP} bytes"
echo "$AURA_RESP" | python3 -m json.tool 2>/dev/null | head -20 || echo "  (not JSON or empty)"

# Check if guest user can access standard objects via REST API
echo ""
echo "  Salesforce REST API guest test:"
curl -sk --max-time 15 \
  -H "Authorization: Bearer guest" \
  "https://$CPP/services/data/v55.0/sobjects/" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30 \
  || echo "  (auth required or no REST API access)"

# If /services/data/ returns anything → CRITICAL: data model exposed
DATA_RESP=$(curl -sk --max-time 10 "https://$CPP/services/data/" 2>/dev/null)
if echo "$DATA_RESP" | python3 -m json.tool >/dev/null 2>&1; then
  echo ""
  echo "  *** SALESFORCE REST API ACCESSIBLE — enumerate versions ***"
  echo "$DATA_RESP" | python3 -m json.tool
fi

echo ""
echo "  Decision: If Aura returns data objects → test SOQL injection via listView"
echo "  Decision: If /services/data/v55.0/sobjects/ returns sObject list → Guest User exposed"
echo "  Report class: Salesforce Guest User misconfiguration → unauthorized data access"

# ============================================================
# PHASE 8 — Live CT-discovered subdomains (from Phase 1)
# ============================================================

section "PHASE 8 — Live CT Discoveries HTTP probe"

echo "Probing any live subdomains discovered via CT logs in Phase 1:"

for CTF in "$OUTDIR"/ct-*.txt; do
  [ -f "$CTF" ] || continue
  PATTERN=$(basename "$CTF" .txt | sed 's/ct-//')
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    # Scope check
    SCOPE_RESULT=$(SCOPE_FILE="$BB/config/marriott-scope.yaml" "$BB/scripts/scope-check.sh" "$host" 2>/dev/null || echo "UNKNOWN")
    [[ "$SCOPE_RESULT" != *"IN-SCOPE"* ]] && continue
    
    echo -n "  [$PATTERN] $host: "
    curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$host/"
    
    # For any 200 response, do quick endpoint check
    CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "https://$host/" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      echo "  *** LIVE 200 on $host — checking common endpoints ***"
      for LPATH in /api /api/v1 /health /actuator /swagger-ui.html /admin /login; do
        echo -n "    $LPATH: "
        curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$host$LPATH"
      done
    fi
  done < "$CTF"
done

# ============================================================
# DECISION GATE
# ============================================================
cat << 'DECISION'

━━━ DECISION GATE — Session 2 ━━━

PURSUE immediately if:

  Raw EC2 hosts (Phase 2):
  - Any 200 on /actuator/env → Critical: env var disclosure (DB creds, API keys)
  - Any 200 on /swagger-ui.html or /api-docs → High: unauthenticated API docs
  - Any non-443/80 port open on port scan → investigate service
  - splunk-phantom-nlb 200 on /rest/ph_user or /console → Critical: SOAR admin exposure
  - mgs.marriott.com 200 on /api → 3 prior reports, find what was missed

  APC Cluster (Phase 3):
  - Different response sizes between hostnames on same path → virtual host routing leaks
  - auth-apc returns OIDC/SAML metadata → test redirect_uri bypass
  - CORS: Access-Control-Allow-Origin: * on auth endpoints → token leakage

  DEV Gateways (Phase 4):
  - ANY actuator endpoint returning JSON → Critical
  - /v2/api-docs returns OpenAPI spec → document all endpoints, test each for auth
  - /sap/opu/odata/ returning 200 → SAP OData without auth = Critical

  PSP (Phase 5):
  - 200 on any payment endpoint → test IDOR on transaction IDs
  - 401 on /api/v1 → register Marriott Bonvoy account, test with Bearer token

  Saviynt IAM (Phase 6):
  - Any 200 on /ECM/api/v5/* without auth → Critical: user/role data exposure
  - Login page accessible → test default credentials (admin/admin, admin/saviynt123)

  OWA (Phase 7):
  - WWW-Authenticate: NTLM in EWS response → follow NTLM hash disclosure PoC
  - Autodiscover returns internal server names → info disclosure chain

  CT discoveries (Phase 8):
  - Any UAT/test subdomain returning 200 → high priority, test all endpoints

DROP if:
  - Host returns consistent 403/404/302-to-login with no JSON body → auth-gated, need account
  - EC2 host only responds on 443 with generic login page → low attack surface
  - Splunk NLB only shows 404 on all paths → network-internal only

DECISION

echo ""
echo "=== Session 2 Complete: $(date) ==="
echo "Output saved to: $OUTDIR/session2-output.txt"
echo "Commit: cd ~/bug-bounty-hunting- && git add results/marriott/ && git commit -m 'marriott: session 2 active probe output'"
