# Pi Runbook — Marriott Session 1
# Goal: Fingerprint all priority targets, enumerate wildcards, probe DEV/TEST envs
# Date: 2026-06-21
# Scope: config/marriott-scope.yaml
# Scope check: SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml ~/bug-bounty-hunting-/scripts/scope-check.sh <host>

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/gorib/go/bin:/home/gorib/.pdtm/go/bin:/home/gorib/.local/bin
BB="${BB:-$HOME/bug-bounty-hunting-}"
mkdir -p "$HOME/hunt"
cd "$HOME/hunt"

# ============================================================
# PHASE A — HTTP fingerprint all Critical/High priority targets
# ============================================================

section() { echo -e "\n\033[1;36m━━━ $* ━━━\033[0m"; }
chk() {
  local h="$1"
  echo -n "  $h: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | redirect=%{redirect_url}\n" "https://$h/"
}

section "PHASE A — Critical asset HTTP fingerprint"
for H in \
  sso.marriott.com \
  psp.marriott.com \
  gatewaydsapdev2.marriott.com \
  gatewaydsaptst1.marriott.com \
  gatewaydsaptst2.marriott.com \
  dcfgatewaytst1.marriott.com \
  lawmanager.marriott.com \
  passwordchallenge.marriott.com \
  mgs.marriott.com \
  marrtool.com \
  marriottfranchisetransactions.marriott.com \
  esupplier.marriott.com \
  cpp.marriott.com \
  homes-and-villas.marriott.com \
  all-inclusive.marriott.com \
  editionhotels.com \
  www.ritzcarlton.com \
  auth-apc.marriott.com \
  apcgateway.marriott.com \
  wechat.api.marriott.com \
  traveler.marriott.com \
  mipartnerprivileges.marriott.com \
  ifast.marriott.com \
  efast.marriott.com \
  eidhelp.marriott.com \
  device.marriott.com \
  bpa2.marriott.com \
  activities.marriott.com \
  owa.marriott.com \
  oasisprod.marriott.com \
  contentportalauth.marriott.com \
  contentportal.marriott.com \
  ci-propertyconversionportal.marriott.com \
  ssm-marriottms.saviyntcloud.com; do
  chk "$H"
done

# ============================================================
# PHASE B — Wildcard subdomain enumeration (fresh surface)
# ============================================================
# FIX: crt.sh query format for in-scope wildcard patterns:
#   "*.gateway.marriott.com" (3rd-level) → query: %25.gateway.marriott.com
#   "gateway*.marriott.com"  (2nd-level) → query: %25gateway%25.marriott.com
#   "*gateway-apc.marriott.com"          → query: %25gateway-apc.marriott.com
#   "*uat.marriott.com"                  → query: %25uat.marriott.com

section "PHASE B — Wildcard subdomain enum"

HUNTDIR="$HOME/hunt"

ct_query() {
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
except: pass
" 2>/dev/null | sort -u >> "$outfile"
  echo "$(wc -l < "$outfile" 2>/dev/null || echo 0) entries"
}

# Correct patterns per scope wildcard entries:
ct_query "gateway*.marriott.com"       "%25gateway%25.marriott.com"         "$HUNTDIR/ct-gateway.txt"
ct_query "*gateway-apc.marriott.com"   "%25gateway-apc.marriott.com"        "$HUNTDIR/ct-gateway-apc.txt"
ct_query "*uat.marriott.com"           "%25uat.marriott.com"                 "$HUNTDIR/ct-uat.txt"
ct_query "*.apigwc.marriott.com"       "%25.apigwc.marriott.com"             "$HUNTDIR/ct-apigwc.txt"
ct_query "*.apigatewayc.marriott.com"  "%25.apigatewayc.marriott.com"        "$HUNTDIR/ct-apigatewayc.txt"
ct_query "*.dcfgateway.marriott.com"   "%25.dcfgateway.marriott.com"         "$HUNTDIR/ct-dcfgateway.txt"
ct_query "*.artifactory.marriott.com"  "%25.artifactory.marriott.com"        "$HUNTDIR/ct-artifactory.txt"
ct_query "*.mgs.marriott.com"          "%25.mgs.marriott.com"                "$HUNTDIR/ct-mgs.txt"
ct_query "*.sba.marriott.com"          "%25.sba.marriott.com"                "$HUNTDIR/ct-sba.txt"
# Also broad marriott.com sweep (aggressive — may return many results)
ct_query "all *.marriott.com"          "%25.marriott.com"                    "$HUNTDIR/ct-all-marriott.txt"

echo ""
echo "=== CT results summary ==="
for F in "$HUNTDIR"/ct-*.txt; do
  echo "  $(basename "$F"): $(wc -l < "$F" 2>/dev/null || echo 0) subs"
done

echo ""
echo "=== Gateway-pattern subdomains found ==="
cat "$HUNTDIR/ct-gateway.txt" 2>/dev/null
echo ""
echo "=== UAT environments found ==="
cat "$HUNTDIR/ct-uat.txt" 2>/dev/null
echo ""
echo "=== Artifactory instances found ==="
cat "$HUNTDIR/ct-artifactory.txt" 2>/dev/null
echo ""
echo "=== API Gateway subdomains found ==="
cat "$HUNTDIR/ct-apigwc.txt" "$HUNTDIR/ct-apigatewayc.txt" 2>/dev/null | sort -u
echo ""
echo "=== Previously unknown Marriott subdomains (from broad sweep) ==="
cat "$HUNTDIR/ct-all-marriott.txt" 2>/dev/null | grep -v -f <(
  # Filter out already-known in-scope list
  grep -E "^\s+-\s+\"" "$BB/config/marriott-scope.yaml" | sed "s/.*\"\(.*\)\".*/\1/" | grep "\."
) | head -50

# Resolve live CT-discovered hosts (probe which are alive)
echo ""
echo "=== Resolving discovered subdomains ==="
for F in "$HUNTDIR"/ct-gateway.txt "$HUNTDIR"/ct-uat.txt "$HUNTDIR"/ct-artifactory.txt \
         "$HUNTDIR"/ct-apigwc.txt "$HUNTDIR"/ct-apigatewayc.txt; do
  [ -f "$F" ] || continue
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    IP=$(dig +short "$host" A 2>/dev/null | grep -E "^[0-9]" | head -1)
    if [ -n "$IP" ]; then
      CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "https://$host/" 2>/dev/null)
      echo "  LIVE: $host → $IP | HTTP $CODE"
    fi
  done < "$F"
done

# ============================================================
# PHASE C — DEV/TEST Gateway deep probe (SAP + generic)
# ============================================================

section "PHASE C — DEV/TEST Gateway deep probe"

for GW in gatewaydsapdev2.marriott.com gatewaydsaptst1.marriott.com dcfgatewaytst1.marriott.com; do
  echo "=== $GW ==="
  
  # Server header fingerprint
  curl -sk --max-time 10 -I "https://$GW/" 2>&1 | grep -iE "^(server|x-powered|content-type|x-frame|location|www-authenticate)" | head -10
  
  # SAP paths (DSP/OData)
  for PATH in \
    / /ping /health /healthz /status /metrics \
    /actuator /actuator/info /actuator/env /actuator/health /actuator/heapdump \
    /swagger-ui.html /swagger-ui /v2/api-docs /v3/api-docs /openapi.json /openapi.yaml \
    /api /api/v1 /api/v2 /api/v3 \
    /sap/opu/odata/ /sap/bc/ /sap/public/ \
    /odata/v1/ /odata/v2/ /odata/v4/ \
    /rest/v1/ /rest/api/ \
    /.env /.git/HEAD /robots.txt /sitemap.xml \
    /debug /console /trace /info \
    /management /management/health /management/info \
    /WEB-INF/web.xml /web.config \
    /api/login /api/auth /auth /login \
    /graphql /graphiql; do
    echo -n "  $PATH: "
    curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$GW$PATH"
  done
  echo ""
done

# ============================================================
# PHASE D — Artifactory discovery and anonymous access
# ============================================================

section "PHASE D — Artifactory"

# Probe known Artifactory subdomain patterns
for SUBD in \
  artifactory \
  repo \
  repos \
  artifacts \
  registry \
  nexus \
  jfrog \
  jfrog-artifactory \
  artifacts.marriott \
  docker; do
  HOST="${SUBD}.artifactory.marriott.com"
  echo -n "  $HOST: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | redirect=%{redirect_url}\n" "https://$HOST/"
done

# Also try direct artifactory subdomain patterns at marriott.com
for SUBD in \
  artifactory \
  nexus \
  repo \
  registry \
  jfrog; do
  HOST="${SUBD}.marriott.com"
  echo -n "  $HOST: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$HOST/"
done

# From subdomain enum results (populated in Phase B)
if [ -f /home/gorib/hunt/marriott-subs-artifactory-marriott-com.txt ]; then
  echo ""
  echo "  Probing enumerated artifactory subdomains:"
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    echo -n "  $host: "
    curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$host/"
  done < /home/gorib/hunt/marriott-subs-artifactory-marriott-com.txt
fi

# If any Artifactory instance found (200/302), test anonymous API:
# Replace ARTIHOST with actual discovered host
ARTIHOST="artifactory.marriott.com"  # update when found
echo ""
echo "  Testing Artifactory anonymous API on $ARTIHOST:"
for APATH in \
  /artifactory/api/system/ping \
  /artifactory/api/repositories \
  /artifactory/api/storageinfo \
  /api/system/ping \
  /api/repositories \
  /ui/api/v1/ui/repos \
  /artifactory/webapp/#/home; do
  echo -n "  $APATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$ARTIHOST$APATH"
done

# ============================================================
# PHASE E — API Gateway cluster probe
# ============================================================

section "PHASE E — API Gateway cluster"

# From subdomain enum results (populated in Phase B)
for GFILE in \
  /home/gorib/hunt/marriott-subs-apigwc-marriott-com.txt \
  /home/gorib/hunt/marriott-subs-apigatewayc-marriott-com.txt \
  /home/gorib/hunt/marriott-subs-dcfgateway-marriott-com.txt \
  /home/gorib/hunt/marriott-subs-gateway-marriott-com.txt; do
  [ -f "$GFILE" ] || continue
  echo "  From: $GFILE ($(wc -l < "$GFILE") hosts)"
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    R=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{size_download}" "https://$host/")
    echo "  $host: $R"
  done < "$GFILE"
done

# Probe live gateway hosts for SSRF + auth bypass
# (update GWHOST to any live host found above)
GWHOST="gateway.marriott.com"
echo ""
echo "  Gateway API probe on $GWHOST:"
for GPATH in \
  /health /healthz /ping /status \
  /api /api/v1 /api/v2 \
  /v1 /v2 /v3 \
  /openapi.json /swagger.json \
  /actuator /actuator/env \
  /admin /internal \
  /metrics /prometheus; do
  echo -n "  $GPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://$GWHOST$GPATH"
done

# CORS check on any live gateway
curl -sk --max-time 10 \
  -H "Origin: https://attacker.com" \
  -I "https://$GWHOST/api/v1" 2>&1 | grep -i "access-control"

# ============================================================
# PHASE F — Auth surface: SSO, auth-apc, passwordchallenge
# ============================================================

section "PHASE F — Auth/SSO surface"

for AUTH_HOST in sso.marriott.com auth-apc.marriott.com passwordchallenge.marriott.com; do
  echo "=== $AUTH_HOST ==="
  
  # OIDC discovery
  echo -n "  /.well-known/openid-configuration: "
  OIDC=$(curl -sk --max-time 10 "https://$AUTH_HOST/.well-known/openid-configuration")
  echo "$OIDC" | python3 -m json.tool 2>/dev/null | head -20 || echo "(not JSON)"
  
  # OIDC from root
  echo -n "  /.well-known/oauth-authorization-server: "
  curl -sk --max-time 10 "https://$AUTH_HOST/.well-known/oauth-authorization-server" | python3 -m json.tool 2>/dev/null | head -10 || echo "(not JSON)"
  
  # Key routes
  for RPATH in / /login /logout /auth /authorize /token /introspect /userinfo \
    /saml/SSO /saml/metadata /sso /sso/login /oauth2 /oauth2/authorize \
    /api/v1/authn /api/v1/sessions /api/v1/users; do
    echo -n "  $RPATH: "
    curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | redirect=%{redirect_url}\n" "https://$AUTH_HOST$RPATH"
  done
  echo ""
done

# ============================================================
# PHASE G — Saviynt IAM and OWA
# ============================================================

section "PHASE G — IAM + OWA"

echo "=== Saviynt IAM: ssm-marriottms.saviyntcloud.com ==="
curl -sv --max-time 12 "https://ssm-marriottms.saviyntcloud.com/" 2>&1 | grep -E "^[<>* ]" | head -20
echo ""
for SPATH in / /api /api/v1 /api/v5 \
  /ECM/api/v5/role \
  /ECM/api/v5/users \
  /ECM/api/v5/access \
  /ECM/api/v5/account \
  /ECM/login /ECM/saml/idpinit \
  /health /swagger-ui.html; do
  echo -n "  $SPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://ssm-marriottms.saviyntcloud.com$SPATH"
done

echo ""
echo "=== OWA: owa.marriott.com ==="
# NTLM hash disclosure via autodiscover
curl -sk --max-time 10 -I "https://owa.marriott.com/" 2>&1 | grep -iE "^(server|www-auth|x-owa|location|ms-asdevicetype)"
for OPATH in / /owa /owa/auth/logon.aspx \
  /autodiscover/autodiscover.xml \
  /EWS/Exchange.asmx \
  /Microsoft-Server-ActiveSync \
  /mapi \
  /rpc/rpcproxy.dll \
  /oab; do
  echo -n "  $OPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://owa.marriott.com$OPATH"
done

# NTLM disclosure probe (safe — just checks for WWW-Authenticate: NTLM header)
echo ""
echo "  NTLM disclosure check:"
curl -sk --max-time 10 \
  -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  -I "https://owa.marriott.com/EWS/Exchange.asmx" 2>&1 | grep -i "www-auth"

# ============================================================
# PHASE H — PSP and Financial targets
# ============================================================

section "PHASE H — PSP + Financial"

echo "=== PSP: psp.marriott.com ==="
curl -sv --max-time 12 "https://psp.marriott.com/" 2>&1 | grep -E "^[<>* ]" | head -20
for PPATH in / /api /api/v1 /api/v2 \
  /health /healthz /ping \
  /payments /transactions /sessions \
  /webhook /webhooks \
  /v1/payments /v1/customers \
  /swagger-ui.html /v2/api-docs \
  /robots.txt /.well-known/security.txt; do
  echo -n "  $PPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://psp.marriott.com$PPATH"
done

echo ""
echo "=== Franchise Transactions: marriottfranchisetransactions.marriott.com ==="
for FPATH in / /api /api/v1 /login /auth /dashboard \
  /transactions /payments /reports; do
  echo -n "  $FPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://marriottfranchisetransactions.marriott.com$FPATH"
done

echo ""
echo "=== Homes & Villas Channel Portal (multi-tenant IDOR) ==="
for HVPATH in / /api /api/v1 /channels /properties /listings \
  /api/v1/properties /api/v1/channels /api/v1/users \
  /channel-portal; do
  echo -n "  $HVPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://channel-portal.homes-and-villas.marriott.com$HVPATH"
done

# ============================================================
# PHASE I — marrtool.com investigation (unknown asset)
# ============================================================

section "PHASE I — marrtool.com investigation"

curl -sv --max-time 12 "https://marrtool.com/" 2>&1 | grep -E "^[<>* ]" | head -20
echo ""
echo "  WHOIS registrant:"
whois marrtool.com 2>/dev/null | grep -iE "registrant|admin|organization|email|creation|expir" | head -10
echo ""
for MPATH in / /login /admin /api /api/v1 /health /robots.txt /.well-known/security.txt; do
  echo -n "  $MPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://marrtool.com$MPATH"
done

# ============================================================
# DECISION GATE
# ============================================================
cat << 'DECISION'

━━━ DECISION GATE ━━━

After running above:

1. DEV gateways (Phase C):
   - 200 on /actuator/env → CRITICAL bug: environment variable disclosure (API keys/DB creds)
   - 200 on /swagger-ui.html or /v2/api-docs → HIGH: unauthenticated API docs, test all endpoints
   - 200 on /sap/opu/odata/ → SAP OData without auth → explore entity sets
   - 401 on /api/v1 → register account at main site, test with auth token

2. Artifactory (Phase D):
   - 200 on /artifactory/api/repositories → CRITICAL: anonymous repo access
   - JSON response with repo list → enumerate repos for sensitive artifacts
   - 302 to login → note login URL, check for guest access

3. API Gateways (Phase E):
   - Any 200 + JSON on /api or /health → alive, test auth bypass
   - 401 not 403 → register account, test with Bearer token
   - CORS: Access-Control-Allow-Origin: * → check what data is returned

4. Auth/SSO (Phase F):
   - OIDC discovery returns redirect_uris → check for bypass patterns
   - /saml/metadata returns XML → check for signature bypass
   - passwordchallenge: 200 on form → test email enumeration, token predictability

5. Saviynt (Phase G):
   - 200 on /ECM/api/v5/users → CRITICAL: user enumeration / IDOR
   - 302 to login → register, then test role IDOR

6. OWA (Phase G):
   - WWW-Authenticate: NTLM in response → NTLM hash disclosure: follow OWA NTLM disclosure PoC
   - /autodiscover returns 200 with XML → check for internal host info

7. PSP (Phase H):
   - 200 on /api/v1 or /payments → explore further with test account
   - 200 on /swagger-ui → document all endpoints, test payment flow

8. marrtool.com (Phase I):
   - Confirm Marriott ownership via WHOIS + domain.administrator@marriott.com
   - If admin tool → probe all endpoints for auth bypass

DECISION

# ============================================================
# SAVE OUTPUT
# ============================================================
echo ""
echo "Save all output: tee /home/gorib/hunt/marriott-session1-output.txt"
echo "Then commit: cd ~/bug-bounty-hunting- && git add results/marriott/ && git commit -m 'marriott: session 1 recon output'"
