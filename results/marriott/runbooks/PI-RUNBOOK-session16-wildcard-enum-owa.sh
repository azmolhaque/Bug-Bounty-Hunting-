#!/usr/bin/env bash
# PI-RUNBOOK-session16-wildcard-enum-owa.sh
# Session 16 — Wildcard subdomain enumeration (M013) + OWA NTLM probe (M009) + efast auth type
#
# Context:
#   - M011 (ci-portal), M001 (esupplier), M007 (mgs), M005 (gatewaydsapdev2): ALL CLOSED
#   - Best remaining surfaces:
#       M013: *.apigwc, *.apigatewayc, *gateway-apc, *uat.marriott.com — untested wildcards
#       M009: owa.marriott.com — OWA/Exchange NTLM autodiscover (never probed)
#       NEW:  efast.marriott.com — 401/6834B CloudFront — auth type unknown
#       M008: APC cluster (auth-apc, gateway-apc) — 503/000, probe with explicit paths
#
# Strategy:
#   Phase A: CT log + crt.sh enum for wildcard scopes (no tools required, just curl+python)
#   Phase B: DNS brute-force common UAT/DEV prefix patterns on *.apigwc + *.apigatewayc
#   Phase C: HTTP probe all resolved subdomains — fingerprint + prioritize
#   Phase D: OWA NTLM autodiscover probe (GET-only, read-only — no credentials sent)
#   Phase E: efast.marriott.com — auth type fingerprint (NTLM? OAuth? SAML?)
#   Phase F: APC cluster Host-header routing probe
#
# Run: bash PI-RUNBOOK-session16-wildcard-enum-owa.sh 2>&1 | tee /tmp/s16.txt

set -uo pipefail
CURL=/usr/bin/curl
OUTDIR=/tmp/s16
mkdir -p "$OUTDIR"
SEP="=================================================================="
log() { echo; echo "$SEP"; echo ">>> $*"; echo "$SEP"; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ─── PHASE 0 ── SCOPE ─────────────────────────────────────────────────────────
log "PHASE 0 — SCOPE CHECK"
SCOPE_SCRIPT=~/bug-bounty-hunting-/scripts/scope-check.sh
SCOPE_CFG=~/bug-bounty-hunting-/config/marriott-scope.yaml
for host in owa.marriott.com efast.marriott.com auth-apc.marriott.com gateway-apc.marriott.com; do
  result=$(SCOPE_FILE="$SCOPE_CFG" bash "$SCOPE_SCRIPT" "$host" 2>&1)
  echo "$host => $result"
done
echo "Note: Wildcard-discovered subdomains will be scope-checked individually before any probe."

# ─── PHASE A ── CT LOG ENUMERATION ────────────────────────────────────────────
log "PHASE A — CT log enum via crt.sh (no subfinder required)"

echo "=== A1: crt.sh query for *.apigwc.marriott.com ==="
$CURL -sk --max-time 30 \
  "https://crt.sh/?q=%25.apigwc.marriott.com&output=json" \
  -H "Accept: application/json" \
  -o "$OUTDIR/crt-apigwc.json" 2>/dev/null
python3 -c "
import json, sys
try:
    data = json.load(open('/tmp/s16/crt-apigwc.json'))
    hosts = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if 'marriott.com' in name: hosts.add(name)
    print(f'Found {len(hosts)} unique hosts:')
    for h in sorted(hosts): print(' ', h)
    with open('/tmp/s16/apigwc-hosts.txt', 'w') as f:
        f.write('\n'.join(sorted(hosts)) + '\n')
except Exception as e:
    print(f'Error: {e}')
    print(open('/tmp/s16/crt-apigwc.json').read()[:200])
" 2>&1

echo ""
echo "=== A2: crt.sh query for *.apigatewayc.marriott.com ==="
$CURL -sk --max-time 30 \
  "https://crt.sh/?q=%25.apigatewayc.marriott.com&output=json" \
  -H "Accept: application/json" \
  -o "$OUTDIR/crt-apigatewayc.json" 2>/dev/null
python3 -c "
import json, sys
try:
    data = json.load(open('/tmp/s16/crt-apigatewayc.json'))
    hosts = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if 'marriott.com' in name: hosts.add(name)
    print(f'Found {len(hosts)} unique hosts:')
    for h in sorted(hosts): print(' ', h)
    with open('/tmp/s16/apigatewayc-hosts.txt', 'w') as f:
        f.write('\n'.join(sorted(hosts)) + '\n')
except Exception as e:
    print(f'Error: {e}')
" 2>&1

echo ""
echo "=== A3: crt.sh query for *uat*.marriott.com ==="
$CURL -sk --max-time 30 \
  "https://crt.sh/?q=%25uat%25.marriott.com&output=json" \
  -H "Accept: application/json" \
  -o "$OUTDIR/crt-uat.json" 2>/dev/null
python3 -c "
import json, sys
try:
    data = json.load(open('/tmp/s16/crt-uat.json'))
    hosts = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if 'marriott.com' in name and 'uat' in name: hosts.add(name)
    print(f'Found {len(hosts)} UAT hosts:')
    for h in sorted(hosts): print(' ', h)
    with open('/tmp/s16/uat-hosts.txt', 'w') as f:
        f.write('\n'.join(sorted(hosts)) + '\n')
except Exception as e:
    print(f'Error: {e}')
" 2>&1

echo ""
echo "=== A4: crt.sh for *gateway-apc* and *dcfgateway* ==="
for pattern in "gateway-apc" "dcfgateway" "artifactory"; do
  $CURL -sk --max-time 30 \
    "https://crt.sh/?q=%25${pattern}%25.marriott.com&output=json" \
    -H "Accept: application/json" \
    -o "$OUTDIR/crt-${pattern}.json" 2>/dev/null
  python3 -c "
import json
try:
    data = json.load(open('/tmp/s16/crt-${pattern}.json'))
    hosts = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if 'marriott.com' in name: hosts.add(name)
    print(f'${pattern}: {len(hosts)} hosts: {sorted(hosts)}')
    with open('/tmp/s16/${pattern}-hosts.txt', 'w') as f:
        f.write('\n'.join(sorted(hosts)) + '\n')
except Exception as e:
    print(f'${pattern}: Error: {e}')
" 2>&1
done

echo ""
echo "=== A5: Broader Marriott CT scan — all recent certs ==="
$CURL -sk --max-time 45 \
  "https://crt.sh/?q=%25.marriott.com&output=json&limit=500" \
  -H "Accept: application/json" \
  -o "$OUTDIR/crt-all.json" 2>/dev/null
python3 - << 'PYEOF'
import json, re

try:
    data = json.load(open('/tmp/s16/crt-all.json'))
except Exception as e:
    print(f'Error loading crt-all.json: {e}')
    exit()

# All known scope targets (to filter out noise)
known = {
    'sso.marriott.com', 'cpp.marriott.com', 'esupplier.marriott.com',
    'mgs.marriott.com', 'bpa2.marriott.com', 'owa.marriott.com',
    'psp.marriott.com', 'efast.marriott.com', 'eidhelp.marriott.com',
    'ci-propertyconversionportal.marriott.com', 'marriottfranchisetransactions.marriott.com',
    'mipartnerprivileges.marriott.com', 'gatewaydsapdev2.marriott.com',
    'auth-apc.marriott.com', 'gateway-apc.marriott.com', 'apcgateway.marriott.com',
    'www.marriott.com', 'homes-and-villas.marriott.com', 'jobs.marriott.com',
}

hosts = set()
for entry in data:
    issued_at = entry.get('not_before', '')
    for name in entry.get('name_value','').split('\n'):
        name = name.strip().lower().lstrip('*.')
        if 'marriott.com' in name and name not in known:
            # Filter out obvious CDN/Akamai noise
            if not any(s in name for s in ['edgekey', 'akamai', 'cloudfront', 'amazonaws']):
                hosts.add(name)

# Exclude obvious public-facing marketing sites
interesting = {h for h in hosts if any(kw in h for kw in [
    'api', 'gateway', 'apigw', 'apig', 'uat', 'dev', 'test', 'stg', 'staging',
    'int', 'internal', 'admin', 'mgmt', 'management', 'auth', 'sso', 'login',
    'portal', 'secure', 'corp', 'enterprise', 'b2b', 'partner', 'vendor',
    'artifactory', 'jenkins', 'gitlab', 'jira', 'confluence', 'ci', 'cd',
    'service', 'micro', 'backend', 'data', 'report', 'analytics', 'monitor',
])}

print(f'Total new hosts from CT: {len(hosts)}')
print(f'Potentially interesting: {len(interesting)}')
print('\n--- INTERESTING HOSTS ---')
for h in sorted(interesting):
    print(' ', h)

print('\n--- ALL NEW HOSTS (first 50) ---')
for h in sorted(hosts)[:50]:
    print(' ', h)

with open('/tmp/s16/ct-interesting.txt', 'w') as f:
    f.write('\n'.join(sorted(interesting)) + '\n')
with open('/tmp/s16/ct-all-new.txt', 'w') as f:
    f.write('\n'.join(sorted(hosts)) + '\n')
PYEOF

# ─── PHASE B ── DNS BRUTE FORCE — COMMON PREFIXES ────────────────────────────
log "PHASE B — DNS brute force for wildcard-in-scope domains"

echo "=== B1: Brute force *.apigwc.marriott.com prefixes ==="
cat > "$OUTDIR/api-prefixes.txt" << 'PREFEOF'
api
api1
api2
dev
dev1
dev2
test
test1
stg
staging
uat
uat1
prod
prod1
internal
ext
external
partner
corp
enterprise
gateway
gw
gw1
gw2
auth
sso
oauth
token
odata
rest
graphql
service
svc
mgmt
admin
reporting
analytics
batch
async
event
notification
webhook
callback
integration
PREFEOF

> "$OUTDIR/apigwc-dns.txt"
while IFS= read -r prefix; do
  host="${prefix}.apigwc.marriott.com"
  ip=$(dig +short "$host" A 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    echo "RESOLVED: ${host} -> ${ip}"
    echo "$host" >> "$OUTDIR/apigwc-resolved.txt"
  fi
done < "$OUTDIR/api-prefixes.txt"
echo "Total resolved: $(wc -l < "$OUTDIR/apigwc-resolved.txt" 2>/dev/null || echo 0)"

echo ""
echo "=== B2: Brute force *.apigatewayc.marriott.com prefixes ==="
> "$OUTDIR/apigatewayc-resolved.txt"
while IFS= read -r prefix; do
  host="${prefix}.apigatewayc.marriott.com"
  ip=$(dig +short "$host" A 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    echo "RESOLVED: ${host} -> ${ip}"
    echo "$host" >> "$OUTDIR/apigatewayc-resolved.txt"
  fi
done < "$OUTDIR/api-prefixes.txt"
echo "Total resolved: $(wc -l < "$OUTDIR/apigatewayc-resolved.txt" 2>/dev/null || echo 0)"

echo ""
echo "=== B3: Brute force *uat.marriott.com (suffix patterns) ==="
cat > "$OUTDIR/uat-patterns.txt" << 'UATEOF'
uat
uat1
uat2
api-uat
gateway-uat
apigwc-uat
portal-uat
auth-uat
sso-uat
psp-uat
esupplier-uat
franchise-uat
mgs-uat
cpp-uat
homes-uat
dev-uat
test-uat
staging-uat
sit-uat
qa-uat
UATEOF

> "$OUTDIR/uat-resolved.txt"
while IFS= read -r prefix; do
  for suffix in "uat.marriott.com" "-uat.marriott.com"; do
    host="${prefix}.${suffix}"
    # Clean up double dots
    host=$(echo "$host" | sed 's/\.\././')
    ip=$(dig +short "$host" A 2>/dev/null | head -1)
    if [ -n "$ip" ]; then
      echo "RESOLVED: ${host} -> ${ip}"
      echo "$host" >> "$OUTDIR/uat-resolved.txt"
    fi
  done
done < "$OUTDIR/uat-patterns.txt"
echo "Total UAT resolved: $(wc -l < "$OUTDIR/uat-resolved.txt" 2>/dev/null || echo 0)"

# ─── PHASE C ── HTTP PROBE ALL DISCOVERED SUBDOMAINS ─────────────────────────
log "PHASE C — HTTP probe all CT + DNS-discovered hosts"

echo "=== C1: Scope-check and probe CT-interesting hosts ==="
python3 -c "
import subprocess

scope_script = '/root/bug-bounty-hunting-/scripts/scope-check.sh'
scope_cfg = '/root/bug-bounty-hunting-/config/marriott-scope.yaml'

try:
    ct_interesting = open('/tmp/s16/ct-interesting.txt').read().strip().split('\n')
except:
    ct_interesting = []

# Also add resolved brute-force hosts
for fname in ['apigwc-resolved.txt', 'apigatewayc-resolved.txt', 'uat-resolved.txt']:
    try:
        lines = open(f'/tmp/s16/{fname}').read().strip().split('\n')
        for line in lines:
            if 'RESOLVED:' in line:
                host = line.split()[1]
                ct_interesting.append(host)
    except:
        pass

all_hosts = list(set(h.strip() for h in ct_interesting if h.strip()))
print(f'Total hosts to scope-check: {len(all_hosts)}')
with open('/tmp/s16/all-discovered.txt', 'w') as f:
    for h in sorted(all_hosts): f.write(h + '\n')
" 2>&1

echo ""
echo "=== C2: HTTP probe all discovered hosts (SCOPE CHECK embedded) ==="
if [ -f "$OUTDIR/all-discovered.txt" ] && [ -s "$OUTDIR/all-discovered.txt" ]; then
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    # Scope check first — only proceed if IN-SCOPE
    scope_result=$(SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
      bash ~/bug-bounty-hunting-/scripts/scope-check.sh "$host" 2>&1)
    if echo "$scope_result" | grep -q "OUT-OF-SCOPE\|AMBIGUOUS"; then
      echo "SKIP (OOS): $host"
      continue
    fi
    # HTTP probe
    result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
      -H "User-Agent: $UA" --max-time 10 \
      "https://${host}/" 2>/dev/null)
    # Also try HTTP
    result_http=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
      -H "User-Agent: $UA" --max-time 10 \
      "http://${host}/" 2>/dev/null)
    echo "https=${result} | http=${result_http} | ${host}"
  done < "$OUTDIR/all-discovered.txt" | tee "$OUTDIR/discovered-http-probe.txt"

  echo ""
  echo "=== C3: Non-000 non-404 non-403 responses (live new surface) ==="
  grep -v '|000|' "$OUTDIR/discovered-http-probe.txt" 2>/dev/null \
    | grep -v '^https=000' \
    | grep -v '^https=404' \
    | grep -v '^https=403' \
    | grep -v 'SKIP' \
    || echo "(none found)"
else
  echo "(no discovered hosts to probe)"
fi

# ─── PHASE D ── OWA NTLM AUTODISCOVER PROBE ──────────────────────────────────
log "PHASE D — owa.marriott.com — NTLM/Exchange pre-auth probe"

echo "=== D1: OWA root redirect confirmation ==="
$CURL -sk -D - -o "$OUTDIR/owa-root.txt" --max-redirs 0 \
  -H "User-Agent: $UA" --max-time 10 \
  "https://owa.marriott.com/" 2>/dev/null | head -20
echo "Root: $(head -3 "$OUTDIR/owa-root.txt")"

echo ""
echo "=== D2: /autodiscover/autodiscover.xml — NTLM challenge (GET only) ==="
# Sends NTLM Type 1 (negotiate) — safe read-only probe that triggers NTLM challenge
# The response's WWW-Authenticate header leaks: domain, server NETBIOS name
$CURL -sk -D - -o "$OUTDIR/owa-autodiscover.txt" \
  --ntlm --user "null:null" \
  -H "User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0; en-US)" \
  -H "Content-Type: text/xml" \
  --max-time 15 \
  "https://owa.marriott.com/autodiscover/autodiscover.xml" 2>/dev/null
echo "Status + Auth headers:"
head -20 "$OUTDIR/owa-autodiscover.txt"
echo ""
echo "WWW-Authenticate header (contains NTLM challenge):"
grep -i 'www-authenticate\|ntlm\|negotiate' "$OUTDIR/owa-autodiscover.txt" || echo "(no NTLM headers)"

echo ""
echo "=== D3: Decode NTLM Type 2 challenge (extracts domain + server name) ==="
python3 - << 'PYEOF'
import base64, re, struct

try:
    content = open('/tmp/s16/owa-autodiscover.txt').read()
except:
    print("Could not read autodiscover response"); exit()

# Extract NTLM Type 2 token from WWW-Authenticate header
ntlm_tokens = re.findall(r'(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]{20,})', content)
if not ntlm_tokens:
    print("No NTLM Type 2 token found in response")
    print("WWW-Authenticate lines:")
    for line in content.split('\n'):
        if 'authenticate' in line.lower() or 'ntlm' in line.lower():
            print(' ', line)
    exit()

for token in ntlm_tokens:
    try:
        data = base64.b64decode(token + '==')
        # NTLM Type 2 signature check
        if data[:8] == b'NTLMSSP\x00' and data[8] == 2:
            print(f"NTLM Type 2 token found! ({len(data)} bytes)")
            # Extract target name (domain)
            tn_len = struct.unpack('<H', data[12:14])[0]
            tn_off = struct.unpack('<I', data[16:20])[0]
            target_name = data[tn_off:tn_off+tn_len].decode('utf-16-le', errors='replace')
            print(f"  Target Name (domain): {target_name}")
            # Flags
            flags = struct.unpack('<I', data[20:24])[0]
            print(f"  Flags: 0x{flags:08x}")
            # Target info block
            ti_len = struct.unpack('<H', data[40:42])[0]
            ti_off = struct.unpack('<I', data[44:48])[0]
            ti_data = data[ti_off:ti_off+ti_len]
            # Parse AvPairs
            i = 0
            while i < len(ti_data) - 4:
                av_id = struct.unpack('<H', ti_data[i:i+2])[0]
                av_len = struct.unpack('<H', ti_data[i+2:i+4])[0]
                av_val = ti_data[i+4:i+4+av_len].decode('utf-16-le', errors='replace')
                av_names = {1:'NetBIOS Domain',2:'NetBIOS Computer',3:'DNS Domain',4:'DNS Computer',5:'DNS Tree',7:'Timestamp'}
                if av_id in av_names:
                    print(f"  {av_names[av_id]}: {av_val}")
                if av_id == 0: break
                i += 4 + av_len
        else:
            print(f"Token is not NTLM Type 2: {token[:20]}...")
    except Exception as e:
        print(f"Decode error: {e}")
        print(f"Token: {token[:40]}")
PYEOF

echo ""
echo "=== D4: /EWS/Exchange.asmx — Exchange Web Services pre-auth ==="
$CURL -sk -D - -o "$OUTDIR/owa-ews.txt" \
  --ntlm --user "null:null" \
  -H "User-Agent: $UA" \
  --max-time 10 \
  "https://owa.marriott.com/EWS/Exchange.asmx" 2>/dev/null
echo "EWS headers (first 15 lines):"
head -15 "$OUTDIR/owa-ews.txt"

echo ""
echo "=== D5: /owa/ login page — fingerprint Exchange version ==="
$CURL -sk -D - -o "$OUTDIR/owa-login.html" \
  -H "User-Agent: $UA" \
  -L --max-redirs 2 --max-time 10 \
  "https://owa.marriott.com/owa/" 2>/dev/null
echo "OWA login page: $(wc -c < "$OUTDIR/owa-login.html")B"
echo "Headers:"
head -20 "$OUTDIR/owa-login.html"
# Extract Exchange version from headers or page
python3 -c "
import re
body = open('/tmp/s16/owa-login.html', errors='replace').read()
ver = re.findall(r'(Exchange|OWA|Outlook Web)[\s\-]+([\d.]+)', body, re.I)
xver = re.findall(r'X-OWA-Version[:\s]+([\d.]+)', body)
title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
print('Title:', title[:3])
print('Version matches:', ver[:5])
print('X-OWA-Version:', xver[:3])
" 2>/dev/null

echo ""
echo "=== D6: /Microsoft-Server-ActiveSync — ActiveSync pre-auth probe ==="
$CURL -sk -o /dev/null -w "Status: %{http_code} Size: %{size_download}\n" \
  -H "User-Agent: $UA" --max-time 10 \
  "https://owa.marriott.com/Microsoft-Server-ActiveSync"

# ─── PHASE E ── efast.marriott.com AUTH FINGERPRINT ──────────────────────────
log "PHASE E — efast.marriott.com (401/6834B) — auth type identification"

echo "=== E1: Root page full headers ==="
$CURL -sk -D - -o "$OUTDIR/efast-root.txt" \
  -H "User-Agent: $UA" --max-time 10 \
  "https://efast.marriott.com/" 2>/dev/null | head -40

echo ""
echo "=== E2: Auth header analysis ==="
python3 -c "
content = open('/tmp/s16/efast-root.txt', errors='replace').read()
import re
# WWW-Authenticate tells us the auth type
auth = re.findall(r'www-authenticate:\s*(.*)', content, re.I)
# X-Powered-By reveals tech stack
powered = re.findall(r'x-powered-by:\s*(.*)', content, re.I)
server = re.findall(r'server:\s*(.*)', content, re.I)
location = re.findall(r'location:\s*(.*)', content, re.I)
print('WWW-Authenticate:', auth)
print('X-Powered-By:', powered)
print('Server:', server)
print('Location (redirects):', location)
"

echo ""
echo "=== E3: efast path probe ==="
for path in / /login /auth /saml /oauth2/authorize /api /api/v1 /health \
            /actuator/health /swagger-ui.html /v2/api-docs /robots.txt \
            /efast /efast/login /efast/api; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" --max-time 10 \
    "https://efast.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done

echo ""
echo "=== E4: efast with NTLM negotiate (check if NTLM auth) ==="
$CURL -sk -D - -o "$OUTDIR/efast-ntlm.txt" \
  --ntlm --user "null:null" \
  -H "User-Agent: $UA" --max-time 10 \
  "https://efast.marriott.com/" 2>/dev/null | head -20

# ─── PHASE F ── APC CLUSTER HOST-HEADER ROUTING ───────────────────────────────
log "PHASE F — APC cluster (auth-apc, gateway-apc, apcgateway) host-header routing"

APC_IP=23.61.96.201  # Confirmed from session 1 DNS resolution

echo "=== F1: Direct IP probe with each Host header ==="
for vhost in auth-apc.marriott.com gateway-apc.marriott.com apcgateway.marriott.com; do
  scope_result=$(SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
    bash ~/bug-bounty-hunting-/scripts/scope-check.sh "$vhost" 2>&1)
  if echo "$scope_result" | grep -q "OUT-OF-SCOPE\|AMBIGUOUS"; then
    echo "SKIP (OOS): $vhost"
    continue
  fi
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" \
    -H "Host: $vhost" \
    --max-time 10 \
    --resolve "${vhost}:443:${APC_IP}" \
    "https://${vhost}/" 2>/dev/null)
  echo "${result}|${vhost} (via ${APC_IP})"
done

echo ""
echo "=== F2: Standard HTTPS probe (via Akamai CDN) ==="
for vhost in auth-apc.marriott.com gateway-apc.marriott.com apcgateway.marriott.com; do
  scope_result=$(SCOPE_FILE=~/bug-bounty-hunting-/config/marriott-scope.yaml \
    bash ~/bug-bounty-hunting-/scripts/scope-check.sh "$vhost" 2>&1)
  echo "$scope_result" | grep -q "OUT-OF-SCOPE\|AMBIGUOUS" && continue

  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" --max-time 10 \
    "https://${vhost}/" 2>/dev/null)
  echo "${result}|${vhost}"
done

echo ""
echo "=== F3: APC path probe (auth-apc likely = SSO auth endpoint) ==="
for path in / /auth /login /oauth2/authorize /oauth2/token /saml2/idp/SSO \
            /api /api/v1 /health /.well-known/openid-configuration \
            /.well-known/oauth-authorization-server /userinfo /token /introspect; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" --max-time 10 \
    "https://auth-apc.marriott.com${path}" 2>/dev/null)
  echo "${result}|auth-apc${path}"
done

# ─── PHASE G ── DECISION GATE ─────────────────────────────────────────────────
log "PHASE G — DECISION GATE"

echo "=== Summary: CT discovered hosts ==="
echo "crt.sh apigwc: $(wc -l < "$OUTDIR/apigwc-hosts.txt" 2>/dev/null || echo 0)"
echo "crt.sh apigatewayc: $(wc -l < "$OUTDIR/apigatewayc-hosts.txt" 2>/dev/null || echo 0)"
echo "crt.sh uat: $(wc -l < "$OUTDIR/uat-hosts.txt" 2>/dev/null || echo 0)"
echo "CT all-new interesting: $(wc -l < "$OUTDIR/ct-interesting.txt" 2>/dev/null || echo 0)"

echo ""
echo "=== Summary: Live discovered hosts ==="
grep -v 'SKIP' "$OUTDIR/discovered-http-probe.txt" 2>/dev/null \
  | grep -v '^https=000\|^https=404\|^https=403' || echo "(no live discovered hosts)"

echo ""
echo "=== Summary: OWA NTLM results ==="
echo "Autodiscover status: $(head -1 "$OUTDIR/owa-autodiscover.txt" 2>/dev/null)"
grep -i 'ntlm\|authenticate\|NetBIOS\|DNS Domain\|Target Name' "$OUTDIR/owa-autodiscover.txt" 2>/dev/null | head -5
echo ""

echo "=== Summary: efast auth type ==="
grep -i 'www-authenticate\|server:\|x-powered\|location:' "$OUTDIR/efast-root.txt" 2>/dev/null | head -5

echo ""
echo "=== Summary: APC cluster status ==="
grep -v 'SKIP' "$OUTDIR/discovered-http-probe.txt" 2>/dev/null | grep 'apc' || \
  echo "(check Phase F output above)"

log "SESSION 16 COMPLETE"
echo "Key decision points:"
echo " 1. If new subdomains found (apigwc, apigatewayc, uat) → scope-check + probe individually"
echo " 2. If OWA NTLM Type 2 decoded → note domain/server names (Low, chains to internal fingerprint)"
echo " 3. If auth-apc returns live responses → test OAuth/OIDC endpoint disclosure"
echo " 4. If efast uses Basic or NTLM → test for NTLM relay vectors"
echo " 5. If efast is CloudFront + SAML → note redirect target, check if OOS"
echo ""
echo "Save: mkdir -p ~/bug-bounty-hunting-/results/marriott/session16/ && cp -r /tmp/s16/* ~/bug-bounty-hunting-/results/marriott/session16/"
