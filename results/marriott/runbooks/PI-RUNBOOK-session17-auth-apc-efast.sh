#!/usr/bin/env bash
# PI-RUNBOOK-session17-auth-apc-efast.sh
# Session 17 — auth-apc.marriott.com /login (M020) + efast.marriott.com body read + CT retry
#
# Context from Session 16:
#   - auth-apc.marriott.com/login → 200/137KB — full SSO login application, all other paths 000
#   - efast.marriott.com root → 401/6834B, server:Tomcat, no WWW-Authenticate, SessionIDCookie
#   - crt.sh returned 502 (down) — CT enum needs retry
#   - scope-check.sh fixed: *gateway-apc, *uat.marriott.com now correctly IN-SCOPE
#
# Bug class hypotheses for auth-apc:
#   - Open redirect via RelayState / redirect_uri / target parameter (chains to ATO)
#   - SAML assertion signature bypass / XML signature wrapping
#   - OAuth state parameter manipulation / PKCE downgrade
#   - OAuth redirect_uri bypass (wildcard/path traversal)
#   - Username enumeration (differential response on unknown vs known user)
#   - Password spray timing side-channel
#   - OIDC token endpoint without PKCE on public client
#   - /.well-known/openid-configuration exposure (credential-free metadata = info disclosure + chain)
#
# Run: bash PI-RUNBOOK-session17-auth-apc-efast.sh 2>&1 | tee /tmp/s17.txt

set -uo pipefail
CURL=/usr/bin/curl
OUTDIR=/tmp/s17
mkdir -p "$OUTDIR"
SEP="=================================================================="
log() { echo; echo "$SEP"; echo ">>> $*"; echo "$SEP"; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ─── PHASE 0 ── SCOPE ─────────────────────────────────────────────────────────
log "PHASE 0 — SCOPE CHECK"
SCOPE_SCRIPT=~/bug-bounty-hunting-/scripts/scope-check.sh
SCOPE_CFG=~/bug-bounty-hunting-/config/marriott-scope.yaml
for host in auth-apc.marriott.com efast.marriott.com gateway-apc.marriott.com; do
  result=$(SCOPE_FILE="$SCOPE_CFG" bash "$SCOPE_SCRIPT" "$host" 2>&1)
  echo "$host => $result"
done

# ─── PHASE A ── auth-apc.marriott.com — FULL DOWNLOAD + FINGERPRINT ──────────
log "PHASE A — auth-apc.marriott.com — Download /login + tech fingerprint"

echo "=== A1: /login full headers + body ==="
$CURL -sk -D "$OUTDIR/auth-apc-login-headers.txt" \
  -o "$OUTDIR/auth-apc-login.html" \
  -H "User-Agent: $UA" \
  -L --max-redirs 3 \
  --max-time 20 \
  "https://auth-apc.marriott.com/login" 2>/dev/null
echo "Login page: $(wc -c < "$OUTDIR/auth-apc-login.html")B"
echo "--- Response headers ---"
cat "$OUTDIR/auth-apc-login-headers.txt"

echo ""
echo "=== A2: Tech fingerprint ==="
python3 - << 'PYEOF'
import re

try:
    body = open('/tmp/s17/auth-apc-login.html', errors='replace').read()
    headers = open('/tmp/s17/auth-apc-login-headers.txt', errors='replace').read()
except Exception as e:
    print(f"Error: {e}"); exit()

title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
server = re.findall(r'(?:server|x-powered-by):\s*(.*)', headers, re.I)
# SSO tech fingerprints
ping = re.findall(r'(PingFederate|PingAccess|ping\.identity|/pingfederate/|/pf/|pfwrapper)', body, re.I)
okta = re.findall(r'(okta|okta-signin-widget|okta\.com)', body, re.I)
forgerock = re.findall(r'(forgerock|openam|am\.login|XUI/|forgerock\.com)', body, re.I)
adfs = re.findall(r'(adfs|Microsoft Identity|/adfs/|wsfederation)', body, re.I)
azure = re.findall(r'(login\.microsoftonline|AzureAD|microsoft\.com/login)', body, re.I)
saml = re.findall(r'(SAMLRequest|SAMLResponse|RelayState|samlp:|saml:|urn:oasis:names:tc:SAML)', body, re.I)
oauth = re.findall(r'(oauth2|openid-connect|client_id|redirect_uri|response_type|code_challenge)', body, re.I)
forms = re.findall(r'<form[^>]*action=["\']([^"\']{0,200})["\']', body, re.I)
inputs = re.findall(r'<input[^>]+>', body, re.I)
scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)

print(f'Title: {title}')
print(f'Server headers: {server}')
print(f'PingFederate: {ping[:5]}')
print(f'Okta: {okta[:5]}')
print(f'ForgeRock: {forgerock[:5]}')
print(f'ADFS: {adfs[:5]}')
print(f'Azure AD: {azure[:5]}')
print(f'SAML indicators: {saml[:8]}')
print(f'OAuth indicators: {oauth[:8]}')
print(f'\nForms ({len(forms)}):')
for f in forms[:5]: print(f'  {f}')
print(f'\nInputs ({len(inputs)}):')
for i in inputs[:15]: print(f'  {i[:120]}')
print(f'\nScripts ({len(scripts)}):')
for s in scripts[:15]: print(f'  {s}')
PYEOF

echo ""
echo "=== A3: Extract hidden fields, CSRF tokens, SAML parameters ==="
python3 -c "
import re
body = open('/tmp/s17/auth-apc-login.html', errors='replace').read()
# Hidden inputs (CSRF tokens, SAML params, state values)
hidden = re.findall(r'<input[^>]+type=[\"\']\s*hidden[^>]+>', body, re.I)
print(f'Hidden inputs ({len(hidden)}):')
for h in hidden[:20]: print(f'  {h[:150]}')
# All name/value pairs from inputs
nv = re.findall(r'<input[^>]+name=[\"\'](.*?)[\"\']\s*(?:value=[\"\'](.*?)[\"\']\s*)?[/]?>', body, re.I)
print(f'\nAll input name/value pairs:')
for n, v in nv[:20]: print(f'  name={n!r} value={v[:50]!r}')
# URL patterns in the page (API endpoints, callback URLs)
urls = re.findall(r'[\"\']((?:https?://|/)[^\s\"\'<>{}\|\\^]+)[\"\'\\]', body)
interesting_urls = [u for u in urls if any(k in u.lower() for k in ['api','auth','token','saml','oauth','callback','redirect','login','sso','idp','sp'])]
print(f'\nInteresting URLs ({len(interesting_urls)}):')
for u in sorted(set(interesting_urls))[:30]: print(f'  {u[:120]}')
" 2>&1

echo ""
echo "=== A4: Extract JavaScript bundle URLs and download ==="
python3 - << 'PYEOF'
import re

body = open('/tmp/s17/auth-apc-login.html', errors='replace').read()
base = 'https://auth-apc.marriott.com'

scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
urls = []
for s in scripts:
    if s.startswith('//'): urls.append('https:' + s)
    elif s.startswith('/'): urls.append(base + s)
    elif s.startswith('http'): urls.append(s)

print(f'Found {len(urls)} JS URLs:')
for u in urls[:20]: print(f'  {u}')
with open('/tmp/s17/auth-apc-js-urls.txt', 'w') as f:
    f.write('\n'.join(urls) + '\n')
PYEOF

# Download first 3 JS bundles (to avoid excessive requests)
if [ -s "$OUTDIR/auth-apc-js-urls.txt" ]; then
  mkdir -p "$OUTDIR/auth-apc-js"
  count=0
  while IFS= read -r jsurl && [ "$count" -lt 5 ]; do
    [ -z "$jsurl" ] && continue
    count=$((count+1))
    outf="$OUTDIR/auth-apc-js/bundle-${count}.js"
    $CURL -sk -L --max-time 20 \
      -H "User-Agent: $UA" \
      -H "Referer: https://auth-apc.marriott.com/login" \
      -o "$outf" "$jsurl" 2>/dev/null
    echo "JS $count: $(wc -c < "$outf")B — $jsurl"
  done < "$OUTDIR/auth-apc-js-urls.txt"
fi

# ─── PHASE B ── auth-apc — PATH ENUMERATION ───────────────────────────────────
log "PHASE B — auth-apc.marriott.com — path enumeration"

echo "=== B1: Common SSO/IDP paths ==="
for path in \
  / /login /logout /auth /sso \
  /.well-known/openid-configuration \
  /.well-known/oauth-authorization-server \
  /.well-known/webfinger \
  /oauth2/authorize /oauth2/token /oauth2/userinfo \
  /oauth2/jwks /oauth2/keys /oauth2/.well-known/openid-configuration \
  /saml /saml2 /saml/idp /saml2/idp \
  /saml/metadata /saml2/metadata /saml/idp/metadata \
  /idp /idp/startSSO.ping /pf/idp \
  /pingfederate /pingfederate/idp \
  /openam /XUI /am /auth/login \
  /as /as/authorization.oauth2 /as/token.oauth2 \
  /api /api/v1 /health /actuator/health \
  /robots.txt /sitemap.xml; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" --max-time 10 \
    "https://auth-apc.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
done | tee "$OUTDIR/auth-apc-paths.txt"

echo ""
echo "=== B2: Non-000/404 paths ==="
grep -v '^000|' "$OUTDIR/auth-apc-paths.txt" | grep -v '^404|' || echo "(none)"

# ─── PHASE C ── auth-apc — OPENID CONFIGURATION + OAUTH METADATA ─────────────
log "PHASE C — auth-apc — OpenID Connect and OAuth metadata"

echo "=== C1: /.well-known/openid-configuration ==="
$CURL -sk -o "$OUTDIR/auth-apc-oidc.json" \
  -H "User-Agent: $UA" \
  -H "Accept: application/json" \
  --max-time 15 \
  "https://auth-apc.marriott.com/.well-known/openid-configuration"
echo "OIDC config ($(wc -c < "$OUTDIR/auth-apc-oidc.json")B):"
cat "$OUTDIR/auth-apc-oidc.json"

echo ""
echo "=== C2: Parse OIDC config for endpoints + test access ==="
python3 - << 'PYEOF'
import json, subprocess

raw = open('/tmp/s17/auth-apc-oidc.json', errors='replace').read().strip()
if not raw:
    print("Empty OIDC config"); exit()
try:
    cfg = json.loads(raw)
    print("=== OIDC Configuration ===")
    for k, v in cfg.items():
        if isinstance(v, (str, int, bool)):
            print(f"  {k}: {v}")
        elif isinstance(v, list):
            print(f"  {k}: {v[:5]}")

    # Key endpoints
    endpoints = {k: v for k, v in cfg.items() if 'endpoint' in k or 'uri' in k}
    print(f"\nEndpoints: {endpoints}")

    # Security settings
    print(f"\nPKCE required: {cfg.get('code_challenge_methods_supported', 'not specified')}")
    print(f"Response types: {cfg.get('response_types_supported', 'not specified')}")
    print(f"Grant types: {cfg.get('grant_types_supported', 'not specified')}")

except json.JSONDecodeError:
    print("Not valid JSON — likely not an OIDC endpoint")
    print(raw[:500])
PYEOF

echo ""
echo "=== C3: Download and analyze JWKS (public keys endpoint) ==="
python3 -c "
import json
try:
    cfg = json.load(open('/tmp/s17/auth-apc-oidc.json'))
    jwks_uri = cfg.get('jwks_uri', '')
    if jwks_uri:
        print(f'JWKS URI: {jwks_uri}')
        with open('/tmp/s17/auth-apc-jwks-uri.txt', 'w') as f:
            f.write(jwks_uri)
    else:
        print('No JWKS URI in OIDC config')
except: print('Could not parse OIDC config for JWKS URI')
" 2>/dev/null

if [ -s "$OUTDIR/auth-apc-jwks-uri.txt" ]; then
  jwks_uri=$(cat "$OUTDIR/auth-apc-jwks-uri.txt")
  $CURL -sk -o "$OUTDIR/auth-apc-jwks.json" \
    -H "User-Agent: $UA" -H "Accept: application/json" \
    --max-time 10 "$jwks_uri"
  echo "JWKS ($(wc -c < "$OUTDIR/auth-apc-jwks.json")B):"
  python3 -c "
import json
try:
    jwks = json.load(open('/tmp/s17/auth-apc-jwks.json'))
    keys = jwks.get('keys', [])
    print(f'Keys: {len(keys)}')
    for k in keys:
        print(f'  alg={k.get(\"alg\",\"?\")} kty={k.get(\"kty\",\"?\")} use={k.get(\"use\",\"?\")} kid={k.get(\"kid\",\"?\")}')
except Exception as e:
    print(f'Error: {e}')
    print(open('/tmp/s17/auth-apc-jwks.json').read()[:300])
"
fi

# ─── PHASE D ── auth-apc — OPEN REDIRECT PROBE ───────────────────────────────
log "PHASE D — auth-apc — Open redirect and RelayState bypass probe"

echo "=== D1: SAMLRequest/RelayState open redirect test ==="
# Many SSO portals use RelayState to redirect after auth — test if it redirects without validation
for param in RelayState relay_state redirect_uri next return goto target returnTo callback; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" \
    -H "User-Agent: $UA" --max-redirs 0 --max-time 10 \
    "https://auth-apc.marriott.com/login?${param}=https://example.com/evil" 2>/dev/null)
  echo "${result}|?${param}=https://example.com/evil"
done

echo ""
echo "=== D2: Login form target parameter (POST-based open redirect) ==="
# If the login form includes a RelayState/target hidden field, test if POST redirects to it
python3 -c "
import re
body = open('/tmp/s17/auth-apc-login.html', errors='replace').read()
form_action = re.findall(r'<form[^>]*action=[\"\'](.*?)[\"\']\s*', body, re.I)
relay_inputs = re.findall(r'<input[^>]+name=[\"\'](RelayState|target|redirect_uri|next|return)[\"\']\s*value=[\"\'](.*?)[\"\']\s*', body, re.I)
print('Form actions:', form_action)
print('RelayState-like inputs:', relay_inputs)
" 2>/dev/null

echo ""
echo "=== D3: SAML metadata endpoint (may reveal SP list + redirect config) ==="
for path in /saml/metadata /saml2/metadata /idp/metadata /saml/idp/metadata \
            /sso/saml/metadata /pingfederate/idp/metadata; do
  result=$($CURL -sk -o /dev/null -w "%{http_code}|%{size_download}" \
    -H "User-Agent: $UA" --max-time 10 \
    "https://auth-apc.marriott.com${path}" 2>/dev/null)
  echo "${result}|${path}"
  if echo "$result" | grep -q '^200|'; then
    # Download if 200 — SAML metadata is highly informative
    $CURL -sk -o "$OUTDIR/saml-metadata${path//\//-}.xml" \
      -H "User-Agent: $UA" --max-time 15 \
      "https://auth-apc.marriott.com${path}"
    echo "  Saved: $OUTDIR/saml-metadata${path//\//-}.xml"
  fi
done

# ─── PHASE E ── auth-apc — JS BUNDLE MINING ──────────────────────────────────
log "PHASE E — auth-apc — JS bundle endpoint + secret mining"

if ls "$OUTDIR/auth-apc-js/"*.js 2>/dev/null | head -1 | grep -q '.'; then
  cat > /tmp/mine_auth_apc.py << 'PYEOF'
import os, re

bundle_dir = '/tmp/s17/auth-apc-js'
api_paths = set()
hostnames = set()
tokens = set()
client_ids = set()
redirect_uris = set()

for fname in sorted(os.listdir(bundle_dir)):
    fpath = os.path.join(bundle_dir, fname)
    try: content = open(fpath, errors='replace').read()
    except: continue
    sz = len(content)
    print(f"Processing {fname} ({sz}B)")

    for p in re.findall(r'["`\'](/?(?:api|oauth|saml|auth|sso|token|idp|sp)[/\w.\-{}:?=&%]+)["`\']', content):
        if 3 < len(p) < 120: api_paths.add(p)

    for h in re.findall(r'["`\']((?:https?://)?[\w-]+\.marriott\.com(?:/[^"\'`\s]{0,60})?)["`\']', content):
        hostnames.add(h[:120])

    for t in re.findall(r'(?:client_id|clientId|client_secret|apikey|api_key|secret|token)\s*[:=]\s*["`\']([\w\-_.]{8,80})["`\']', content, re.I):
        tokens.add(t)

    for c in re.findall(r'client_id["\s:=]+"([\w\-]+)"', content, re.I):
        client_ids.add(c)

    for r in re.findall(r'redirect_uri["\s:=]+"([^"]{10,120})"', content, re.I):
        redirect_uris.add(r)

print(f"\n=== API PATHS ({len(api_paths)}) ===")
for p in sorted(api_paths)[:50]: print(' ', p)
print(f"\n=== HOSTNAMES ({len(hostnames)}) ===")
for h in sorted(hostnames)[:30]: print(' ', h)
if tokens:
    print(f"\n=== POTENTIAL SECRETS/CLIENT IDs ({len(tokens)}) ===")
    for t in sorted(tokens)[:20]: print(' ', t[:60])
if client_ids:
    print(f"\n=== OAUTH CLIENT IDs ({len(client_ids)}) ===")
    for c in client_ids: print(' ', c)
if redirect_uris:
    print(f"\n=== REDIRECT URIs ({len(redirect_uris)}) ===")
    for r in redirect_uris: print(' ', r)
PYEOF
  python3 /tmp/mine_auth_apc.py | tee "$OUTDIR/auth-apc-js-mining.txt"
else
  echo "No JS bundles downloaded — skipping mining"
fi

# ─── PHASE F ── efast.marriott.com — READ 401 BODY ───────────────────────────
log "PHASE F — efast.marriott.com — Read 401 response body"

echo "=== F1: Download root 401 response body ==="
$CURL -sk -D "$OUTDIR/efast-headers.txt" \
  -o "$OUTDIR/efast-body.html" \
  -H "User-Agent: $UA" \
  --max-time 15 \
  "https://efast.marriott.com/" 2>/dev/null
echo "Body: $(wc -c < "$OUTDIR/efast-body.html")B"
echo "--- Headers ---"
cat "$OUTDIR/efast-headers.txt"

echo ""
echo "=== F2: Analyze efast body ==="
python3 - << 'PYEOF'
import re

try:
    body = open('/tmp/s17/efast-body.html', errors='replace').read()
except Exception as e:
    print(f"Error: {e}"); exit()

print(f"Body size: {len(body)}B")
title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.I|re.S)
inputs = re.findall(r'<input[^>]+>', body, re.I)
links = re.findall(r'href=["\']([^"\']{3,120})["\']', body, re.I)
scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
saml_params = re.findall(r'(SAMLRequest|RelayState|redirect|sso|login|auth|token)', body, re.I)

print(f'Title: {title}')
print(f'\nForms: {len(forms)}')
for f in forms[:3]: print(f'  {f[:200]}')
print(f'\nInputs: {len(inputs)}')
for i in inputs[:15]: print(f'  {i[:120]}')
print(f'\nLinks: {links[:20]}')
print(f'\nScripts: {scripts[:10]}')
print(f'\nSAML/Auth params: {set(saml_params)}')
print(f'\nFirst 500 chars of body:')
print(body[:500])
PYEOF

echo ""
echo "=== F3: Download /efast body ==="
$CURL -sk -o "$OUTDIR/efast-efast.html" \
  -H "User-Agent: $UA" --max-time 15 \
  "https://efast.marriott.com/efast"
echo "Body: $(wc -c < "$OUTDIR/efast-efast.html")B"
python3 -c "
import re
body = open('/tmp/s17/efast-efast.html', errors='replace').read()
title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
forms = re.findall(r'<form[^>]*action=[\"\'](.*?)[\"\']\s*', body, re.I)
print('Title:', title)
print('Form actions:', forms[:5])
print('First 300B:', repr(body[:300]))
" 2>/dev/null

echo ""
echo "=== F4: Try efast with SessionIDCookie set ==="
# The 401 response sets SessionIDCookie — test if it unlocks anything
SESSION_COOKIE=$(grep -i 'set-cookie' "$OUTDIR/efast-headers.txt" | head -1 | sed 's/set-cookie:\s*//i' | cut -d';' -f1)
echo "Using cookie: $SESSION_COOKIE"
if [ -n "$SESSION_COOKIE" ]; then
  $CURL -sk -o /dev/null -w "With session cookie: %{http_code}|%{size_download}\n" \
    -H "User-Agent: $UA" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 10 \
    "https://efast.marriott.com/"
fi

# ─── PHASE G ── CT LOG RETRY ──────────────────────────────────────────────────
log "PHASE G — CT log enum retry (crt.sh was down in S16)"

echo "=== G1: crt.sh retry for key wildcard scopes ==="
for scope in "%25.apigwc.marriott.com" "%25uat%25.marriott.com" "%25gateway-apc%25.marriott.com" "%25artifactory%25.marriott.com"; do
  echo "Querying crt.sh for $scope..."
  $CURL -sk --max-time 30 \
    "https://crt.sh/?q=${scope}&output=json" \
    -H "Accept: application/json" \
    -o "$OUTDIR/crt-${scope//%25./}.json" 2>/dev/null
  python3 -c "
import json, sys
scope = '$scope'
fname = '/tmp/s17/crt-${scope//%25./}.json'
try:
    raw = open(fname).read()
    if raw.startswith('<'):
        print(f'{scope}: crt.sh returned HTML (still down or rate-limited)')
    else:
        data = json.loads(raw)
        hosts = set()
        for entry in data:
            for name in entry.get('name_value','').split('\n'):
                name = name.strip().lower().lstrip('*.')
                if 'marriott.com' in name: hosts.add(name)
        print(f'{scope}: {len(hosts)} hosts found')
        for h in sorted(hosts): print(f'  {h}')
except Exception as e:
    print(f'{scope}: Error - {e}')
" 2>&1
  echo ""
done

# ─── PHASE H ── DECISION GATE ─────────────────────────────────────────────────
log "PHASE H — DECISION GATE"

echo "=== Summary: auth-apc /login fingerprint ==="
python3 -c "
import re
try:
    body = open('/tmp/s17/auth-apc-login.html', errors='replace').read()
    title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
    print('Title:', title)
    # Quick SSO tech detection
    for tech, patterns in {
        'PingFederate': ['PingFederate','/pingfederate/','/pf/','/idp/startSSO.ping'],
        'ForgeRock': ['forgerock','openam','/XUI/','ForgeRock'],
        'Okta': ['okta','okta-signin'],
        'ADFS': ['adfs','Microsoft Identity'],
        'Azure AD': ['login.microsoftonline','AzureAD'],
        'SAML-enabled': ['SAMLRequest','RelayState'],
        'OAuth/OIDC': ['oauth2','openid-connect','client_id'],
    }.items():
        matches = [p for p in patterns if p.lower() in body.lower()]
        if matches:
            print(f'TECH: {tech} (matched: {matches})')
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null

echo ""
echo "=== Summary: OIDC config ==="
cat "$OUTDIR/auth-apc-oidc.json" 2>/dev/null | head -20 || echo "(no OIDC config)"

echo ""
echo "=== Summary: Open redirect results ==="
grep -v '^000|' "$OUTDIR/auth-apc-paths.txt" 2>/dev/null | grep -v '^404|' || echo "(check Phase D output)"

echo ""
echo "=== Summary: efast body analysis ==="
echo "Body size: $(wc -c < "$OUTDIR/efast-body.html" 2>/dev/null)B"
python3 -c "
import re
try:
    body = open('/tmp/s17/efast-body.html', errors='replace').read()
    title = re.findall(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
    print('efast title:', title)
except: pass
" 2>/dev/null

echo ""
echo "=== Raw files in $OUTDIR ==="
ls -lh "$OUTDIR/"

log "SESSION 17 COMPLETE"
echo "Key decision points:"
echo " 1. If auth-apc is PingFederate → test /idp/startSSO.ping?PartnerSpId= open redirect"
echo " 2. If OIDC config present → check grant types, PKCE, implicit flow (deprecated = weaker)"
echo " 3. If redirect_uri found in JS → test URI bypass (path traversal, wildcard domain)"
echo " 4. If SAML metadata accessible → parse SP list, look for weak signing config"
echo " 5. If efast body has login form → extract form action + fields for next session"
echo " 6. Report auth-apc findings if open redirect or unprotected metadata confirmed"
echo ""
echo "Save: mkdir -p ~/bug-bounty-hunting-/results/marriott/session17/ && cp -r /tmp/s17/* ~/bug-bounty-hunting-/results/marriott/session17/"
