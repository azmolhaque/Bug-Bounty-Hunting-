#!/bin/bash
# Exchange a one-time passcode for a management API Bearer token.
# Usage:
#   1. Visit https://login.apigee.com/passcode in your browser (while logged in
#      as azmolhaque95@gmail.com) and copy the code.
#   2. export PASSCODE="<code>"  && bash scripts/apigee_get_token.sh
#   On success the token is printed and saved to /tmp/apigee_token.txt
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

PASSCODE="${PASSCODE:-}"
APIGEE_EMAIL="${APIGEE_EMAIL:-azmolhaque95@gmail.com}"
TOKEN_URL="https://login.apigee.com/oauth/token"

if [ -z "$PASSCODE" ]; then
  echo "ERROR: export PASSCODE='<code from login.apigee.com/passcode>' first"
  exit 1
fi

echo "Attempting passcode exchange for ${APIGEE_EMAIL}..."
echo

# Variant 1: edgecli via -u (Basic auth header for client, username+passcode in body)
echo "=== Variant 1: -u edgecli:edgeclisecret + username in body ==="
R1=$(/usr/bin/curl -sk --max-time 15 \
  -X POST "$TOKEN_URL" \
  -u "edgecli:edgeclisecret" \
  -H "Accept: application/json" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=${APIGEE_EMAIL}&passcode=${PASSCODE}")
echo "$R1" | python3 -m json.tool 2>/dev/null || echo "$R1"
echo

# If variant 1 succeeded, extract and save token
ACCESS_TOKEN=$(echo "$R1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
  # Variant 2: all params in body (no Basic auth header)
  echo "=== Variant 2: all params in body (no client Basic auth) ==="
  R2=$(/usr/bin/curl -sk --max-time 15 \
    -X POST "$TOKEN_URL" \
    -H "Accept: application/json" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=${APIGEE_EMAIL}&passcode=${PASSCODE}&client_id=edgecli&client_secret=edgeclisecret")
  echo "$R2" | python3 -m json.tool 2>/dev/null || echo "$R2"
  echo
  ACCESS_TOKEN=$(echo "$R2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)
fi

if [ -z "$ACCESS_TOKEN" ]; then
  # Variant 3: scope=openid added (some UAA deployments require it)
  echo "=== Variant 3: with scope=openid ==="
  R3=$(/usr/bin/curl -sk --max-time 15 \
    -X POST "$TOKEN_URL" \
    -u "edgecli:edgeclisecret" \
    -H "Accept: application/json" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=${APIGEE_EMAIL}&passcode=${PASSCODE}&scope=openid")
  echo "$R3" | python3 -m json.tool 2>/dev/null || echo "$R3"
  echo
  ACCESS_TOKEN=$(echo "$R3" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)
fi

if [ -n "$ACCESS_TOKEN" ]; then
  echo "SUCCESS — token obtained!"
  echo "$ACCESS_TOKEN" > /tmp/apigee_token.txt
  echo "Token (first 40 chars): ${ACCESS_TOKEN:0:40}..."
  echo
  echo "Now run:"
  echo "  export APIGEE_TOKEN=\"\$(cat /tmp/apigee_token.txt)\""
  echo "  bash scripts/apigee_mgmt_token_probe.sh"
else
  echo "FAILED — all variants returned no access_token."
  echo "Possible causes:"
  echo "  - Passcode expired (they last ~5 min; get a fresh one)"
  echo "  - edgecli:edgeclisecret not registered on this UAA instance"
  echo "  - Account requires a different client ID"
  echo
  echo "Alternative: capture the token directly from browser DevTools:"
  echo "  1. Open DevTools > Network while on console.apigee.com"
  echo "  2. Look for calls to api.enterprise.apigee.com"
  echo "  3. Copy the Authorization: Bearer <token> header value"
  echo "  4. export APIGEE_TOKEN='<value>'"
  echo "  5. bash scripts/apigee_mgmt_token_probe.sh"
fi
