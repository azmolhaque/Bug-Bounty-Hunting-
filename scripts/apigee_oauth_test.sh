#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUT="$HOME/bug-bounty-hunting-/results/apigee/01-recon/oauth-test.txt"

echo "=== /xredirect open redirect test ===" | tee "$OUT"
# Test 1: bare /xredirect (where does it go with no params?)
echo "--- bare /xredirect ---" | tee -a "$OUT"
/usr/bin/curl -skI --max-time 8 "https://login.apigee.com/xredirect" 2>&1 | tee -a "$OUT"

echo | tee -a "$OUT"
# Test 2: /xredirect with redirect param variants
echo "--- /xredirect with redirect params ---" | tee -a "$OUT"
for param in \
  "redirect=https://example.com" \
  "url=https://example.com" \
  "next=https://example.com" \
  "return=https://example.com" \
  "goto=https://example.com" \
  "target=https://example.com" \
  "dest=https://example.com"; do
  /usr/bin/curl -skI --max-time 8 \
    "https://login.apigee.com/xredirect?${param}" 2>&1 \
    | /usr/bin/grep -E "^HTTP|^Location:" | tee -a "$OUT"
  echo "  param: $param" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "=== OIDC full discovery doc ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 \
  "https://login.apigee.com/.well-known/openid-configuration" | tee -a "$OUT"
echo | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== /token_key (JWKS) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 "https://login.apigee.com/token_key" | tee -a "$OUT"
echo | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== /oauth/authorize redirect_uri test ===" | tee -a "$OUT"
# First: probe with no client_id to see error message
echo "--- no client_id ---" | tee -a "$OUT"
/usr/bin/curl -skI --max-time 8 \
  "https://login.apigee.com/oauth/authorize?response_type=code&redirect_uri=https://example.com" \
  2>&1 | /usr/bin/grep -E "^HTTP|^Location:|error" | tee -a "$OUT"

echo | tee -a "$OUT"
# Probe with known Apigee Edge management UI client_id candidates
echo "--- known client_id candidates ---" | tee -a "$OUT"
for client_id in \
  "edge_management" \
  "apigeeui" \
  "apigee-ui" \
  "management" \
  "apigee_management"; do
  /usr/bin/curl -skI --max-time 8 \
    "https://login.apigee.com/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=https://example.com&state=test123" \
    2>&1 | /usr/bin/grep -E "^HTTP|^Location:|error" | tee -a "$OUT"
  echo "  client_id: $client_id" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "=== /sign_up page ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 "https://login.apigee.com/sign_up" \
  -w "HTTP_%{http_code}" -o /tmp/apigee_signup.txt > /tmp/apigee_signup_code.txt
code=$(cat /tmp/apigee_signup_code.txt)
echo "sign_up: $code" | tee -a "$OUT"
# Check for form action and hidden fields
/usr/bin/grep -o 'action="[^"]*"' /tmp/apigee_signup.txt | tee -a "$OUT"
/usr/bin/grep -o 'type="hidden"[^>]*' /tmp/apigee_signup.txt | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== community.apigee.com Discourse API (following redirects) ===" | tee -a "$OUT"
for path in "/site.json" "/about.json" "/categories.json" \
            "/users.json" "/admin/users/list/active.json" \
            "/session/current.json"; do
  /usr/bin/curl -skL --max-time 8 -w "HTTP_%{http_code}" \
    -H "Accept: application/json" \
    -o /tmp/disc_r.txt "https://community.apigee.com${path}" > /tmp/disc_code.txt
  code=$(cat /tmp/disc_code.txt)
  printf "%-45s %s  " "$path:" "$code"
  /usr/bin/head -c 150 /tmp/disc_r.txt
  echo
done | tee -a "$OUT"

echo
echo "Done. Results: $OUT"
