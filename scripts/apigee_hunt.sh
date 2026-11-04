#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUT="$HOME/bug-bounty-hunting-/results/apigee/01-recon/hunt.txt"

echo "=== login.apigee.com (CloudFoundry UAA) probe ===" | tee "$OUT"

echo "--- /info (UAA version + prompts) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 "https://login.apigee.com/info" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- /.well-known/openid-configuration ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 "https://login.apigee.com/.well-known/openid-configuration" \
  -o /tmp/uaa_oidc.txt
/usr/bin/head -c 600 /tmp/uaa_oidc.txt | tee -a "$OUT"
echo | tee -a "$OUT"

echo "--- Spring Boot actuator endpoints ---" | tee -a "$OUT"
for path in "/actuator" "/actuator/env" "/actuator/health" "/actuator/info" \
            "/actuator/metrics" "/actuator/mappings" "/health" "/healthz"; do
  /usr/bin/curl -sk --max-time 8 -w "HTTP_%{http_code}" \
    -o /tmp/uaa_act.txt "https://login.apigee.com${path}" > /tmp/uaa_act_code.txt
  code=$(cat /tmp/uaa_act_code.txt)
  printf "%-40s %s  " "$path:" "$code"
  /usr/bin/head -c 80 /tmp/uaa_act.txt
  echo
done | tee -a "$OUT"

echo | tee -a "$OUT"
echo "--- UAA OAuth endpoints ---" | tee -a "$OUT"
for path in \
  "/oauth/token" \
  "/oauth/authorize" \
  "/check_token" \
  "/userinfo" \
  "/passcode" \
  "/identity-providers" \
  "/login"; do
  /usr/bin/curl -sk --max-time 8 -w "HTTP_%{http_code}" \
    -o /tmp/uaa_oauth.txt "https://login.apigee.com${path}" > /tmp/uaa_oauth_code.txt
  code=$(cat /tmp/uaa_oauth_code.txt)
  printf "%-40s %s  " "$path:" "$code"
  /usr/bin/head -c 100 /tmp/uaa_oauth.txt
  echo
done | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== api.apigee.com with Accept: application/json ===" | tee -a "$OUT"
for path in "/v1/o" "/v1/organizations" "/v1/users" "/v1/userroles" "/v1/mint"; do
  /usr/bin/curl -sk --max-time 8 -w "HTTP_%{http_code}" \
    -H "Accept: application/json" \
    -o /tmp/ap_json.txt "https://api.apigee.com${path}" > /tmp/ap_json_code.txt
  code=$(cat /tmp/ap_json_code.txt)
  printf "%-40s %s  " "$path:" "$code"
  /usr/bin/head -c 150 /tmp/ap_json.txt
  echo
done | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== community.apigee.com Discourse API (unauthenticated) ===" | tee -a "$OUT"
for path in \
  "/site.json" \
  "/categories.json" \
  "/users.json" \
  "/admin/users/list/active.json" \
  "/session/current.json" \
  "/about.json" \
  "/admin.json"; do
  /usr/bin/curl -sk --max-time 8 -w "HTTP_%{http_code}" \
    -H "Accept: application/json" \
    -o /tmp/disc.txt "https://community.apigee.com${path}" > /tmp/disc_code.txt
  code=$(cat /tmp/disc_code.txt)
  printf "%-40s %s  " "$path:" "$code"
  /usr/bin/head -c 150 /tmp/disc.txt
  echo
done | tee -a "$OUT"

echo
echo "Done. Results: $OUT"
