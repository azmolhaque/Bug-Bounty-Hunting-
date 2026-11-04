#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUT="$HOME/bug-bounty-hunting-/results/apigee/01-recon/dns-http.txt"
mkdir -p "$(dirname "$OUT")"

echo "=== Apigee Edge Management API path probe ===" | tee "$OUT"
for path in \
  "/v1" \
  "/v1/o" \
  "/v1/organizations" \
  "/v1/users" \
  "/v1/userroles" \
  "/v1/mint" \
  "/v1/apimodels" \
  "/v1/identity-providers" \
  "/v1/idps" \
  "/v2" \
  "/v2/organizations"; do
  /usr/bin/curl -sk --max-time 8 -w "%{http_code}" \
    -o /tmp/ap_r.txt "https://api.apigee.com${path}" > /tmp/ap_code.txt 2>/dev/null
  code=$(cat /tmp/ap_code.txt)
  body=$(/usr/bin/head -c 120 /tmp/ap_r.txt)
  printf "%-40s HTTP %s  %s\n" "$path:" "$code" "$body" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "=== registry.apigee.com path probe ===" | tee -a "$OUT"
for path in \
  "/v1" \
  "/v1/projects" \
  "/v1/projects/apigee" \
  "/apis" \
  "/v1/apis" \
  "/api/v1"; do
  /usr/bin/curl -sk --max-time 8 -w "%{http_code}" \
    -o /tmp/ap_r.txt "https://registry.apigee.com${path}" > /tmp/ap_code.txt 2>/dev/null
  code=$(cat /tmp/ap_code.txt)
  body=$(/usr/bin/head -c 120 /tmp/ap_r.txt)
  printf "%-40s HTTP %s  %s\n" "$path:" "$code" "$body" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "=== app.apigee.com (legacy) probe ===" | tee -a "$OUT"
/usr/bin/curl -skL --max-time 10 \
  -w "HTTP_%{http_code}" \
  -o /tmp/ap_app.txt "https://app.apigee.com/" > /tmp/ap_app_code.txt 2>/dev/null
code=$(cat /tmp/ap_app_code.txt)
printf "app.apigee.com: %s\n" "$code" | tee -a "$OUT"
/usr/bin/head -c 300 /tmp/ap_app.txt | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== community.apigee.com platform identification ===" | tee -a "$OUT"
/usr/bin/curl -skL --max-time 10 "https://community.apigee.com/" -o /tmp/ap_comm.txt
echo "Downloaded: $(wc -c < /tmp/ap_comm.txt) bytes"
/usr/bin/grep -oi "salesforce\|jive\|discourse\|wordpress\|lithium\|khoros" /tmp/ap_comm.txt \
  | sort -u | tee -a "$OUT"
/usr/bin/grep -o "title.[^/]*title" /tmp/ap_comm.txt \
  | /usr/bin/head -3 | tee -a "$OUT"
/usr/bin/grep -oE "platform[-_v0-9.]+" /tmp/ap_comm.txt \
  | sort -u | /usr/bin/head -5 | tee -a "$OUT"

echo | tee -a "$OUT"
echo "=== login.apigee.com (Apache) probe ===" | tee -a "$OUT"
/usr/bin/curl -skI --max-time 8 "https://login.apigee.com/" 2>&1 | tee -a "$OUT"
echo "--- Body preview ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 8 "https://login.apigee.com/" -o /tmp/ap_login.txt
/usr/bin/head -c 500 /tmp/ap_login.txt | tee -a "$OUT"

echo
echo "Done. Results in $OUT"
