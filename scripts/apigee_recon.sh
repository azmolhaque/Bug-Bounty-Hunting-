#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

echo "=== Apigee DNS recon ==="
for host in \
  "apigee.com" \
  "console.apigee.com" \
  "login.apigee.com" \
  "api.apigee.com" \
  "ui.apigee.com" \
  "docs.apigee.com" \
  "community.apigee.com" \
  "enterprise.apigee.com" \
  "accounts.apigee.com" \
  "registry.apigee.com" \
  "portal.apigee.com" \
  "app.apigee.com" \
  "edge.apigee.com" \
  "apigee.google.com"; do
  ip=$(/usr/bin/nslookup "$host" 2>/dev/null | /usr/bin/grep "Address:" | /usr/bin/grep -v "100.100" | /usr/bin/tail -1 | /usr/bin/awk '{print $2}')
  if [ -n "$ip" ]; then
    printf "%-40s %s\n" "$host" "$ip"
  else
    printf "%-40s NXDOMAIN/SERVFAIL\n" "$host"
  fi
done

echo
echo "=== HTTP probe of live hosts ==="
for host in \
  "apigee.com" \
  "console.apigee.com" \
  "login.apigee.com" \
  "api.apigee.com" \
  "docs.apigee.com" \
  "community.apigee.com" \
  "enterprise.apigee.com" \
  "registry.apigee.com" \
  "apigee.google.com"; do
  code=$(/usr/bin/curl -skL --max-time 8 -w "%{http_code}" -o /tmp/ap_resp.txt "https://$host/")
  server=$(/usr/bin/curl -skI --max-time 8 "https://$host/" 2>&1 | /usr/bin/grep -i "^server:" | /usr/bin/head -1 | /usr/bin/tr -d '\r')
  printf "%-40s HTTP %s  %s\n" "$host" "$code" "$server"
done
