#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

MATOMO="https://matomo.ext.icrc.org"
EXT="https://ext.icrc.org"

echo "=== ext.icrc.org root ==="
/usr/bin/curl -skL --max-time 10 -w "HTTP_%{http_code}" -o /tmp/ext_root.txt "$EXT/"
echo
/usr/bin/head -c 300 /tmp/ext_root.txt
echo

echo
echo "=== matomo.ext.icrc.org root ==="
/usr/bin/curl -skL --max-time 10 -w "HTTP_%{http_code}" \
  -D /tmp/matomo_headers.txt \
  -o /tmp/matomo_root.txt "$MATOMO/"
echo
/usr/bin/head -c 500 /tmp/matomo_root.txt
echo
echo "--- Headers ---"
/usr/bin/cat /tmp/matomo_headers.txt

echo
echo "=== Matomo login page ==="
/usr/bin/curl -skL --max-time 10 -w "HTTP_%{http_code}" \
  -o /tmp/matomo_login.txt \
  "$MATOMO/index.php?module=Login"
echo
/usr/bin/grep -oE '(matomo|piwik)[^"]*version[^"]*"|"[0-9]+\.[0-9]+\.[0-9]+"' /tmp/matomo_login.txt | /usr/bin/head -5
/usr/bin/grep -oE 'form action="[^"]+"' /tmp/matomo_login.txt | /usr/bin/head -3

echo
echo "=== Matomo unauthenticated API (token_auth=anonymous) ==="
for method in \
  "API.getMatomoVersion" \
  "API.getPhpVersion" \
  "SitesManager.getAllSites" \
  "UsersManager.getUsers" \
  "API.getSettings"; do
  resp=$(/usr/bin/curl -sk --max-time 8 \
    "$MATOMO/index.php?module=API&method=${method}&token_auth=anonymous&format=JSON")
  code=$(echo "$resp" | /usr/bin/grep -c '"result":"error"')
  echo "  $method: $(echo "$resp" | /usr/bin/head -c 120)"
  echo
done

echo
echo "=== Matomo Installation page (left-over setup) ==="
/usr/bin/curl -skL --max-time 8 -w "HTTP_%{http_code}" \
  -o /tmp/matomo_install.txt \
  "$MATOMO/index.php?module=Installation"
echo
/usr/bin/head -c 200 /tmp/matomo_install.txt
echo

echo
echo "=== Matomo API with idSite=1 ==="
/usr/bin/curl -sk --max-time 8 \
  "$MATOMO/index.php?module=API&method=VisitsSummary.get&idSite=1&period=day&date=today&token_auth=anonymous&format=JSON"
echo
