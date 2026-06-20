#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

echo "=== Fetching www.icrc.org ==="
/usr/bin/curl -skL --max-time 15 --compressed "https://www.icrc.org/" -o /tmp/www_icrc.txt
echo "Downloaded $(wc -c < /tmp/www_icrc.txt) bytes"

echo
echo "=== api.icrc.org references ==="
/usr/bin/grep -oE 'api\.icrc\.org[^"'"'"'<> ]+' /tmp/www_icrc.txt | sort -u | /usr/bin/head -20

echo
echo "=== JS bundle URLs ==="
/usr/bin/grep -oE 'https://[^"]+\.js' /tmp/www_icrc.txt | sort -u | /usr/bin/head -15

echo
echo "=== Fetch first JS bundle and search for api.icrc.org ==="
FIRST_JS=$(/usr/bin/grep -oE 'https://[^"]+\.js' /tmp/www_icrc.txt | /usr/bin/head -1)
if [ -n "$FIRST_JS" ]; then
  echo "Fetching: $FIRST_JS"
  /usr/bin/curl -sk --max-time 20 "$FIRST_JS" -o /tmp/icrc_bundle.js
  echo "Bundle size: $(wc -c < /tmp/icrc_bundle.js) bytes"
  /usr/bin/grep -oE 'api\.icrc\.org[^"'"'"' ]+' /tmp/icrc_bundle.js | sort -u | /usr/bin/head -30
fi

echo
echo "=== Any other icrc.org API hostnames in page ==="
/usr/bin/grep -oE '[a-z-]+\.icrc\.org' /tmp/www_icrc.txt | sort -u
