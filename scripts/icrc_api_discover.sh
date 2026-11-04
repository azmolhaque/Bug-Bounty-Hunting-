#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

BASE="https://www.icrc.org"

echo "=== Fetching www.icrc.org ==="
/usr/bin/curl -skL --max-time 15 --compressed "$BASE/" -o /tmp/www_icrc.txt
echo "Downloaded $(wc -c < /tmp/www_icrc.txt) bytes"

echo
echo "=== Relative JS chunks (/_next/, /sites/, /modules/) ==="
/usr/bin/grep -oE 'src="(/[^"]+\.js)"' /tmp/www_icrc.txt | /usr/bin/grep -oE '/[^"]+\.js' | sort -u | /usr/bin/head -20

echo
echo "=== Absolute JS URLs ==="
/usr/bin/grep -oE 'https://[^"]+\.js' /tmp/www_icrc.txt | sort -u

echo
echo "=== Inline JSON / API references ==="
/usr/bin/grep -oE '"(https?://[^"]*icrc[^"]*)"' /tmp/www_icrc.txt | sort -u | /usr/bin/head -20

echo
echo "=== Drupal settings or Next.js data ==="
/usr/bin/grep -oE 'drupalSettings|__NEXT_DATA__|window\.__' /tmp/www_icrc.txt | sort -u | /usr/bin/head -5

echo
echo "=== All icrc.org subdomains referenced ==="
/usr/bin/grep -oE '[a-z0-9.-]+\.icrc\.org' /tmp/www_icrc.txt | sort -u

echo
echo "=== Fetch analytics.ext.icrc.org bundle + grep for api. ==="
/usr/bin/curl -skL --max-time 15 --compressed \
  "https://analytics.ext.icrc.org/js/container_wmhTexuo.js" \
  -o /tmp/ext_bundle.js
echo "ext bundle: $(wc -c < /tmp/ext_bundle.js) bytes"
/usr/bin/grep -oE '[a-z0-9.-]+\.icrc\.org[^"'"'"' ]*' /tmp/ext_bundle.js | sort -u | /usr/bin/head -30

echo
echo "=== Fetch a content page and check for API calls ==="
/usr/bin/curl -skL --max-time 15 --compressed "$BASE/en/document" -o /tmp/icrc_content.txt
/usr/bin/grep -oE 'api\.icrc\.org[^"'"'"'<> ]+' /tmp/icrc_content.txt | sort -u | /usr/bin/head -20
/usr/bin/grep -oE 'src="(/[^"]+\.js)"' /tmp/icrc_content.txt | /usr/bin/grep -oE '/[^"]+\.js' | sort -u | /usr/bin/head -20
