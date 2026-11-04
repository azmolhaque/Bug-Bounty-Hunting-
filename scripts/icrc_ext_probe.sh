#!/bin/bash
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

EXT="https://ext.icrc.org"

echo "=== Full logout page content ==="
/usr/bin/curl -skL --max-time 10 -D /tmp/ext_headers.txt -o /tmp/ext_root.txt "$EXT/"
echo "--- HTTP Headers ---"
/usr/bin/cat /tmp/ext_headers.txt
echo "--- Body ---"
/usr/bin/cat /tmp/ext_root.txt

echo
echo "=== common.js (reveals app structure) ==="
/usr/bin/curl -skL --max-time 10 -w "HTTP_%{http_code}" \
  -o /tmp/ext_common_js.txt "$EXT/public/include/js/common.js"
echo
/usr/bin/head -c 1000 /tmp/ext_common_js.txt

echo
echo "=== Path discovery ==="
for path in \
  "/login" "/login.php" "/login/" \
  "/index.php" "/index.html" \
  "/public/" \
  "/admin" "/admin/" \
  "/api" "/api/" "/api/v1" \
  "/logout" \
  "/home" "/dashboard" \
  "/apm" "/apm/" \
  "/portal" "/portal/" \
  "/app" "/app/"; do
  resp=$(/usr/bin/curl -skL --max-time 8 -w "HTTP_%{http_code}" -o /tmp/ext_p.txt "$EXT$path")
  code=$(echo "$resp" | /usr/bin/grep -oE '[0-9]{3}$')
  printf "%-30s HTTP %s  (%d bytes)\n" "$path" "$code" "$(wc -c < /tmp/ext_p.txt)"
done

echo
echo "=== apm.css (reveals more JS/structure clues) ==="
/usr/bin/curl -skL --max-time 10 -w "HTTP_%{http_code}" \
  -o /tmp/ext_apm_css.txt "$EXT/public/include/css/apm.css"
echo
/usr/bin/head -c 500 /tmp/ext_apm_css.txt
