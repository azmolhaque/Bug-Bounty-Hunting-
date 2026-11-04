#!/data/data/com.termux/files/usr/bin/bash
# H14 T6 — mine the web app's JS bundles for the internal API surface.
#
# WHY
#   T2 (can LOWPRIV assign itself a role?) needs the endpoint the admin UI calls.
#   Role assignment is not in the public v1/v2 API — it is an internal XHR. That
#   endpoint is written, in plain text, inside the SPA's JavaScript.
#
#   This is the Adobe play: the whole agentic tool registry came out of a public
#   login page's bundle there, with no authenticated request at all.
#
# WHAT THIS IS NOT
#   Not fuzzing, not scanning. It fetches assets the browser fetches anyway, then
#   reads them locally. Every grep below runs against files on disk.
#
# RULES OF ENGAGEMENT — in the code, not the comment (FO-21):
#   0.6s between requests, single threaded, X-Intigriti-Username on every fetch.
#
# usage:
#   bash h14-jsmine.sh fetch     # pull the HTML + JS bundles
#   bash h14-jsmine.sh routes    # extract API routes
#   bash h14-jsmine.sh roles     # hunt specifically for role / permission endpoints

set -u
HOST='sectestgorib01.app.personio.com'
UA='X-Intigriti-Username: gorib'
SLEEP=0.6
OUT="${OUT:-$HOME/h14/js}"; mkdir -p "$OUT"

fetch() {
  echo "== entry points"
  for p in / /login /staff/details/39463216; do
    f="$OUT/page$(echo "$p" | tr '/' '_').html"
    code=$(curl -s -o "$f" -w '%{http_code}' --max-time 20 -H "$UA" "https://$HOST$p")
    printf '  %-32s [%s] %s bytes\n' "$p" "$code" "$(wc -c < "$f")"
    sleep "$SLEEP"
  done

  echo
  echo "== javascript referenced by those pages"
  grep -ohoE '(src|href)="[^"]+\.js[^"]*"' "$OUT"/page*.html 2>/dev/null \
    | sed -E 's/^(src|href)="//; s/"$//' | sort -u > "$OUT/js-urls.txt"
  # also catch bundler manifests that list chunks as bare strings
  grep -ohoE '"[^"]*\.js"' "$OUT"/page*.html 2>/dev/null \
    | tr -d '"' | sort -u >> "$OUT/js-urls.txt"
  sort -u -o "$OUT/js-urls.txt" "$OUT/js-urls.txt"
  echo "   $(wc -l < "$OUT/js-urls.txt") candidate urls"

  n=0
  while read -r u; do
    [ -z "$u" ] && continue
    case "$u" in
      http*) full="$u" ;;
      //*)   full="https:$u" ;;
      /*)    full="https://$HOST$u" ;;
      *)     full="https://$HOST/$u" ;;
    esac
    n=$((n+1))
    f="$OUT/bundle-$n.js"
    code=$(curl -s -o "$f" -w '%{http_code}' --max-time 30 -H "$UA" "$full")
    printf '  %-3s [%s] %-9s %s\n' "$n" "$code" "$(wc -c < "$f")b" "${full:0:80}"
    sleep "$SLEEP"
  done < "$OUT/js-urls.txt"
  echo "-- bundles in $OUT"
}

routes() {
  echo "== API routes found in the bundles (local grep, no requests)"
  cat "$OUT"/bundle-*.js 2>/dev/null \
    | grep -ohoE '"/(api|rest)/[a-zA-Z0-9/_.{}$-]{3,70}"' \
    | tr -d '"' | sort -u > "$OUT/routes.txt"
  cat "$OUT"/bundle-*.js 2>/dev/null \
    | grep -ohoE '`/(api|rest)/[a-zA-Z0-9/_.{}$-]{3,70}`' \
    | tr -d '`' | sort -u >> "$OUT/routes.txt"
  sort -u -o "$OUT/routes.txt" "$OUT/routes.txt"
  echo "   $(wc -l < "$OUT/routes.txt") distinct routes"
  head -80 "$OUT/routes.txt"
}

roles() {
  echo "== anything role / permission / admin shaped"
  cat "$OUT"/bundle-*.js 2>/dev/null \
    | grep -ohoE '["`][^"`]{0,90}(role|permission|privilege|grant|admin)[^"`]{0,60}["`]' \
    | tr -d '"`' | grep -iE '/' | sort -u | head -60
  echo
  echo "== employee / salary / document routes"
  grep -iE 'salary|compensation|document|payroll' "$OUT/routes.txt" 2>/dev/null | head -40
}

case "${1:-}" in
  fetch)  fetch ;;
  routes) routes ;;
  roles)  roles ;;
  *) echo "usage: bash h14-jsmine.sh {fetch|routes|roles}" ;;
esac
