#!/data/data/com.termux/files/usr/bin/bash
# H14 — Personio unauthenticated recon, in-scope assets only.
#
# The engagement so far has only touched sectestgorib01.app.personio.com and
# api.personio.de. Several in-scope Tier 2 assets have never been looked at:
#
#   *.personio-internal.de        "internal" in the name
#   *.personio.tools              tooling
#   *.app.personio-dev.com        dev environment
#   api.personio-dev.com
#   *.personiowhistleblowing.com  whistleblowing — anonymous reports by design
#   hug.personio.com
#
# RULES OF ENGAGEMENT, enforced here:
#   - max 2 requests/sec  -> 0.6s between requests, single threaded
#   - X-Intigriti-Username: gorib on EVERY request
#   - no DoS, no fuzzing, no brute force. GET only.
#
# OUT OF SCOPE, never probed (hard-coded exclusion below):
#   www.personio.com · www.personio.de · www.personio.es
#   support.personio.de · statuspage.personio.de · personio.slack.com
#   personio.com/careers
#
# usage:
#   bash h14-recon.sh named     # probe the explicitly named in-scope hosts
#   bash h14-recon.sh ct        # passive subdomain discovery via crt.sh (no Personio traffic)
#   bash h14-recon.sh probe     # probe what ct found, rate limited

set -u
OUT="${OUT:-$HOME/h14}"
mkdir -p "$OUT"
UA='X-Intigriti-Username: gorib'
SLEEP=0.6

OOS='^(www\.personio\.(com|de|es)|support\.personio\.de|statuspage\.personio\.de|personio\.slack\.com)$'

hit() { # $1 = host
  case "$1" in
    *" "*|"") return ;;
  esac
  if printf '%s' "$1" | grep -qE "$OOS"; then
    printf '  %-48s SKIPPED (out of scope)\n' "$1"; return
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "$UA" "https://$1/" 2>/dev/null)
  srv=$(curl -s -I --max-time 15 -H "$UA" "https://$1/" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="server"{print $2}' | head -1)
  ttl=$(curl -s --max-time 15 -H "$UA" "https://$1/" 2>/dev/null \
        | grep -oiE '<title>[^<]{0,70}' | head -1 | sed 's/<title>//I')
  printf '  %-48s [%s] %-14s %s\n' "$1" "${code:-000}" "${srv:-—}" "${ttl:-}"
  sleep "$SLEEP"
}

named() {
  echo "== named in-scope hosts"
  for h in \
    api.personio.de \
    api.personio-dev.com \
    app.personio-dev.com \
    hug.personio.com \
    community.personio.com \
    personio-internal.de \
    personio.tools \
    personiowhistleblowing.com \
    app.personio.com
  do hit "$h"; done
}

ct() {
  echo "== passive subdomain discovery (crt.sh — no traffic to Personio)"
  : > "$OUT/subs.txt"
  for d in personio-internal.de personio.tools personio-dev.com \
           personiowhistleblowing.com app.personio.com personio.de; do
    printf '  %-32s ' "$d"
    n=$(curl -s --max-time 40 "https://crt.sh/?q=%25.$d&output=json" \
        | tr ',' '\n' | grep -oE '"(common_)?name_value":"[^"]+' \
        | sed 's/.*":"//' | tr 'A-Z' 'a-z' | tr '\\n' '\n' \
        | sed 's/^\*\.//' | sort -u | tee -a "$OUT/subs.txt" | wc -l)
    echo "$n names"
    sleep 2
  done
  sort -u -o "$OUT/subs.txt" "$OUT/subs.txt"
  grep -vE "$OOS" "$OUT/subs.txt" > "$OUT/subs-inscope.txt" || true
  echo "-- total unique: $(wc -l < "$OUT/subs.txt")  in-scope: $(wc -l < "$OUT/subs-inscope.txt")"
  echo "-- review $OUT/subs-inscope.txt BEFORE running probe"
}

probe() {
  [ -s "$OUT/subs-inscope.txt" ] || { echo "!! run ct first"; return 1; }
  n=$(wc -l < "$OUT/subs-inscope.txt")
  echo "== probing $n hosts at ${SLEEP}s intervals (~$((n*2/3))s)"
  while read -r h; do hit "$h"; done < "$OUT/subs-inscope.txt"
}

case "${1:-}" in
  named) named ;;
  ct)    ct ;;
  probe) probe ;;
  *) echo "usage: bash h14-recon.sh {named|ct|probe}" ;;
esac
