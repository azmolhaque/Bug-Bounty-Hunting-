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

hit() { # $1 = host   — ONE request per host, not three
  case "$1" in *" "*|"") return ;; esac
  if printf '%s' "$1" | grep -qE "$OOS"; then
    printf '  %-52s SKIPPED (out of scope)\n' "$1"; return
  fi
  # Single GET: headers to a temp file, body to stdout. Three separate curls here
  # would have been ~5 req/s against the 2 req/s cap in the rules of engagement.
  body=$(curl -s -D "$OUT/.hdr" -o - --max-time 15 -H "$UA" "https://$1/" 2>/dev/null | head -c 4000)
  code=$(awk 'NR==1{print $2}' "$OUT/.hdr" 2>/dev/null)
  srv=$(tr -d '\r' < "$OUT/.hdr" 2>/dev/null | awk -F': ' 'tolower($1)=="server"{print $2}' | head -1)
  ttl=$(printf '%s' "$body" | grep -oiE '<title>[^<]{0,60}' | head -1 | sed 's/<title>//I')
  printf '  %-52s [%s] %-12s %s\n' "$1" "${code:-000}" "${srv:-—}" "${ttl:-}"
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
           personiowhistleblowing.com personio.com personio.de; do
    printf '  %-32s ' "$d"
    curl -s --max-time 60 "https://crt.sh/?q=%25.$d&output=json" > "$OUT/ct-$d.json"
    # JSON parsing in python: name_value holds newline-separated SANs.
    # (A previous tr-based version split on the letter 'n' and mangled every name.)
    n=$(python3 - "$OUT/ct-$d.json" <<'PYEOF' | tee -a "$OUT/subs.txt" | wc -l
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit()
out=set()
for r in d:
    for k in ("name_value","common_name"):
        for v in str(r.get(k,"")).split("\n"):
            v=v.strip().lower().lstrip("*.")
            if v and " " not in v: out.add(v)
print("\n".join(sorted(out)))
PYEOF
)
    echo "$n names"
    sleep 2
  done
  sort -u -o "$OUT/subs.txt" "$OUT/subs.txt"
  grep -vE "$OOS" "$OUT/subs.txt" > "$OUT/subs-inscope.txt" || true
  echo "-- total unique: $(wc -l < "$OUT/subs.txt")  in-scope: $(wc -l < "$OUT/subs-inscope.txt")"
  echo
  echo "-- most interesting (mcp / agent / llm / dev / internal / sec / gitlab):"
  grep -iE 'mcp|agent|llm|copilot|rag|gitlab|internal|\bsec\.|bi-dev|bi-prod|stge|uat|test' \
    "$OUT/subs-inscope.txt" | head -60
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
