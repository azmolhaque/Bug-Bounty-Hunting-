#!/data/data/com.termux/files/usr/bin/bash
# T01 — Tesla passive asset discovery + rate-limited probing.
#
# WHY THIS SHAPE
#   Tesla has been hunted since 2015 (983 bugs, 528 researchers recently joined). Depth on
#   tesla.com is a losing bet. Breadth across the neglected estates is not: the brief itself
#   puts "any host verified to be owned by Tesla Motors Inc." in scope, which is an invitation
#   to recon.
#
# RULES OF ENGAGEMENT — in the code, not the comment (FO-21)
#   - "Do not attempt to use brute force or denial of service attacks": single threaded,
#     0.5s between requests, GET only, no path wordlists, no form submissions.
#   - Out-of-scope hosts are excluded below by pattern and never requested (FO-22: redirects
#     are NOT followed, because a redirect can land on an out-of-scope host).
#   - Stage 1 sends zero traffic to Tesla. It reads certificate transparency logs only.
#
# usage:
#   bash t01-recon.sh ct        # passive: crt.sh only, no Tesla traffic
#   bash t01-recon.sh probe     # one GET per host, rate limited
#   bash t01-recon.sh triage    # local analysis of what probe found

set -u
OUT="${OUT:-$HOME/tesla}"; mkdir -p "$OUT"
SLEEP=0.5

# Ordered by neglect, not by size. tesla.com is deliberately last.
DOMAINS="tesla.services solarcity.com teslainsuranceservices.com tesla.cn teslamotors.com tesla.com"

# Hard exclusion. Every one of these is named out of scope in the brief.
OOS='^(employeefeedback\.tesla\.com|energysupport\.tesla\.com|engage\.tesla\.com|.*\.engage\.tesla\.com|feedback\.tesla\.com|feedback\.teslamotors\.com|ir\.tesla\.com|ir\.teslamotors\.com|mkto\.teslamotors\.com|shop\.eu\.teslamotors\.com|.*maxwell\.com)$'

ct() {
  echo "== passive discovery via crt.sh — no traffic to Tesla"
  : > "$OUT/subs-raw.txt"
  for d in $DOMAINS; do
    printf '  %-30s ' "$d"
    curl -s --max-time 120 "https://crt.sh/?q=%25.$d&output=json" > "$OUT/ct-$d.json"
    n=$(python3 - "$OUT/ct-$d.json" <<'PYEOF' | tee -a "$OUT/subs-raw.txt" | wc -l
import json,sys
try: rows=json.load(open(sys.argv[1]))
except Exception: raise SystemExit
out=set()
for r in rows:
    for k in ("name_value","common_name"):
        for v in str(r.get(k,"")).split("\n"):
            v=v.strip().lower().lstrip("*.")
            if v and " " not in v and "@" not in v:
                out.add(v)
print("\n".join(sorted(out)))
PYEOF
)
    echo "$n names"
    sleep 3
  done
  sort -u -o "$OUT/subs-raw.txt" "$OUT/subs-raw.txt"
  grep -vE "$OOS" "$OUT/subs-raw.txt" > "$OUT/subs.txt" || true
  echo "-- unique: $(wc -l < "$OUT/subs-raw.txt")   in scope: $(wc -l < "$OUT/subs.txt")"
  echo
  echo "-- names that look like something other than marketing:"
  grep -iE 'dev|stag|staging|uat|qa|test|internal|intranet|admin|api|legacy|old|beta|demo|sandbox|jenkins|gitlab|git|grafana|kibana|jira|confluence|vpn|portal|partner|vendor|supplier|sso|auth|oauth|upload|files|backup|s3|tool|dashboard|report|console' \
    "$OUT/subs.txt" | tee "$OUT/interesting.txt" | head -60
  echo "-- $(wc -l < "$OUT/interesting.txt") flagged for probing first"
}

hit() { # $1 host — ONE request. No -L: a redirect may point out of scope (FO-22).
  case "$1" in *" "*|"") return;; esac
  if printf '%s' "$1" | grep -qE "$OOS"; then
    printf '  %-46s SKIPPED (out of scope)\n' "$1"; return
  fi
  body=$(curl -s -D "$OUT/.hdr" -o - --max-time 15 "https://$1/" 2>/dev/null | head -c 3000)
  code=$(awk 'NR==1{print $2}' "$OUT/.hdr" 2>/dev/null)
  [ -z "${code:-}" ] && { printf '  %-46s %s\n' "$1" "no response"; sleep "$SLEEP"; return; }
  srv=$(tr -d '\r' < "$OUT/.hdr" | awk -F': ' 'tolower($1)=="server"{print $2}' | head -1)
  loc=$(tr -d '\r' < "$OUT/.hdr" | awk -F': ' 'tolower($1)=="location"{print $2}' | head -1)
  ttl=$(printf '%s' "$body" | grep -oiE '<title>[^<]{0,60}' | head -1 | sed 's/<title>//I')
  printf '  %-46s [%s] %-14s %s%s\n' "$1" "$code" "${srv:-—}" "${ttl:-}" "${loc:+ -> $loc}" \
    | tee -a "$OUT/probe.txt"
  sleep "$SLEEP"
}

probe() {
  L="${1:-$OUT/interesting.txt}"
  [ -s "$L" ] || { echo "!! run ct first, or pass a host list"; return 1; }
  n=$(wc -l < "$L")
  echo "== probing $n hosts, one GET each, ${SLEEP}s apart (~$((n/2))s)"
  : > "$OUT/probe.txt"
  while read -r h; do hit "$h"; done < "$L"
  echo "-- saved to $OUT/probe.txt"
}

triage() {
  [ -s "$OUT/probe.txt" ] || { echo "!! run probe first"; return 1; }
  echo "== live and NOT a redirect to the marketing site"
  grep -E '\[(200|401|403)\]' "$OUT/probe.txt" | grep -viE 'www\.tesla|-> https://www\.tesla' | head -40
  echo
  echo "== auth-shaped (401/403 means something is there and guarded)"
  grep -E '\[(401|403)\]' "$OUT/probe.txt" | head -25
  echo
  echo "== servers that are not the usual CDN front"
  awk -F'] ' '{print $2}' "$OUT/probe.txt" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
}

case "${1:-}" in
  ct) ct ;;
  probe) probe "${2:-}" ;;
  triage) triage ;;
  *) echo "usage: bash t01-recon.sh {ct|probe [hostlist]|triage}" ;;
esac
