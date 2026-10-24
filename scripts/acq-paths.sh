#!/usr/bin/env bash
# acq-paths.sh — phase 2: on the hosts that answered, where can you get in?
#
# Looks only for places a person logs in or administers something. Not for
# disclosure: fifteen of this account's reports were closed for describing an
# endpoint, and both that were Fixed came from reaching a control surface and
# then using it.
#
# The hard part is not finding paths, it is not believing a site that answers
# 200 to everything. So every host is baselined first with a path that cannot
# exist, and a probe only counts when it differs from that baseline in status
# or in size. A host whose baseline is already 200 with a real page gets its
# probes compared against that page's size, and ties are reported as ties.
#
# Usage:
#   ./scripts/acq-paths.sh                      # newest live table
#   ./scripts/acq-paths.sh ~/acq/live-X.tsv
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
DELAY="${DELAY:-0.5}"
STAMP="$(date +%Y%m%d-%H%M)"
LOG="$OUT/paths-$STAMP.log"
TSV="${1:-$(ls -1t "$OUT"/live-*.tsv 2>/dev/null | head -1)}"

[ -n "${TSV:-}" ] && [ -f "$TSV" ] || { echo "!! no live table; run acq-live.sh first"; exit 1; }
[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing"; exit 1; }

PATHS=(
  /admin /admin/login /administrator /login /signin
  /console /manage /management /dashboard /portal
  /setup /install
)

UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

fetch() {   # fetch <url> -> "status size"
  # No --max-filesize: curl fails the transfer when a page exceeds it, this
  # function then returns "ERR 0", and "ERR 0" differs from every baseline —
  # so a large page was reported as a path that exists. -m bounds it instead.
  curl -sS -m 10 -o /dev/null -w '%{http_code} %{size_download}' \
       -A "$UA" "$1" 2>/dev/null || printf 'ERR 0'
}

{
echo "# control-surface probe"
echo "# when  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from  : $TSV"
echo "# paths : ${#PATHS[@]} per host, ${DELAY}s apart"
echo

mapfile -t HOSTS < <(awk -F'\t' 'NR>1 && $3 !~ /^(DEAD|ERR)$/ {print $1}' "$TSV" | sort -u)
echo "== ${#HOSTS[@]} host(s) answered in phase 1 =="
echo

hits=0
for h in "${HOSTS[@]}"; do
  "$SCOPE" "$h" >/dev/null 2>&1 || { echo "SKIP $h (out of scope)"; continue; }

  # Baseline: a path that cannot exist. Everything else is read against this.
  base=$(fetch "https://$h/zz-no-such-path-$RANDOM-$RANDOM")
  bst="${base%% *}"; bsz="${base##* }"
  sleep "$DELAY"

  found=""
  for p in "${PATHS[@]}"; do
    r=$(fetch "https://$h$p")
    st="${r%% *}"; sz="${r##* }"
    if [ "$st" != "$bst" ] || [ "$sz" != "$bsz" ]; then
      found="$found  $p -> $st (${sz}b, baseline $bst/${bsz}b)"$'\n'
    fi
    sleep "$DELAY"
  done

  if [ -n "$found" ]; then
    hits=$((hits+1))
    echo "== $h   baseline $bst/${bsz}b"
    printf '%s' "$found"
    echo
  fi
done

echo "== $hits host(s) answered differently on at least one path =="
cat <<'NOTE'

== reading it ==
A path that differs from the baseline exists in some form. That is all it
means. 401 and 403 are doors, not findings; 200 is a door that opened, and
the only question that matters next is what is behind it and whether any of
it belongs to someone else.

Do not report a path. Report what you reached through it.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "log: $LOG"
