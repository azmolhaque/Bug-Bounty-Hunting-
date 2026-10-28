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

# PATHS_FILE replaces the list above, one path per line, '#' for comments.
#
# The built-in list looks for places a person logs in. A gateway answers to a
# different vocabulary entirely, and the question on the intrinsic.ai estate is
# in that other vocabulary: edge.intrinsic.ai answers 401 while edge-dev and
# edge-qa answer 404 from the same nginx, so what matters is whether a health,
# metrics or RPC path on the dev and qa gateways answers without the token the
# production one demands. Asking that with /admin and /dashboard would measure
# nothing and report a zero.
if [ -n "${PATHS_FILE:-}" ]; then
  [ -f "$PATHS_FILE" ] || { echo "!! no path list at $PATHS_FILE"; exit 1; }
  mapfile -t PATHS < <(grep -vE '^[[:space:]]*(#|$)' "$PATHS_FILE" | sed 's/[[:space:]]*$//')
  [ "${#PATHS[@]}" -gt 0 ] || { echo "!! $PATHS_FILE contains no paths"; exit 1; }
fi

UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

fetch() {   # fetch <url> -> "status size redirect-or--"
  # No --max-filesize: curl fails the transfer when a page exceeds it, this
  # function then returns "ERR 0", and "ERR 0" differs from every baseline —
  # so a large page was reported as a path that exists. -m bounds it instead.
  #
  # The redirect target is recorded because on a Google-operated host it is
  # the whole signal: a route that exists and sits behind sign-in answers 302
  # to accounts.google.com, while a route that does not exist answers 404.
  # Status and size alone say "something is different here" and leave you to
  # guess what, which is how a redirect to a marketing page and a redirect
  # into an authenticated app end up looking identical in a report.
  local r
  r="$(curl -sS -m 10 -o /dev/null -w '%{http_code} %{size_download} %{redirect_url}' \
       -A "$UA" "$1" 2>/dev/null)" || r='ERR 0'
  case "$r" in
    *' ') printf '%s-' "$r" ;;   # no redirect: keep three fields
    *)    printf '%s' "$r" ;;
  esac
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
  read -r bst bsz bloc <<<"$base"
  [ "${bloc:-}" = "-" ] && bloc=""   # "-" is the placeholder for "no redirect"
  sleep "$DELAY"

  # A 404 page that echoes the requested path is a few bytes longer for
  # /administrator than for /login, and comparing sizes exactly called that a
  # difference. Every path on myaccount.nest.com came back as a hit that way.
  # So a size difference only counts when it is larger than the paths could
  # explain; a status difference always counts.
  TOL="${TOL:-64}"
  found=""; ndiff=0
  for p in "${PATHS[@]}"; do
    r=$(fetch "https://$h$p")
    read -r st sz loc <<<"$r"
    d=$(( sz > bsz ? sz - bsz : bsz - sz ))
    if [ "$st" != "$bst" ] || [ "$d" -gt "$TOL" ]; then
      ndiff=$((ndiff+1))
      # The baseline's own redirect target is printed alongside, because a host
      # that redirects EVERYTHING to one sign-in page is not telling you that
      # this path exists.
      if [ "${loc:--}" != "-" ]; then
        found="$found  $p -> $st (${sz}b, baseline $bst/${bsz}b) -> $loc"$'\n'
      else
        found="$found  $p -> $st (${sz}b, baseline $bst/${bsz}b)"$'\n'
      fi
    fi
    sleep "$DELAY"
  done

  # If everything differs, nothing does: the host answers the same way to any
  # path and the baseline carries no information about it.
  if [ "$ndiff" -eq "${#PATHS[@]}" ]; then
    echo "== $h   baseline $bst/${bsz}b${bloc:+ -> $bloc}"
    echo "   every path differs — this host answers the same for anything,"
    echo "   so the comparison says nothing. Suppressed."
    echo
    continue
  fi

  if [ -n "$found" ]; then
    hits=$((hits+1))
    echo "== $h   baseline $bst/${bsz}b${bloc:+ -> $bloc}"
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
