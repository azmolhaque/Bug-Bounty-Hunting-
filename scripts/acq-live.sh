#!/usr/bin/env bash
# acq-live.sh — phase 1 on the acquisition scope: what is alive, and what is it.
#
# Why this scope and this shape. Of 25 reports, two were Fixed:
#   support.pring.jp   — a host taken over
#   rip.photomath.net  — default admin credentials
# Both on acquisitions, both ending in control of something rather than a
# description of a misconfiguration. Fifteen closures were the other kind.
# So: acquisitions first, and the thing being looked for is a control surface.
#
# This phase only asks which hosts answer and what they say they are. One
# request per host, nothing probed, nothing guessed. Path probing comes after,
# against the short list this produces, so the noisy part runs over dozens of
# hosts rather than thirteen hundred.
#
# Usage:
#   ./scripts/acq-live.sh                 # TIER0 and TIER1
#   TIERS=TIER0 ./scripts/acq-live.sh
#   nohup ./scripts/acq-live.sh > ~/acq-live.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PB="${PB:-$ROOT/config/acquisitions_domains_tiers.asciipb}"
SCOPE="$HERE/scope-check.sh"
TIERS="${TIERS:-TIER0,TIER1}"
DELAY="${DELAY:-0.4}"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)"
# Written under .partial and renamed only when the sweep finishes. Twice now a
# recheck was built from `ls -1t live-*.tsv | head -1` while this was still
# running, giving 52 hosts once and 12 the next time and reading as a result
# both times. A half-written table should not be reachable by the name
# everything else looks for.
TSV_FINAL="$OUT/live-$STAMP.tsv"
TSV="$TSV_FINAL.partial"
LOG="$OUT/live-$STAMP.log"

[ -f "$PB" ]    || { echo "!! no acquisitions file at $PB"; exit 1; }
[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }
command -v curl >/dev/null || { echo "!! curl missing"; exit 1; }

probe() {   # probe <host> -> "status<TAB>server<TAB>title"
  local h="$1" hdr body st srv ti
  hdr=$(mktemp); body=$(mktemp)
  # No --max-filesize. curl treats exceeding it as a transfer failure, so a
  # large home page is recorded as DEAD: www.waze.com (348 KB), wing.com
  # (646 KB) and tenor.com (273 KB) were all filed as dead hosts by this line.
  # -m 10 already bounds the request.
  # Same trap as --max-filesize above, in a different flag. --max-redirs 3 made
  # curl exit 47 on any longer chain, and exit 47 was being read as DEAD:
  # mail.google.com, myaccount.google.com, passwords.google.com,
  # admin.google.com and ediscovery.google.com — five TIER0 hosts of the main
  # Google program — were all filed as dead while answering normally. A host
  # that answers anything is not dead; only a connection that never completes
  # is. So the limit is raised, and if the chain still fails we record the
  # FIRST response instead of throwing the host away.
  if ! curl -sS -m 10 -L --max-redirs 10 \
       -A 'Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)' \
       -D "$hdr" -o "$body" "https://$h/" 2>/dev/null; then
    : > "$hdr"; : > "$body"
    if ! curl -sS -m 10 \
         -A 'Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)' \
         -D "$hdr" -o "$body" "https://$h/" 2>/dev/null; then
      rm -f "$hdr" "$body"; printf 'DEAD\t\t'; return
    fi
  fi
  st=$(awk 'tolower($1) ~ /^http/ {s=$2} END{print s}' "$hdr")
  srv=$(awk 'BEGIN{IGNORECASE=1} /^server:/{sub(/^[Ss]erver:[ \t]*/,""); gsub(/\r/,""); print; exit}' "$hdr")
  ti=$(tr '\n' ' ' < "$body" | grep -oiE '<title[^>]*>[^<]{0,120}' | head -1 | sed 's/<[^>]*>//' | sed 's/^[ \t]*//;s/[ \t]*$//')
  rm -f "$hdr" "$body"
  printf '%s\t%s\t%s' "${st:-?}" "${srv:-}" "${ti:-}"
}

{
echo "# acquisition liveness sweep"
echo "# when  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# tiers : $TIERS"
echo

# ---- control 1: a host that must answer ----
# If this comes back DEAD the network or DNS is broken, and every DEAD below
# would be a statement about this machine rather than about the target.
CTL_OK=$(probe www.appsheet.com | cut -f1)
case "$CTL_OK" in
  2*|3*|4*) echo "POSITIVE  www.appsheet.com -> HTTP $CTL_OK" ;;
  *) echo "!! BROKEN: the known-live control came back '$CTL_OK'."
     echo "!!         Fix connectivity before trusting anything below."; exit 2 ;;
esac

# ---- control 2: a host that must not ----
# A resolver that answers everything (captive portal, ISP wildcard) would make
# every host look alive. This has to fail.
CTL_BAD=$(probe nonexistent-canary-"$RANDOM".appsheet.com | cut -f1)
case "$CTL_BAD" in
  DEAD) echo "NEGATIVE  nonexistent host -> DEAD" ;;
  *) echo "!! BROKEN: a host that does not exist answered with '$CTL_BAD'."
     echo "!!         Something is answering for every name; results are noise."; exit 2 ;;
esac

# ---- control 3: a long redirect chain is not death ----
# The defect this guards against wrote DEAD against mail.google.com. There is
# no portable host guaranteed to redirect more than ten times, so instead of
# hunting one, this forces the failure: --max-redirs 0 against a host that is
# known to redirect makes the first curl fail exactly as a deep chain does,
# and the fallback has to record a status anyway.
CTL_REDIR=$(curl -sS -m 10 -L --max-redirs 0 -o /dev/null -w '%{http_code}' \
            "http://google.com/" 2>/dev/null; echo " rc=$?")
case "$CTL_REDIR" in
  *"rc=0"*) echo "   note: --max-redirs 0 did not fail here; control 3 is not exercising the path" ;;
  *) CTL_FB=$(probe mail.google.com | cut -f1)
     case "$CTL_FB" in
       DEAD) echo "!! BROKEN: a host behind a long redirect chain still reads as DEAD."
             echo "!!         That is the defect this control exists for; fix probe() first."; exit 2 ;;
       *) echo "POSITIVE  a host behind a long redirect chain reads as HTTP $CTL_FB, not DEAD" ;;
     esac ;;
esac
echo

# fqdn + tier out of the protobuf text, filtered to the tiers asked for.
#
# HOSTS_FILE overrides it with one hostname per line. That exists because the
# protobuf is Google's inventory, not the boundary: domains carrying
# propagate_tier_to_direct_subdomains put unlisted direct subdomains in scope,
# and those names come from certificate transparency rather than from this
# file. They still go through scope-check below like everything else — the
# list only says what to consider, never what is allowed.
if [ -n "${HOSTS_FILE:-}" ]; then
  [ -f "$HOSTS_FILE" ] || { echo "!! no host list at $HOSTS_FILE"; exit 1; }
  mapfile -t HOSTS < <(grep -vE '^\s*(#|$)' "$HOSTS_FILE" \
                       | tr 'A-Z' 'a-z' | sed 's/[[:space:]]*$//' \
                       | awk -v t="${TIER_LABEL:-CT}" 'NF {print $1 "\t" t}' | sort -u)
  echo "== ${#HOSTS[@]} host(s) from $(basename "$HOSTS_FILE") =="
else
mapfile -t HOSTS < <(awk -v want="$TIERS" '
  /fqdn:/ { f=$2; gsub(/"/,"",f) }
  /tier:/ { t=$2; if (f!="" && index(want,t)) print f "\t" t; f="" }
' "$PB" | sort -u)

echo "== ${#HOSTS[@]} host(s) in $TIERS =="
fi
printf 'host\ttier\tstatus\tserver\ttitle\n' > "$TSV"

n=0; live=0; skipped=0
for e in "${HOSTS[@]}"; do
  h="${e%%$'\t'*}"; t="${e##*$'\t'}"
  n=$((n+1))
  # CLAUDE.md 0: nothing is touched that scope-check does not bless.
  if ! "$SCOPE" "$h" >/dev/null 2>&1; then
    skipped=$((skipped+1)); continue
  fi
  r=$(probe "$h")
  printf '%s\t%s\t%s\n' "$h" "$t" "$r" >> "$TSV"
  case "${r%%$'\t'*}" in DEAD) ;; *) live=$((live+1)) ;; esac
  [ $((n % 50)) -eq 0 ] && echo "   ... $n/${#HOSTS[@]}  live=$live"
  sleep "$DELAY"
done

echo
echo "== $live answered, $((n-live-skipped)) dead, $skipped out of scope =="
echo
echo "== control surfaces worth a second look =="
awk -F'\t' 'NR>1 && $3 !~ /^(DEAD|40[134]|5)/ {
    t=tolower($5)
    if (t ~ /admin|login|sign in|dashboard|console|portal|panel|jenkins|grafana|kibana|swagger|phpmyadmin|gitlab|airflow|rancher|argo|prometheus|setup|install/)
      printf "%-45s %-7s %-5s %s\n", $1, $2, $3, $5
  }' "$TSV" | sort | head -60

cat <<'NOTE'

== what to do with this ==
A title saying "login" is not a finding and neither is a live host. It is a
place to go and ask the only question that has ever paid here: can I get in,
and once in, what is mine that should not be?

Both Fixed reports in this account came from that question. Fifteen closures
came from stopping at the description.
NOTE
} 2>&1 | tee "$LOG"

echo
mv -f "$TSV" "$TSV_FINAL"
echo "table : $TSV_FINAL"
echo "log   : $LOG"
