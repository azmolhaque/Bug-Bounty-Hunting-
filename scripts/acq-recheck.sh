#!/usr/bin/env bash
# acq-recheck.sh — the hosts acq-live.sh called DEAD, asked again without
# certificate verification.
#
# Why: acq-live.sh verifies TLS, so any host serving an expired, mismatched or
# unchained certificate comes back DEAD. myhelp.fitbit.com is exactly that —
# a live Fitbit support portal on a certificate that expired on 2026-09-27,
# filed under "dead" and never looked at. Neglected-but-serving is the most
# interesting state a host can be in, and the sweep was hiding it.
#
# This is a bash script rather than a loop at the prompt because the loop at
# the prompt got it wrong three ways: `set -- $r` does not word-split in zsh
# (our own defect 22, repeated), a failed curl left the previous host's body
# in the temp file so titles belonged to the wrong hosts, and failures printed
# as if they were results. The count came out "140 / 140 alive", which was the
# number of lines printed and nothing else.
#
# Usage:
#   SCOPE_FILE=$PWD/config/scope-acquisitions.yaml ./scripts/acq-recheck.sh ~/acq/dead.txt
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
LIST="${1:-$HOME/acq/dead.txt}"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)"
TSV="$OUT/recheck-$STAMP.tsv"
DELAY="${DELAY:-0.4}"
UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

[ -f "$LIST" ]  || { echo "!! no host list at $LIST"; exit 1; }
[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing"; exit 1; }

body=$(mktemp); trap 'rm -f "$body"' EXIT

probe() {   # probe <host> -> "code<TAB>size<TAB>tls<TAB>title"  (empty on failure)
  # Two attempts, because one cannot answer both questions.
  #
  # With -k, curl stops verifying and `%{ssl_verify_result}` stops meaning
  # anything — it came back 20 for www.waze.com, tenor.com and every other
  # host, which read as "the whole acquisition map is on broken certificates"
  # when the certificates were fine and the flag was the problem.
  #
  # So: verify first and keep that verdict, then, only if verification failed,
  # fetch the body insecurely to see what is being served.
  : > "$body"
  local w code tls title strict rc
  strict=$(curl -sS -m 10 -A "$UA" \
             -o "$body" -w '%{http_code}\t%{size_download}\t%{ssl_verify_result}' \
             "https://$1/" 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    tls=ok
    w="$strict"
  else
    # Keep the verification verdict from the strict attempt before retrying.
    # A verify code if curl produced one, otherwise curl's own exit code,
    # labelled so the two cannot be read off the same scale.
    tls="${strict##*$'\t'}"
    case "$tls" in ''|*[!0-9]*|0) tls="e$rc" ;; esac
    : > "$body"
    w=$(curl -sS -k -m 10 -A "$UA" \
          -o "$body" -w '%{http_code}\t%{size_download}\tx' \
          "https://$1/" 2>/dev/null) || return 1
  fi
  code="${w%%$'\t'*}"
  [ "$code" = "000" ] && return 1
  local size="${w#*$'\t'}"; size="${size%%$'\t'*}"
  title=$(tr '\n' ' ' < "$body" | grep -oiE '<title[^>]*>[^<]{0,90}' | head -1 \
          | sed 's/<[^>]*>//; s/^[ \t]*//; s/[ \t]*$//')
  printf '%s\t%s\t%s\t%s' "$code" "$size" "$tls" "$title"
}

# ---- controls ----
# A host that must answer, and one that must not. Without both, "n of m
# answered" is a statement about this machine.
echo "== CONTROL =="
# www.appsheet.com, because acq-live.sh already uses it as its control and it
# is therefore known to answer from this machine. The first version used
# www.waze.com, whose page is larger than the --max-filesize that was set
# here, so the control failed for a reason that had nothing to do with
# connectivity.
CTL="${CTL_HOST:-www.appsheet.com}"
if ! probe "$CTL" >/dev/null; then
  echo "!! BROKEN: $CTL did not answer, so every 'no answer' below would be"
  echo "!!         about this machine. Check connectivity, or set CTL_HOST."
  exit 2
fi
echo "POSITIVE  $CTL answered"
if probe "nonexistent-canary-$RANDOM.appsheet.com" >/dev/null; then
  echo "!! BROKEN: a host that does not exist answered."; exit 2
fi
echo "NEGATIVE  a nonexistent host did not"
echo

printf 'host\tcode\tsize\ttls\ttitle\n' > "$TSV"
n=0; alive=0; skipped=0
while read -r h; do
  [ -n "$h" ] || continue
  n=$((n+1))
  if ! "$SCOPE" "$h" >/dev/null 2>&1; then skipped=$((skipped+1)); continue; fi
  if r=$(probe "$h"); then
    alive=$((alive+1))
    printf '%s\t%s\n' "$h" "$r" >> "$TSV"
    IFS=$'\t' read -r code size tls title <<<"$r"
    printf '  %-44s %-4s %8sb  tls=%-3s %s\n' "$h" "$code" "$size" "$tls" "$title"
  fi
  sleep "$DELAY"
done < "$LIST"

echo
echo "== $alive of $n answered without certificate verification ($skipped out of scope) =="
echo "table: $TSV"

cat <<'NOTE'

== reading tls= ==
  ok  verification passed; acq-live.sh called it DEAD for some other reason
  10  certificate expired
  18  self-signed
  19  self-signed in the chain
  20  issuer certificate could not be found
  62  hostname does not match the certificate

These come from an attempt that did verify. A host serving an expired
certificate, or somebody else's, is a host nobody is watching — and both
findings this account has had rewarded came from a host nobody was watching.

tls=ok on a host the sweep called DEAD means the sweep failed for a different
reason: a redirect chain longer than three hops, or a body over its
--max-filesize. Those are worth a look too, but they are not neglect.
NOTE
