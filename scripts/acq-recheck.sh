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

probe() {   # probe <host> -> "code<TAB>size<TAB>verify<TAB>title"  (empty on failure)
  : > "$body"                       # never let the previous host's page survive
  local w
  w=$(curl -sS -k -m 10 -A "$UA" --max-filesize 262144 \
        -o "$body" -w '%{http_code}\t%{size_download}\t%{ssl_verify_result}' \
        "https://$1/" 2>/dev/null) || return 1
  local code="${w%%$'\t'*}"
  [ "$code" = "000" ] && return 1
  local title
  title=$(tr '\n' ' ' < "$body" | grep -oiE '<title[^>]*>[^<]{0,90}' | head -1 \
          | sed 's/<[^>]*>//; s/^[ \t]*//; s/[ \t]*$//')
  printf '%s\t%s' "$w" "$title"
}

# ---- controls ----
# A host that must answer, and one that must not. Without both, "n of m
# answered" is a statement about this machine.
echo "== CONTROL =="
if ! probe www.waze.com >/dev/null; then
  echo "!! BROKEN: a known-live host did not answer. Fix connectivity first."; exit 2
fi
echo "POSITIVE  www.waze.com answered"
if probe "nonexistent-canary-$RANDOM.waze.com" >/dev/null; then
  echo "!! BROKEN: a host that does not exist answered."; exit 2
fi
echo "NEGATIVE  a nonexistent host did not"
echo

printf 'host\tcode\tsize\tverify\ttitle\n' > "$TSV"
n=0; alive=0; skipped=0
while read -r h; do
  [ -n "$h" ] || continue
  n=$((n+1))
  if ! "$SCOPE" "$h" >/dev/null 2>&1; then skipped=$((skipped+1)); continue; fi
  if r=$(probe "$h"); then
    alive=$((alive+1))
    printf '%s\t%s\n' "$h" "$r" >> "$TSV"
    IFS=$'\t' read -r code size verify title <<<"$r"
    printf '  %-44s %-4s %8sb  verify=%-3s %s\n' "$h" "$code" "$size" "$verify" "$title"
  fi
  sleep "$DELAY"
done < "$LIST"

echo
echo "== $alive of $n answered without certificate verification ($skipped out of scope) =="
echo "table: $TSV"

cat <<'NOTE'

== reading verify= ==
  0   certificate is fine; the first sweep failed for some other reason
  10  expired
  18  self-signed
  19  self-signed in the chain
  20  issuer certificate could not be found
  62  hostname does not match the certificate

10, 20 and 62 are the interesting ones. A host serving somebody else's
certificate, or one nobody has renewed in months, is a host nobody is
watching — and every finding this account has had rewarded came from a host
nobody was watching.
NOTE
