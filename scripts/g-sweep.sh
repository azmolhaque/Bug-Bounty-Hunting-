#!/data/data/com.termux/files/usr/bin/bash
# g-sweep.sh — polite liveness sweep over Google's own published tier list.
#
#   bash scripts/g-sweep.sh results/google/targets-acq-t012.txt results/google/sweep-acq.tsv
#
# One GET of "/" per host, body discarded, ~0.7s apart. Nothing is guessed: every
# hostname comes from github.com/google/bughunters. Resumable — rerun after a dropped
# connection and it skips what it already has.
#
# Each apex carries a zzz-canary-7x2.<apex> SENTINEL. If the canary resolves and
# answers, that apex has wildcard DNS and every sibling result must be read against
# the canary's status+size, not on its own.

IN="${1:?usage: g-sweep.sh <targets.txt> <out.tsv>}"
OUT="${2:?usage: g-sweep.sh <targets.txt> <out.tsv>}"
[ -f "$OUT" ] || printf 'host\ttier\tip\tcode\tsize\tserver\tredirect\n' > "$OUT"

total=$(grep -cve '^[[:space:]]*$' "$IN"); n=0
while IFS=$'\t' read -r host tier; do
  [ -z "$host" ] && continue
  n=$((n+1))
  cut -f1 "$OUT" | grep -qxF "$host" && continue          # resume
  printf '\r[%d/%d] %-52s' "$n" "$total" "$host" >&2

  ip=$(dig +short +time=2 +tries=1 "$host" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
  if [ -z "$ip" ]; then
    printf '%s\t%s\t-\tNODNS\t-\t-\t-\n' "$host" "$tier" >> "$OUT"; continue
  fi

  read -r code size srv loc <<<"$(curl -s -o /dev/null --max-time 8 \
      -A 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/141.0 Safari/537.36' \
      -w '%{http_code} %{size_download} %{redirect_url}' "https://$host/" 2>/dev/null \
      | awk '{print $1, $2, "-", ($3==""?"-":$3)}')"
  srv=$(curl -sI --max-time 6 "https://$host/" 2>/dev/null \
      | awk 'BEGIN{IGNORECASE=1}/^server:/{sub(/^[^:]*: */,"");gsub(/\r/,"");print;exit}')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$host" "$tier" "$ip" "${code:-ERR}" "${size:-0}" "${srv:--}" "${loc:--}" >> "$OUT"
  sleep 0.7
done < "$IN"
printf '\rdone — %d rows in %s\n' "$(($(wc -l < "$OUT")-1))" "$OUT" >&2
