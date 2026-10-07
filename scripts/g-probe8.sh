#!/data/data/com.termux/files/usr/bin/bash
# g-probe8.sh — redo the systemic sweep. probe7's version was broken.
#
# probe7 reported every host "clean", INCLUDING accounts.fitbit.com and
# feed-moderation.fitbit.com, which we already know leak. That is a false
# negative across the board: the config is URL-ENCODED inside the meta tag, so
# "clientId":"..." never appears literally in the body and the greps could never
# match. The answer to "is this systemic?" was therefore never obtained.
#
# This version decodes first, and builds the control INTO the run: the two known
# leaking hosts are checked alongside everything else. If they do not light up,
# the script is broken again and no row below means anything.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

scan() { # scan <host> <tier>
  body=$(curl -s --max-time 12 "https://$1/" 2>/dev/null)
  [ -z "$body" ] && { printf '      %-38s %-9s (no body)\n' "$1" "$2"; return; }
  printf '%s' "$body" | grep -oE 'content="%7B[^"]*"' | sed 's/content="//;s/"$//' \
    > "$T/metas.txt" 2>/dev/null
  hits=$(python3 - "$T/metas.txt" <<'PY' 2>/dev/null
import sys,urllib.parse,re,base64
out=[]
try: blobs=open(sys.argv[1]).read().split("\n")
except Exception: blobs=[]
for b in blobs:
    if not b.strip(): continue
    raw=urllib.parse.unquote(b)
    # id:secret pairs, anything named *secret*, and base64 that decodes to id:secret
    for m in re.findall(r'"[A-Za-z_]*"?\s*:\s*"[A-Za-z0-9]{4,10}:[0-9a-f]{32}"',raw): out.append("pair   "+m)
    for m in re.findall(r'"[A-Za-z_]*secret[A-Za-z_]*"\s*:\s*"[^"]{8,}"',raw,re.I): out.append("secret "+m)
    for k,v in re.findall(r'"([A-Za-z_]+)"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"',raw):
        try:
            d=base64.b64decode(v+"==").decode("utf-8","ignore")
            if re.fullmatch(r'[A-Za-z0-9]{4,12}:[0-9a-f]{32}',d): out.append(f'basic  "{k}" -> {d}')
        except Exception: pass
print("\n".join(sorted(set(out))[:4]))
PY
)
  if [ -n "$hits" ]; then
    printf '  >>> %-38s %-9s LEAKS\n' "$1" "$2"
    printf '%s\n' "$hits" | sed 's/^/        /'
  else
    printf '      %-38s %-9s clean\n' "$1" "$2"
  fi
  sleep 0.7
}

echo "######################################################################"
echo "# POSITIVE CONTROLS — these two MUST light up or the script is broken #"
echo "######################################################################"
scan accounts.fitbit.com        "TIER1-CTL"
scan feed-moderation.fitbit.com "TIER1-CTL"
echo
echo "  If either says 'clean', STOP READING. The scan is broken again and the"
echo "  rows below are meaningless — exactly what happened in probe7."

echo
echo "######################################################################"
echo "# Every host that answered 200 in the acquisition sweep              #"
echo "######################################################################"
awk -F'\t' '$4=="200" && $1!="accounts.fitbit.com" && $1!="feed-moderation.fitbit.com"{print $1"\t"$2}' \
  results/google/sweep-acq.tsv 2>/dev/null | while IFS=$'\t' read -r h tier; do scan "$h" "$tier"; done
