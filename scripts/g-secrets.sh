#!/data/data/com.termux/files/usr/bin/bash
# g-secrets.sh — hunt credentials in page source AND JS bundles, across a sweep result.
#
# The two Fitbit secrets were found by decoding a config meta tag. That is ONE place.
# Bundles are the bigger surface and where most real credential leaks live. This looks
# in both.
#
# POSITIVE CONTROLS ARE BUILT IN. accounts.fitbit.com and feed-moderation.fitbit.com are
# scanned first every run. If they do not light up, the scanner is broken and every
# "clean" below it is meaningless — which is exactly what happened with probe7.
set -u
IN="${1:?usage: g-secrets.sh <sweep.tsv>}"
T="$HOME/.gsec"; mkdir -p "$T"
OUT="$HOME/secrets-found.txt"; : > "$OUT"

scan() { # scan <host> <tier>
  h="$1"; tier="$2"
  body=$(curl -s --max-time 12 -A 'Mozilla/5.0 (Linux; Android 14) Chrome/141.0' "https://$h/" 2>/dev/null)
  [ -z "$body" ] && { printf '      %-40s %-9s (empty)\n' "$h" "$tier"; return; }
  printf '%s' "$body" > "$T/page"
  # bundles: same-origin .js referenced by the page, first 4, 3 MB cap each
  printf '%s' "$body" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"$//' | head -4 > "$T/js.txt"
  : > "$T/all"; cat "$T/page" >> "$T/all"
  while read -r j; do
    [ -z "$j" ] && continue
    case "$j" in http*) u="$j" ;; //*) u="https:$j" ;; /*) u="https://$h$j" ;; *) u="https://$h/$j" ;; esac
    case "$u" in *"$h"*) ;; *) continue ;; esac      # same-origin only
    curl -s --max-time 25 --max-filesize 3000000 "$u" >> "$T/all" 2>/dev/null
    sleep 0.4
  done < "$T/js.txt"

  hits=$(python3 - "$T/all" <<'PY' 2>/dev/null
import sys,re,urllib.parse,base64
raw=open(sys.argv[1],encoding='utf-8',errors='ignore').read()
# config blobs are URL-encoded inside meta tags - decode them too
dec=raw
for m in re.findall(r'content="(%7B[^"]{40,})"',raw):
    dec+="\n"+urllib.parse.unquote(m)
out=set()
for m in re.findall(r'"[A-Za-z_]{0,24}":"[A-Za-z0-9]{4,12}:[0-9a-f]{32}"',dec): out.add("pair    "+m)
for m in re.findall(r'"[A-Za-z_]*(?:secret|SECRET)[A-Za-z_]*"\s*:\s*"[^"]{8,120}"',dec): out.add("secret  "+m[:150])
for m in re.findall(r'"[A-Za-z_]*(?:private_?key|PRIVATE_?KEY)[A-Za-z_]*"\s*:\s*"[^"]{20,}"',dec): out.add("privkey "+m[:120])
for m in re.findall(r'-----BEGIN [A-Z ]*PRIVATE KEY-----',dec): out.add("pem     "+m)
for k,v in re.findall(r'"([A-Za-z_]+)"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"',dec):
    try:
        d=base64.b64decode(v+"==").decode("utf-8","ignore")
        if re.fullmatch(r'[A-Za-z0-9]{4,12}:[0-9a-f]{32}',d): out.add('basic   "%s" -> %s' % (k,d))
    except Exception: pass
print("\n".join(sorted(out)[:6]))
PY
)
  if [ -n "$hits" ]; then
    printf '  >>> %-40s %-9s LEAKS\n' "$h" "$tier"
    printf '%s\n' "$hits" | sed 's/^/        /'
    { printf '=== %s (%s) ===\n' "$h" "$tier"; printf '%s\n' "$hits"; } >> "$OUT"
  else
    printf '      %-40s %-9s clean\n' "$h" "$tier"
  fi
}

echo "################ POSITIVE CONTROLS — must say LEAKS ################"
scan accounts.fitbit.com        "CONTROL"
scan feed-moderation.fitbit.com "CONTROL"
echo "  If either says clean, STOP: the scanner is broken and nothing below counts."
echo
echo "################ every host that answered 200 ################"
awk -F'\t' '$4=="200" && $2!="SENTINEL"{print $1"\t"$2}' "$IN" | while IFS=$'\t' read -r h tier; do
  scan "$h" "$tier"
done
echo
printf 'anything found is also appended to %s\n' "$OUT"
