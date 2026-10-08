#!/data/data/com.termux/files/usr/bin/bash
# s-map.sh — map SynthID Detector from its own JavaScript.
#
# The result page carries no id in the URL, so there is no URL-addressable object
# and the usual IDOR shape is absent at that layer. But the upload goes somewhere,
# and whatever it returns may well be addressable.
#
# Same method that produced the Fitbit endpoint map: read the app's own bundles.
# It found a credential once and a full endpoint list twice; it costs a handful of
# GETs against files the browser already fetches.
set -u
T="$HOME/.synthid"; mkdir -p "$T"
echo "fetching synthid.com ..."
curl -s --max-time 20 -A 'Mozilla/5.0 (Linux; Android 14) Chrome/141.0' https://synthid.com/ -o "$T/index.html"
printf '  index: %s bytes\n' "$(wc -c < "$T/index.html")"

echo
echo "######################################################################"
echo "# 1. script bundles the page loads                                   #"
echo "######################################################################"
grep -oE 'src="[^"]+\.js[^"]*"' "$T/index.html" | sed 's/src="//;s/"$//' | sort -u | tee "$T/js.txt" | sed 's/^/  /'

: > "$T/all.js"
n=0
while read -r j; do
  [ -z "$j" ] && continue; n=$((n+1)); [ "$n" -gt 8 ] && break
  case "$j" in http*) u="$j" ;; //*) u="https:$j" ;; /*) u="https://synthid.com$j" ;; *) u="https://synthid.com/$j" ;; esac
  curl -s --max-time 40 --max-filesize 6000000 "$u" >> "$T/all.js" 2>/dev/null
  sleep 0.4
done < "$T/js.txt"
printf '\n  total JS: %s bytes\n' "$(wc -c < "$T/all.js")"

echo
echo "######################################################################"
echo "# 2. where does an upload GO?                                        #"
echo "######################################################################"
grep -ohoE '"/[a-zA-Z0-9][a-zA-Z0-9/_.$-]{2,60}"' "$T/all.js" 2>/dev/null \
  | tr -d '"' | grep -iE 'upload|detect|media|file|api|scan|result|job|image|video|audio|history' \
  | sort -u | head -30 | sed 's/^/  /'
echo "  --- absolute hosts it talks to ---"
grep -ohoE 'https://[a-zA-Z0-9.-]+\.(google|googleapis|googleusercontent|withgoogle)\.com[a-zA-Z0-9/_.$-]{0,50}' "$T/all.js" 2>/dev/null \
  | sort -u | head -20 | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 3. does anything look like a per-upload IDENTIFIER?                #"
echo "######################################################################"
echo "  (this is checklist question 1: if results are addressed by a long random"
echo "   id, the IDOR class is dead here and we stop)"
grep -ohoE '[a-zA-Z_]{2,22}(Id|ID|Uuid|Token|Key|Name)"?\s*[:=]' "$T/all.js" 2>/dev/null \
  | sort -u | head -30 | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 4. credentials shipped to the browser (the Fitbit pattern)         #"
echo "######################################################################"
grep -ohoE 'AIza[A-Za-z0-9_-]{30,40}|"[A-Za-z0-9]{4,12}:[0-9a-f]{32}"|[0-9]{10,13}-[a-z0-9]{32}\.apps\.googleusercontent\.com' "$T/all.js" 2>/dev/null \
  | sort -u | head -12 | sed 's/^/  /'
echo "  (an AIza key here is NOT a finding on its own — Google's own article says"
echo "   key reports are frequently false positives. It is only context.)"
