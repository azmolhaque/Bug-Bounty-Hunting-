#!/data/data/com.termux/files/usr/bin/bash
# f-map.sh — extract Fitbit's own endpoint list from its own bundle, then test each
# one for the class that produced G-F002: a resource reachable by a caller who does
# not own it.
#
# We did not guess our way to `introspect`. It came out of a constants map in
# accounts.fitbit.com's bundle. That map had more entries than we read, and one
# bug in a team's code is rarely the only one of its kind.
set -u
T="$HOME/.gcap"; mkdir -p "$T"
if [ ! -s "$T/all.js" ]; then
  echo "fetching bundles (cache empty)..."
  curl -s --max-time 15 https://accounts.fitbit.com/ -o "$T/index.html"
  grep -oE 'src="[^"]+\.js[^"]*"' "$T/index.html" | sed 's/src="//;s/"$//' | while read -r j; do
    case "$j" in http*) u="$j" ;; /*) u="https://accounts.fitbit.com$j" ;; *) u="https://accounts.fitbit.com/$j" ;; esac
    curl -s --max-time 40 --max-filesize 4000000 "$u" >> "$T/all.js"; sleep 0.5
  done
fi
printf 'bundle: %s bytes\n\n' "$(wc -c < "$T/all.js")"

echo "######################################################################"
echo "# 1. Fitbit's OWN endpoint constants — the map, not a guess          #"
echo "######################################################################"
grep -oE '[A-Z_]{4,34}:"[0-9a-z.]{0,6}/?[a-z0-9/_.-]{3,46}"' "$T/all.js" \
  | grep -viE '"(https?|text|application|image|utf)' | sort -u | head -45 | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 2. every api.fitbit.com path the bundle mentions                   #"
echo "######################################################################"
grep -oE '"(1|1\.1|oauth2)/[a-zA-Z0-9/_.-]{3,50}"' "$T/all.js" | tr -d '"' | sort -u | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 3. and any absolute Fitbit API URLs                                #"
echo "######################################################################"
grep -oE 'https://(api|web-api|accounts)\.fitbit\.com/[a-zA-Z0-9/_.-]{0,60}' "$T/all.js" | sort -u | head -25 | sed 's/^/  /'

cat <<'TXT'

  WHAT WE ARE LOOKING FOR

  G-F002 was not an isolated mistake in a vacuum - it was one endpoint in a set
  where a sibling (revoke) got the ownership check right and this one did not.
  Any path above that takes an identifier of a thing a caller might not own - a
  token, a subscription, a device, a user id - is worth the same four-way test:

      [CONTROL]  caller asks about its OWN object
      [CROSS]    caller asks about ANOTHER client's object
      [SENTINEL] caller asks about a fabricated identifier
      [NO AUTH]  no credentials at all

  Paste the output back and I will pick the ones worth probing. Do not start
  firing requests at every path - most will be irrelevant, and volume is exactly
  what the program rules ask us not to generate.
TXT
