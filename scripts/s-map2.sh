#!/data/data/com.termux/files/usr/bin/bash
# s-map2.sh — the first pass grepped for <script src> and found only Google's
# generic gapi library. Google's own apps are built on Boq/Wiz: the code comes from
# gstatic.com/_/ under a hashed path and the data arrives in AF_initDataCallback
# blocks inlined in the HTML. Look there instead.
set -u
T="$HOME/.synthid"; mkdir -p "$T"
[ -s "$T/index.html" ] || curl -s --max-time 20 -A 'Mozilla/5.0 (Linux; Android 14) Chrome/141.0' https://synthid.com/ -o "$T/index.html"
printf 'index: %s bytes\n\n' "$(wc -c < "$T/index.html")"

echo "######################################################################"
echo "# 1. the Boq application name and its gstatic code path              #"
echo "######################################################################"
grep -ohoE 'https://www\.gstatic\.com/_/[a-zA-Z0-9/_.-]{10,120}' "$T/index.html" | sort -u | head -10 | sed 's/^/  /'
grep -ohoE '"[A-Za-z]*(SynthId|Synthid|synthid)[A-Za-z]*"|/_/[A-Za-z]{4,40}/' "$T/index.html" | sort -u | head -12 | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 2. endpoints named in the page itself                              #"
echo "######################################################################"
grep -ohoE '"/[a-zA-Z0-9][a-zA-Z0-9/_.$-]{3,70}"' "$T/index.html" | tr -d '"' | sort -u \
  | grep -viE '\.(css|png|svg|jpg|ico|woff2?)$' | head -30 | sed 's/^/  /'
echo "  --- batchexecute / rpcids, which is how Boq apps call their backend ---"
grep -ohoE 'batchexecute|rpcids|f\.req|[A-Za-z0-9]{6}\.[A-Za-z0-9]{4,8}"' "$T/index.html" | sort -u | head -12 | sed 's/^/  /'

echo
echo "######################################################################"
echo "# 3. inline data blocks (AF_initDataCallback / WIZ_global_data)       #"
echo "######################################################################"
printf '  AF_initDataCallback blocks : %s\n' "$(grep -o 'AF_initDataCallback' "$T/index.html" | wc -l)"
printf '  WIZ_global_data            : %s\n' "$(grep -o 'WIZ_global_data' "$T/index.html" | wc -l)"
grep -ohoE '"(FdrFJe|SNlM0e|cfb2h|qwAQke|Yllh3e)","[^"]{4,80}"' "$T/index.html" | head -8 | sed 's/^/  /'
echo "  (SNlM0e is the per-session request token Boq apps send with every call;"
echo "   qwAQke is the app name. Their presence tells us this is a Boq app and"
echo "   that the real API is /_/<App>/data/batchexecute, not a REST path.)"

echo
echo "######################################################################"
echo "# 4. any per-upload identifier in the markup at all                   #"
echo "######################################################################"
grep -ohoE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9_-]{22,}' "$T/index.html" \
  | sort -u | head -12 | sed 's/^/  /'
cat <<'TXT'

  WHAT DECIDES THIS

  If this is a Boq app calling /_/<App>/data/batchexecute, there is no REST object
  id to tamper with - requests are RPC batches bound to the session token. That
  removes the IDOR shape entirely, and it removes it for a structural reason
  rather than because we failed to find one.

  The question that still matters, and that the browser answers faster than any
  grep: does the app KEEP anything? Check the three-dot menu for a history or a
  list of past detections. No stored results means no cross-user object, which
  means no boundary - the same wall Fitbit hit.
TXT
