#!/data/data/com.termux/files/usr/bin/bash
# g-probe7.sh — last reconnaissance before reporting. Three questions that can
# still change the severity, and nothing that cannot.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

echo "######################################################################"
echo "# 1. The FULL config of accounts.fitbit.com, not just matching keys  #"
echo "######################################################################"
echo "  Last pass printed only keys whose NAME matched secret/clientId/token. A"
echo "  credential under any other name would have been invisible. Print all of it."
curl -s --max-time 12 https://accounts.fitbit.com/ \
  | grep -oE 'content="%7B[^"]*"' | head -1 | sed 's/content="//;s/"$//' \
  | python3 -c "import sys,urllib.parse,json
raw=urllib.parse.unquote(sys.stdin.read())
try: print(json.dumps(json.loads(raw),indent=1))
except Exception: print(raw)" 2>/dev/null | head -80

echo
echo "######################################################################"
echo "# 2. Is this two apps, or the house style across every acquisition?  #"
echo "######################################################################"
echo "  Sweeping every host that answered 200, looking for the same shape. Two"
echo "  leaked secrets is a bug; a build convention that leaks them is a finding"
echo "  with a much larger blast radius, and the report should say which it is."
awk -F'\t' '$4=="200"{print $1"\t"$2}' results/google/sweep-acq.tsv 2>/dev/null | while IFS=$'\t' read -r h tier; do
  body=$(curl -s --max-time 10 "https://$h/" 2>/dev/null)
  [ -z "$body" ] && continue
  # a Basic-auth pair base64s to something that decodes with a colon in the middle
  basic=$(printf '%s' "$body" | grep -oE '"[A-Za-z]*[Bb]asic[A-Za-z]*"\s*:\s*"[A-Za-z0-9+/=]{16,}"' | head -2)
  pair=$(printf '%s' "$body" | grep -oE '"[A-Za-z_]*(client_?[Ii]d|CLIENT_ID)"\s*:\s*"[A-Za-z0-9]{4,10}:[0-9a-f]{32}"' | head -2)
  sec=$(printf '%s' "$body" | grep -oE '"[A-Za-z_]*(secret|SECRET)[A-Za-z_]*"\s*:\s*"[^"]{8,}"' | head -2)
  if [ -n "$basic$pair$sec" ]; then
    printf '  >>> %-34s %-6s\n' "$h" "$tier"
    [ -n "$pair" ]  && printf '        pair   %s\n' "$pair"
    [ -n "$basic" ] && printf '        basic  %s\n' "$basic"
    [ -n "$sec" ]   && printf '        secret %s\n' "$sec"
  else
    printf '      %-34s %-6s  clean\n' "$h" "$tier"
  fi
  sleep 0.7
done

echo
echo "######################################################################"
echo "# 3. dev.fitbit.com showed 19 32-hex strings — what are they?        #"
echo "######################################################################"
curl -s --max-time 12 https://dev.fitbit.com/ -o "$T/dev.html"
echo "  context around each 32-hex match (first 6):"
grep -oE '.{60}[0-9a-f]{32}.{20}' "$T/dev.html" | head -6
echo
echo "  --- and its script bundles, which is where a config usually hides ---"
grep -oE 'src="[^"]+\.js"' "$T/dev.html" | sort -u | head -10

echo
echo "######################################################################"
echo "# 4. client ids used anywhere in the two leaking apps' bundles       #"
echo "######################################################################"
echo "  Fitbit client ids are 6 chars, uppercase alphanumeric. If the bundles"
echo "  reference ids beyond 227ZG3 and 228TQD, there may be more to check."
for u in https://feed-moderation.fitbit.com/assets/feed-moderation-3c230761f6306dc935f8e8cc775b7ed3.js \
         https://feed-moderation.fitbit.com/assets/vendor-2ddd5d69acb14ccc97279c22cfdf6e89.js; do
  printf '  %s\n' "$(basename "$u")"
  curl -s --max-time 20 "$u" 2>/dev/null \
    | grep -oE '"[0-9]{3}[A-Z0-9]{3}"|[0-9]{3}[A-Z0-9]{3}:[0-9a-f]{32}' | sort -u | head -10 | sed 's/^/      /'
  sleep 0.8
done
