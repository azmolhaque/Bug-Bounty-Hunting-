#!/data/data/com.termux/files/usr/bin/bash
# g-probe10.sh — the question that decides WAI.
#
# Fitbit's strongest defence is: "accounts.fitbit.com IS our login page. It calls
# the token endpoint from the browser, so the client credential has to be in the
# browser. Working as intended."
#
# That defence is only available if the page ACTUALLY USES the secret. So:
#
#   bundle uses basicToken + grant_type=password   -> the design is browser-side ROPC.
#       WAI is arguable. The report must then be about the CONSEQUENCE (a second,
#       unprotected door to the same credential check) and not about the leak itself.
#
#   bundle never touches basicToken                -> the secret is published for
#       NOTHING. No design need, no defence. That is the strongest possible position.
#
# Either answer is worth knowing BEFORE submitting, because it decides which
# sentence the report leads with.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

echo "######################################################################"
echo "# Does accounts.fitbit.com's own JavaScript use the published secret? #"
echo "######################################################################"
curl -s --max-time 12 https://accounts.fitbit.com/ -o "$T/acc.html"
echo "  script bundles:"
grep -oE 'src="[^"]+\.js"' "$T/acc.html" | sed 's/src="//;s/"$//' | sort -u | tee "$T/acc.js.txt" | sed 's/^/    /'
echo
n=0
while read -r js; do
  [ -z "$js" ] && continue
  case "$js" in http*) u="$js" ;; /*) u="https://accounts.fitbit.com$js" ;; *) u="https://accounts.fitbit.com/$js" ;; esac
  n=$((n+1)); [ "$n" -gt 6 ] && break
  f="$T/acc$n.js"
  curl -s --max-time 30 "$u" -o "$f" 2>/dev/null
  printf '  --- %s  (%s bytes) ---\n' "$(basename "$js")" "$(wc -c < "$f" 2>/dev/null)"
  printf '      basicToken refs : %s\n' "$(grep -oc 'basicToken' "$f" 2>/dev/null || echo 0)"
  printf '      grant_type refs : %s\n' "$(grep -o 'grant_type' "$f" 2>/dev/null | wc -l)"
  echo "      grant types named in the code:"
  grep -oE "grant_type[^,;}]{0,60}" "$f" 2>/dev/null | sort -u | head -8 | sed 's/^/        /'
  echo "      token endpoints named:"
  grep -oE "oauth2/(token|revoke|introspect)" "$f" 2>/dev/null | sort -u | sed 's/^/        /'
  echo "      how the Authorization header is built:"
  grep -oE "Authorization[^,;}]{0,70}|Basic [^\"',;}]{0,40}" "$f" 2>/dev/null | sort -u | head -6 | sed 's/^/        /'
  sleep 0.8
done < "$T/acc.js.txt"

echo
echo "######################################################################"
echo "# And the same for feed-moderation — an INTERNAL tool, not a login   #"
echo "######################################################################"
echo "  This one matters separately. Whatever Fitbit argues about their login page"
echo "  needing a browser-side credential, a staff moderation console has no such"
echo "  excuse. If its bundle never uses the pair either, the leak is gratuitous"
echo "  in both places and 'working as intended' has nothing to stand on."
f="$T/fm.js"
curl -s --max-time 30 "https://feed-moderation.fitbit.com/assets/feed-moderation-3c230761f6306dc935f8e8cc775b7ed3.js" -o "$f"
printf '      bytes            : %s\n' "$(wc -c < "$f")"
printf '      227ZG3 refs      : %s\n' "$(grep -o '227ZG3' "$f" | wc -l)"
printf '      grant_type refs  : %s\n' "$(grep -o 'grant_type' "$f" | wc -l)"
grep -oE "grant_type[^,;}]{0,60}|oauth2/token|Basic [^\"',;}]{0,30}" "$f" | sort -u | head -8 | sed 's/^/        /'
