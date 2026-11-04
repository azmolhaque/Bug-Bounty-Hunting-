#!/data/data/com.termux/files/usr/bin/bash
# g-probe14.sh — three things still testable from the terminal alone.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

echo "######################################################################"
echo "# 1. The OTHER client, 227ZG3 — we only mapped the grants for 228TQD #"
echo "######################################################################"
echo "  227ZG3 is 'Social Feed Moderation Application', a STAFF tool. If a staff"
echo "  moderation app's published credential also unlocks the password grant, that"
echo "  is harder to defend than a login page needing one."
B1=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
for g in "zzz_not_a_real_grant_7x2" "password&username=zzz-nobody-7x2@example.com&password=zzz" "social&googleUID=000000000000000000000" "mfa_sms&mfaToken=ZZZINVALID7x2"; do
  printf '  %-34s ' "${g%%&*}"
  curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $B1" \
    -H 'Content-Type: application/x-www-form-urlencoded' -d "grant_type=$g" \
    -w ' [%{http_code}]\n' | tr -d '\n' | head -c 220; echo
  sleep 2
done
echo "  First row is the SENTINEL. Anything matching it is not available on this client."

echo
echo "######################################################################"
echo "# 2. Internet Archive — the technique that produced the Tesla finding #"
echo "######################################################################"
echo "  We swept hosts that are live TODAY. The archive remembers paths that were"
echo "  live once: old bundles, old config endpoints, decommissioned admin trees."
echo "  Tesla's one real finding came from exactly this and nothing else."
for d in fitbit.com nest.com nestlabs.com waze.com looker.com mandiant.com cameyo.com pring.jp appsheet.com photomath.net; do
  f="$T/cdx-$d.txt"
  if [ ! -s "$f" ]; then
    curl -s --max-time 90 "https://web.archive.org/cdx/search/cdx?url=$d&matchType=domain&fl=original&collapse=urlkey&limit=40000" -o "$f"
    sleep 2
  fi
  n=$(wc -l < "$f" 2>/dev/null || echo 0)
  # CDX sometimes returns an HTML error page; the Tesla run was mis-read for exactly this.
  if head -1 "$f" | grep -qi '<html\|Temporarily'; then
    printf '  %-16s CDX RETURNED HTML, not data — rerun later\n' "$d"; continue
  fi
  hits=$(grep -ciE '/(config|env|settings|secrets?|credentials?)[^/]*\.(json|js|ya?ml|txt|xml)|\.env|/\.git/|/api/.*\.json|appsettings|firebase' "$f" 2>/dev/null || echo 0)
  printf '  %-16s %6s urls   %4s config-shaped\n' "$d" "$n" "$hits"
done
echo
echo "  --- the config-shaped URLs worth looking at ---"
cat "$T"/cdx-*.txt 2>/dev/null \
  | grep -iE '/(config|env|settings|secrets?|credentials?)[^/]*\.(json|js|ya?ml|txt)|\.env$|appsettings|firebase.*\.json' \
  | grep -viE '\.(png|jpg|gif|svg|css|woff|ttf)' | sort -u | head -40 | sed 's/^/    /'
cat "$T"/cdx-*.txt 2>/dev/null \
  | grep -iE '/(config|env|settings|secrets?|credentials?)[^/]*\.(json|js|ya?ml|txt)|\.env$|appsettings|firebase.*\.json' \
  | grep -viE '\.(png|jpg|gif|svg|css|woff|ttf)' | sort -u > "$T/cdx-interesting.txt"
printf '\n  %s candidate URLs saved to %s\n' "$(wc -l < "$T/cdx-interesting.txt")" "$T/cdx-interesting.txt"

echo
echo "######################################################################"
echo "# 3. Are those archived paths STILL SERVED today?                    #"
echo "######################################################################"
echo "  An archived URL proves it existed once. Only a live fetch proves it is still"
echo "  there — which is what made the Tesla config file a finding rather than history."
echo "  Checking the first 25, with a canary per host so a blanket 200 cannot fool us."
head -25 "$T/cdx-interesting.txt" | while read -r u; do
  [ -z "$u" ] && continue
  case "$u" in http*) U="$u" ;; *) U="https://$u" ;; esac
  code=$(curl -s -o "$T/body" --max-time 10 -w '%{http_code}' "$U" 2>/dev/null)
  sz=$(wc -c < "$T/body" 2>/dev/null || echo 0)
  mark=""
  if [ "$code" = "200" ] && [ "$sz" -gt 40 ]; then
    grep -qiE 'secret|apikey|api_key|password|token|AIza|[0-9a-f]{32}' "$T/body" 2>/dev/null && mark="   <<< CONTAINS SECRET-SHAPED STRINGS"
  fi
  printf '  %-4s %7sb  %s%s\n' "$code" "$sz" "$(printf '%s' "$U" | cut -c1-82)" "$mark"
  sleep 0.8
done
