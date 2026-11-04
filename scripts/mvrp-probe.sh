#!/usr/bin/env bash
# mvrp-probe.sh — exported content provider-গুলো জীবন্ত পরীক্ষা করো,
#                 control আর sentinel সহ, একই রানে।
#
# ব্যবহার:  ./mvrp-probe.sh com.fitbit.FitbitMobile
#           ./mvrp-probe.sh com.fitbit.FitbitMobile com.fitbit.provider.extra
#
# কেন adb shell:
#   adb shell uid=2000 (shell), app-এর uid না। তাই এখান থেকে পড়তে পারা মানে
#   "অন্য একটা unprivileged caller পড়তে পারে"। আর Mobile VRP নিজেই বলে:
#   "in cases that the vulnerability can be fully triggered by using ADB,
#    that is also acceptable."
#
# CONTROL নীতি:
#   প্রতিটা রানে তিনটে জিনিস একসাথে চলে —
#     POSITIVE  : যেটা পড়া যাওয়ার কথা  -> ভাঙা হলে টুল ভাঙা, target না
#     SENTINEL  : যেটা অস্তিত্বহীন       -> সফল হলে ফলাফল পুরো অর্থহীন
#     TARGET    : আসল probe
#   তিনটে পাশাপাশি না দেখে কোনো সিদ্ধান্ত না।
set -uo pipefail

PKG="${1:?ব্যবহার: $0 <package> [authority ...]}"; shift || true
OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded/$PKG"; EV="$OUT/evidence/$PKG"
mkdir -p "$EV"
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LOG="$EV/probe-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

# ---- authority সংগ্রহ: argument, নয়তো manifest থেকে ----
AUTHS=("$@")
if [ ${#AUTHS[@]} -eq 0 ]; then
  M="$DEC/resources/AndroidManifest.xml"
  [ -f "$M" ] || { echo "!! manifest নেই: $M — আগে mvrp-surface.sh চালাও"; exit 1; }
  mapfile -t AUTHS < <(grep -o 'android:authorities="[^"]*"' "$M" \
                       | sed 's/.*="//;s/"$//' | tr ';' '\n' | sort -u)
fi
[ ${#AUTHS[@]} -eq 0 ] && { echo "!! কোনো authority নেই — এই app-এ provider নেই"; exit 0; }

# ---- classify: চারটে আলাদা অবস্থা, "কাজ করেছে/করেনি" নয় ----
classify() {
  local o="$1"
  if   grep -qiE 'permission denial|securityexception|requires .*permission' <<<"$o"; then echo DENIED
  elif grep -qiE 'unknown uri|failed to find provider|could not find provider|does not exist' <<<"$o"; then echo NOPROVIDER
  elif grep -q 'Row:' <<<"$o"; then echo "DATA"
  elif grep -qi 'no result found' <<<"$o"; then echo EMPTY
  # `content` CLI একটা permission denial-কে NPE হিসেবে দেখায়: সে remote
  # exception-এর খালি message পড়তে গিয়ে নিজেই String.contains(null) মারে।
  # আসল কারণ থাকে 'Caused by' ব্লকে। ওটাই দেখো, NPE-টা না।
  elif grep -qiE 'checkContentProviderPermission|checkAssociationAndPermission' <<<"$o"; then echo DENIED
  elif grep -qi 'unsupportedoperation' <<<"$o"; then echo UNSUPPORTED
  elif grep -qi 'error while accessing provider' <<<"$o"; then echo REACHED
  elif [ -z "${o//[[:space:]]/}" ]; then echo SILENT
  else echo OTHER
  fi
}

q() { adb shell content query --uri "$1" 2>&1 | tr -d '\r' | head -45; }

{
echo "# Mobile VRP provider probe"
echo "# package : $PKG"
echo "# when    : $STAMP"
echo "# device  : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r') (SDK $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
echo "# app ver : $(adb shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' | awk -F= '/versionName=/{print $2; exit}')"
echo "# caller  : adb shell, uid=$(adb shell id -u | tr -d '\r')  (app uid নয়)"
echo

echo "== CONTROL =="
po=$(q "content://settings/system")
echo "POSITIVE  content://settings/system           -> $(classify "$po")"
so=$(q "content://${PKG}.canary.does.not.exist/x")
echo "SENTINEL  content://${PKG}.canary.does.not.exist/x -> $(classify "$so")"

if [ "$(classify "$po")" != "DATA" ]; then
  echo
  echo "!! POSITIVE control ব্যর্থ — 'content query' নিজেই কাজ করছে না।"
  echo "!! এই রানের কোনো ফলাফল বিশ্বাস কোরো না। থামো।"
  exit 3
fi
if [ "$(classify "$so")" = "DATA" ]; then
  echo
  echo "!! SENTINEL ডেটা ফেরত দিয়েছে — অস্তিত্বহীন provider-ও 'সফল'।"
  echo "!! classify() ভাঙা। এই রান অর্থহীন। থামো।"
  exit 3
fi
echo "control ঠিক আছে — এগোচ্ছি।"
echo

echo "== TARGET: ${#AUTHS[@]} authority =="
for auth in "${AUTHS[@]}"; do
  o=$(q "content://$auth")
  v=$(classify "$o")
  printf '%-10s %s\n' "$v" "content://$auth"
  if [ "$v" = "DATA" ]; then
    echo "           ----- ফেরত আসা বাইট -----"
    sed 's/^/           /' <<<"$o"
    echo "           -------------------------"
  fi

  # FileProvider-ধাঁচ হলে path traversal দেখো (arbitrary file read -> theft)
  case "$auth" in
    *fileprovider*|*FileProvider*|*.provider|*.files|*.file)
      for t in "../../../../data/data/$PKG/shared_prefs" \
               "..%2F..%2F..%2Fdatabases" \
               "root/data/data/$PKG/shared_prefs"; do
        ro=$(adb shell content read --uri "content://$auth/$t" 2>&1 | tr -d '\r' | head -5)
        rv=$(classify "$ro")
        [ "$rv" = "DENIED" ] || [ "$rv" = "NOPROVIDER" ] || \
          printf '  %-8s read %s\n%s\n' "$rv" "content://$auth/$t" "$(sed 's/^/           /' <<<"$ro")"
      done;;
  esac
done

echo
echo "== পড়ার নিয়ম =="
cat <<'NOTE'
DATA       অন্য একটা unprivileged caller সারি পেয়েছে।
           এখনই জিজ্ঞেস করো: সারিতে কী আছে? token/credential/medical/message?
           - হ্যাঁ  -> Theft of Sensitive Data। evidence রাখো, বাইট কপি করো।
           - না   -> "Access to non-sensitive internal files of another app
                      also does not qualify" — kill list। ছেড়ে দাও।
DENIED     সীমানা ধরে আছে। এটাই স্বাভাবিক। লিখে রাখো, এগোও।
EMPTY      provider খোলা কিন্তু এই URI-তে সারি নেই। path বদলে দেখো
           (manifest-এর <grant-uri-permission>, আর jadx-এ UriMatcher দেখো)।
NOPROVIDER এই authority নেই/exported না।
SILENT     ভাবনার বিষয় — ফলাফল নয়, flag। হাতে যাচাই করো।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "evidence: $LOG"
