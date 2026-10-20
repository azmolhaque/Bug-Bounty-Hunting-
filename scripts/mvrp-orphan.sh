#!/usr/bin/env bash
# mvrp-orphan.sh — অনাথ permission: Mobile VRP-র নাম-ধরে-পুরস্কৃত পঞ্চম শ্রেণি।
#
# rules থেকে আক্ষরিক: "orphaned permissions"।
#
# আক্রমণ:
#   app A একটা exported component-কে permission P দিয়ে পাহারা দেয়।
#   P সংজ্ঞায়িত করে app B। B ডিভাইসে না থাকলে P **অনাথ** — কেউ ওটা
#   সংজ্ঞায়িত করেনি। তখন আক্রমণকারী নিজের manifest-এ
#       <permission android:name="P" android:protectionLevel="normal"/>
#       <uses-permission android:name="P"/>
#   লিখে ইনস্টল করে। সে-ই এখন সংজ্ঞাদাতা, normal মানে install-এ
#   স্বয়ংক্রিয় grant, আর A-র পাহারা দেওয়া component তার কাছে খুলে যায়।
#
# কেন এটা আগে করিনি: আমি চারটে শ্রেণি বেছেছিলাম rules-এর তালিকা থেকে,
# আর mvrp_surface.py সারা রাত "orphaned permission?" ছাপিয়ে গেছে অথচ
# একটাও ধরা হয়নি। যন্ত্র বলছিল, আমি পড়িনি।
#
# ব্যবহার:  ./mvrp-orphan.sh            # সব decoded manifest
#           ./mvrp-orphan.sh <pkg> ...
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; REP="$OUT/orphan"; mkdir -p "$REP"
LOG="$REP/orphan-$(date +%Y%m%d-%H%M).txt"
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }
[ -d "$DEC" ] || { echo "!! $DEC নেই — আগে mvrp-surface.sh চালাও"; exit 1; }

# ---------- ডিভাইসে কোন permission গুলো সংজ্ঞায়িত ----------
DEF="$REP/defined.txt"
adb shell pm list permissions -f 2>/dev/null </dev/null | tr -d '\r' \
  | awk '/^\+ permission:/{p=substr($0,13)} /^  package:/{print p"\t"substr($0,11)}' \
  | sort -u > "$DEF"
NDEF=$(wc -l < "$DEF")

# protectionLevel-ও লাগবে: signature হলে আক্রমণকারী সংজ্ঞাদাতা হলেও
# স্বাক্ষর না মিললে grant পাবে না।
LVL="$REP/levels.txt"
adb shell pm list permissions -f 2>/dev/null </dev/null | tr -d '\r' \
  | awk '/^\+ permission:/{p=substr($0,13)} /protectionLevel:/{sub(/.*protectionLevel:/,""); print p"\t"$0}' \
  | sort -u > "$LVL"

{
echo "# orphaned permission sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo

# ---------- CONTROL ----------
# ভাঙা যন্ত্র যেন নীরবে "সব অনাথ" বা "একটাও অনাথ নয়" না বলে।
echo "== CONTROL =="
if [ "$NDEF" -lt 100 ]; then
  echo "!! BROKEN: ডিভাইসে মাত্র $NDEF টা permission পড়া গেল — pm list ভেঙেছে"
  exit 2
fi
echo "POSITIVE  ডিভাইসে $NDEF টা permission সংজ্ঞায়িত পাওয়া গেছে"
if cut -f1 "$DEF" | grep -qx 'android.permission.INTERNET'; then
  echo "POSITIVE  জানা-সংজ্ঞায়িত (android.permission.INTERNET) DEFINED হিসেবে ধরা পড়ছে"
else
  echo "!! BROKEN: INTERNET-ও সংজ্ঞায়িত দেখাচ্ছে না — পার্সিং ভেঙেছে"; exit 2
fi
if cut -f1 "$DEF" | grep -qx 'com.cindrasec.definitely.not.a.real.permission'; then
  echo "!! BROKEN: বানানো permission-ও সংজ্ঞায়িত দেখাচ্ছে"; exit 2
fi
echo "POSITIVE  বানানো permission ORPHANED হিসেবেই থাকছে"
echo

# ---------- প্রতিটা manifest ----------
pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')

echo "== পাহারাদার permission, আর সেগুলো কে সংজ্ঞায়িত করে =="
TOT=0; ORPH=0
for pkg in "${pkgs[@]}"; do
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue
  # exported component + permission -> (component, kind, perm)
  rows=$(python3 -I - "$m" <<'PY'
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=None): return e.get("{%s}%s"%(AND,n),d)
try:
    root=ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(0)
app=root.find("application")
if app is None: sys.exit(0)
# এই app নিজে কোন permission গুলো ঘোষণা করে
own={a(p,"name") for p in root.findall("permission")}
for k in ("activity","activity-alias","service","receiver","provider"):
    for el in app.findall(k):
        if a(el,"enabled")=="false": continue
        exp=a(el,"exported")
        if not (exp=="true" or (exp is None and el.findall("intent-filter"))): continue
        for attr in ("permission","readPermission","writePermission"):
            p=a(el,attr)
            if p and p not in own:
                print("%s\t%s\t%s\t%s"%(k,a(el,"name") or "?",attr,p))
PY
)
  [ -z "$rows" ] && continue
  printed=0
  while IFS=$'\t' read -r kind name attr perm; do
    [ -z "$perm" ] && continue
    TOT=$((TOT+1))
    definer=$(awk -F'\t' -v p="$perm" '$1==p{print $2}' "$DEF" | head -1)
    level=$(awk -F'\t' -v p="$perm" '$1==p{print $2}' "$LVL" | head -1)
    if [ -z "$definer" ]; then
      [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
      ORPH=$((ORPH+1))
      echo "  *** ORPHANED  $perm"
      echo "      কেউ সংজ্ঞায়িত করে না -> আক্রমণকারী নিজে ঘোষণা করে নিতে পারে"
      echo "      পাহারা দিচ্ছে: [$kind] $name  ($attr)"
    elif [ "${VERBOSE:-}" ]; then
      [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
      echo "  defined   $perm"
      echo "      সংজ্ঞাদাতা: $definer   level: ${level:-?}"
    fi
  done <<<"$rows"
done

echo
echo "== সারাংশ =="
echo "পাহারাদার permission (exported component-এ): $TOT"
echo "অনাথ: $ORPH"
cat <<'NOTE'

== পড়ার নিয়ম ==
ORPHANED মানে **precondition, finding নয়** (CLAUDE.md 2.6)। তিনটে ধাপ বাকি:
  ১. সত্যিই দাবি করা যায় কিনা — আক্রমণকারী app-এ
         <permission android:name="P" android:protectionLevel="normal"/>
         <uses-permission android:name="P"/>
     দিয়ে ইনস্টল করে `adb shell dumpsys package <attacker> | grep -A5 grantedPermissions`
     দেখে প্রমাণ করো যে grant হয়েছে। Wiz-এর subdomain রিপোর্ট মরেছিল ঠিক
     এখানেই — দাবি করা যায় ধরে নেওয়া হয়েছিল, করে দেখানো হয়নি।
  ২. পাহারা দেওয়া component-এ আসলে পৌঁছানো যায় কিনা — bind/start করে দেখাও।
  ৩. পৌঁছে **কী পাওয়া যায়**। boolean বা no-op হলে kill_list, বাদ।

VERBOSE=1 দিলে সংজ্ঞায়িত permission গুলোও দেখাবে, সংজ্ঞাদাতা আর level সহ।
signature-level permission-এ আক্রমণকারী সংজ্ঞাদাতা হলেও grant পাবে না —
কিন্তু অনাথ permission-এর কোনো level নেই, কারণ সংজ্ঞাই নেই।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
