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
# হাতে অক্ষর গুনে substr() করা হয়েছিল — "+ permission:" ঠিক ১৩ অক্ষর, তাই
# substr($0,13) কোলন থেকে শুরু করে নাম বানাত ":android.permission.INTERNET"।
# control সেটা ধরেছে। জাদু-সংখ্যা বাদ, prefix কেটে নেওয়া হচ্ছে।
# `-g` ছাড়া pm group-ভুক্ত permission ছাপে না — CAMERA, LOCATION, CONTACTS,
# অর্থাৎ প্রতিটা dangerous runtime permission বাদ পড়ে। control সেটা ধরেছে।
# parser ঠিক ছিল, প্রশ্নটা ভুল ছিল; তাই `-g -f` চাই।
RAW="$REP/pm-raw.txt"
adb shell pm list permissions -g -f 2>/dev/null </dev/null | tr -d '\r' > "$RAW"

# group ব্লকেরও নিজের package: লাইন আছে। p রিসেট না করলে সেটা আগের
# permission-এর সাথে জোড়া লেগে যায়।
DEF="$REP/defined.txt"      # নাম \t সংজ্ঞাদাতা package
awk '
  /^[[:space:]]*[+]?[[:space:]]*group:/ { p=""; next }
  /permission:/            { p=$0; sub(/^.*permission:/,"",p); next }
  /^[[:space:]]*package:/  { if (p!="") { k=$0; sub(/^[[:space:]]*package:/,"",k); print p"\t"k } }
' "$RAW" | sort -u > "$DEF"

LVL="$REP/levels.txt"       # নাম \t protectionLevel
awk '
  /^[[:space:]]*[+]?[[:space:]]*group:/ { p=""; next }
  /permission:/            { p=$0; sub(/^.*permission:/,"",p); next }
  /protectionLevel:/       { if (p!="") { l=$0; sub(/^.*protectionLevel:/,"",l); print p"\t"l } }
' "$RAW" | sort -u > "$LVL"

# definedness একটা package: লাইন থাকার উপর নির্ভর করবে না — নামই যথেষ্ট।
# তিনটে স্বাধীন উৎস মেলানো হচ্ছে, যাতে একটা ভাঙলে উত্তরটা নীরবে বদলে না যায়।
DEFSET="$REP/defined-names.txt"
{ sed -n 's/^.*[^-]permission:\(.*\)$/\1/p' "$RAW"
  adb shell pm list permissions -g 2>/dev/null </dev/null | tr -d '\r' \
    | sed -n 's/^[[:space:]]*permission:\(.*\)$/\1/p'
  adb shell pm list permissions 2>/dev/null </dev/null | tr -d '\r' \
    | sed -n 's/^[[:space:]]*permission:\(.*\)$/\1/p'
} | grep -v '^$' | sort -u > "$DEFSET"

# ---- যন্ত্র নিজেই পরীক্ষিত বস্তুকে বদলে ফেলেছে ----
# আক্রমণকারী probe app অনাথ permission গুলো **ঘোষণা করে** (সেটাই তো পরীক্ষা)।
# ফলে পরের রানে pm ওগুলোকে "সংজ্ঞায়িত" বলে — সংজ্ঞাদাতা আমরা নিজেরা।
# একবার ১৬টা অনাথ ৩-এ নেমেছিল, আর পাঠটা দেখতে "সমস্যা মিটে গেছে"-র মতো।
# তাই কেবল-আমাদের-সংজ্ঞায়িত নামগুলো বাদ: ওগুলো আসলে এখনো অনাথ।
SELF_RE="${MVRP_SELF_RE:-^com\.cindrasec\.}"
SELFONLY="$REP/self-only.txt"
awk -F'\t' -v re="$SELF_RE" '
  $2 ~ re { self[$1]=1; next }
  { other[$1]=1 }
  END { for (n in self) if (!(n in other)) print n }
' "$DEF" | sort -u > "$SELFONLY"
NSELF=$(grep -c . "$SELFONLY")
if [ "$NSELF" -gt 0 ]; then
  grep -vxF -f "$SELFONLY" "$DEFSET" > "$DEFSET.tmp" && mv "$DEFSET.tmp" "$DEFSET"
fi
NDEF=$(wc -l < "$DEFSET")

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
CTLOK=1
# group-বিহীন একটা, group-ভুক্ত তিনটে — আগের রানে শুধু প্রথমটা থাকায়
# control পাস করে যেত আর সব grouped permission অনাথ গোনা হতো।
for p in android.permission.INTERNET android.permission.CAMERA \
         android.permission.READ_CONTACTS android.permission.ACCESS_FINE_LOCATION; do
  grep -qx "$p" "$DEFSET" || { echo "!! BROKEN: $p সংজ্ঞায়িত দেখাচ্ছে না — পার্সিং ভেঙেছে"; CTLOK=0; }
done
[ "$CTLOK" -eq 1 ] || { echo "   প্রথম কয়েকটা পার্স করা নাম:"; head -3 "$DEFSET" | sed 's/^/     /'; exit 2; }
echo "POSITIVE  জানা-সংজ্ঞায়িত (INTERNET, CAMERA) DEFINED হিসেবে ধরা পড়ছে"
if grep -qx 'com.cindrasec.definitely.not.a.real.permission' "$DEFSET"; then
  echo "!! BROKEN: বানানো permission-ও সংজ্ঞায়িত দেখাচ্ছে"; exit 2
fi
echo "POSITIVE  বানানো permission ORPHANED হিসেবেই থাকছে"
if [ "$NSELF" -gt 0 ]; then
  echo "NOTE      $NSELF টা permission কেবল probe app ($SELF_RE) সংজ্ঞায়িত করে —"
  echo "          বাদ দেওয়া হলো, কারণ ওগুলো আসলে এখনো অনাথ। তালিকা: $SELFONLY"
fi
echo

# ---------- প্রতিটা manifest ----------
pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')

echo "== পাহারাদার permission, আর সেগুলো কে সংজ্ঞায়িত করে =="
# অনাথ ছাড়াও একটা বড় শ্রেণি আছে যেটা আগে দেখিনি: permission সংজ্ঞায়িত,
# কিন্তু protectionLevel **normal**। তখন আক্রমণকারীর কোনো কৌশলই লাগে না —
# শুধু <uses-permission> লিখলেই install-এ স্বয়ংক্রিয় grant। অর্থাৎ ওই
# component কার্যত অরক্ষিত, অনাথের চেয়েও সহজে।
# dangerous হলে ব্যবহারকারীর সম্মতি লাগে — দুর্বল, কিন্তু এক ধাপ কঠিন।
# signature / privileged / internal = আসল পাহারা।
TOT=0; ORPH=0; WEAKN=0; WEAKD=0
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
    if ! grep -qxF "$perm" "$DEFSET"; then
      [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
      ORPH=$((ORPH+1))
      echo "  *** ORPHANED  $perm"
      echo "      কেউ সংজ্ঞায়িত করে না -> আক্রমণকারী নিজে ঘোষণা করে নিতে পারে"
      echo "      পাহারা দিচ্ছে: [$kind] $name  ($attr)"
    elif grep -qE '^normal' <<<"${level:-}" ; then
      [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
      WEAKN=$((WEAKN+1))
      echo "  ### WEAK-NORMAL  $perm"
      echo "      level=$level  সংজ্ঞাদাতা=$definer"
      echo "      যেকোনো app শুধু <uses-permission> লিখলেই পায় — পাহারা নামমাত্র"
      echo "      পাহারা দিচ্ছে: [$kind] $name  ($attr)"
    elif grep -qE '^dangerous' <<<"${level:-}" ; then
      WEAKD=$((WEAKD+1))
      if [ -n "${VERBOSE:-}" ]; then
        [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
        echo "  ##  WEAK-DANGEROUS  $perm   ([$kind] $name)"
      fi
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
echo "অনাথ (কেউ সংজ্ঞায়িত করে না): $ORPH"
echo "দুর্বল — normal (যে কেউ চাইলেই পায়): $WEAKN"
echo "দুর্বল — dangerous (ব্যবহারকারীর সম্মতি লাগে): $WEAKD   [VERBOSE=1 দিলে তালিকা]"
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
