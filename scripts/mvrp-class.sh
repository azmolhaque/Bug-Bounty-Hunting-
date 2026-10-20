#!/usr/bin/env bash
# mvrp-class.sh — একটা নির্দিষ্ট ক্লাস decompile করো, পুরো app নয়।
#
# কেন: AGSA-তে ৫টা apk, লক্ষ লক্ষ মেথড। পুরোটা jadx করতে ঘণ্টা যায়, অথচ
# দরকার একটাই ক্লাস। jadx --single-class ঠিক সেটা দেয়।
#
# কোন apk-এ ক্লাসটা আছে তা আগে জানা নেই (base না split), তাই একে একে চেষ্টা।
#
# control: কোথাও না পেলে সেটা স্পষ্ট করে বলা হয় — "jadx ব্যর্থ" আর
# "ক্লাসটা নেই" দুটো আলাদা বার্তা, নইলে শূন্য ফল আবার অর্থহীন হয়ে যায়।
#
# ব্যবহার:
#   ./mvrp-class.sh com.google.android.googlequicksearchbox \
#       com.google.android.apps.search...ExportedSmartspaceTrampolineActivity
set -uo pipefail

PKG="${1:?ব্যবহার: $0 <package> <fully.qualified.ClassName>}"
CLS="${2:?ক্লাসের পূর্ণ নাম লাগবে}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
APKDIR="$OUT/apk/$PKG"
DEST="$OUT/class/$PKG"; mkdir -p "$DEST"
JADX="$(command -v jadx || echo "$HOME/bughunters/jadx/bin/jadx")"

[ -x "$JADX" ] || { echo "!! jadx নেই: $JADX"; exit 1; }
[ -d "$APKDIR" ] || { echo "!! apk নেই: $APKDIR — আগে mvrp-pull.sh চালাও"; exit 1; }

mapfile -t APKS < <(ls -1 "$APKDIR"/*.apk 2>/dev/null)
[ ${#APKS[@]} -eq 0 ] && { echo "!! $APKDIR-এ একটাও apk নেই"; exit 1; }

REL="$(printf '%s' "$CLS" | tr '.' '/').java"
echo "# pkg   : $PKG   (${#APKS[@]} টা apk)"
echo "# class : $CLS"
echo

TRIED=0; FOUND=""
for apk in "${APKS[@]}"; do
  TRIED=$((TRIED+1))
  d="$DEST/$(basename "$apk" .apk)"
  rm -rf "$d"; mkdir -p "$d"
  "$JADX" --single-class "$CLS" -d "$d" "$apk" > "$d.log" 2>&1
  f=$(find "$d" -name '*.java' -size +0 2>/dev/null | head -1)
  if [ -n "$f" ]; then
    echo "== পাওয়া গেছে: $(basename "$apk")"
    FOUND="$f"
    break
  fi
done

if [ -z "$FOUND" ]; then
  echo "!! $TRIED টা apk-এ ক্লাসটা পাওয়া যায়নি।"
  echo "   jadx কি আদৌ চলেছে? শেষ log-এর লেজ:"
  tail -5 "$DEST/$(basename "${APKS[-1]}" .apk).log" 2>/dev/null | sed 's/^/     /'
  echo "   ক্লাসের নাম manifest থেকে হুবহু কপি করেছ তো? (obfuscation নয়,"
  echo "   কিন্তু split apk-এ থাকলে উপরের লুপেই পাওয়া উচিত ছিল)"
  exit 2
fi

echo "# ফাইল  : $FOUND"
echo
cat "$FOUND"
