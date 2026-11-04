#!/usr/bin/env bash
# mvrp-update-diff.sh — কেবল যা বদলেছে তাই দেখো।
#
# কৌশল: গতকালের পাঠ হলো ভিড়ই আসল শত্রু — Google-এর পরিপক্ব app ছয় স্তরে
# পাহারা দেয় কারণ বছরের পর বছর শত শত হান্টার ওগুলো ঝাড়ু দিয়েছে। কিন্তু
# একটা **নতুন রিলিজ** ওই ভিড়টা কয়েক দিনের জন্য সরিয়ে দেয়: নতুন component,
# নতুন permission, নতুন কোড — আর কেউ এখনো দেখেনি।
#
# তাই ৬৫টা app আবার টানা নয়। পুরোনো অবস্থা ইতিমধ্যেই ডিস্কে:
# decoded manifest-এ versionName লেখা থাকে, আর ডিভাইসে চলছে নতুনটা।
# দুটো মিলিয়ে কিছু না টেনেই বলা যায় কোনগুলো বাসি।
#
# ধাপ:
#   stale   — কোন app আপডেট হয়েছে (কিছু টানে না, সেকেন্ডের কাজ)
#   refresh — শুধু বাসিগুলো টেনে আবার decode করো, পুরোনোটা prev/ এ রেখে
#   diff    — পুরোনো বনাম নতুন manifest: নতুন exported component, নতুন guard
#
# ব্যবহার:
#   ./mvrp-update-diff.sh stale
#   ./mvrp-update-diff.sh refresh
#   ./mvrp-update-diff.sh diff
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; PREV="$OUT/decoded.prev"; APK="$OUT/apk"; SRC="$OUT/src"
REP="$OUT/updiff"; mkdir -p "$REP"
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-stale}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

manifest_of() { echo "$DEC/$1/resources/AndroidManifest.xml"; }

stored_ver() {   # decoded manifest থেকে versionName
  local m; m=$(manifest_of "$1")
  [ -f "$m" ] || { echo ""; return; }
  grep -o 'android:versionName="[^"]*"' "$m" 2>/dev/null | head -1 \
    | sed 's/.*="//; s/"$//'
}
live_ver() {     # ডিভাইস থেকে versionName
  adb shell dumpsys package "$1" 2>/dev/null </dev/null | tr -d '\r' \
    | awk -F= '/versionName=/{print $2; exit}'
}

# ---------- component ছাপ: kind | name | exported | permission ----------
comps() {
  local m="$1"
  [ -f "$m" ] || return 0
  python3 -I - "$m" <<'PY'
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=""): return e.get("{%s}%s"%(AND,n),d)
try: root=ET.parse(sys.argv[1]).getroot()
except Exception: sys.exit(0)
app=root.find("application")
if app is None: sys.exit(0)
rows=[]
for k in ("activity","activity-alias","service","receiver","provider"):
    for el in app.findall(k):
        exp=a(el,"exported")
        exported = exp=="true" or (exp=="" and el.findall("intent-filter"))
        if not exported: continue
        if a(el,"enabled")=="false": continue
        perm = a(el,"permission") or a(el,"readPermission") or a(el,"writePermission") or "-"
        rows.append("%s\t%s\t%s" % (k, a(el,"name"), perm))
for r in sorted(set(rows)): print(r)
PY
}

mapfile -t PKGS < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')
[ ${#PKGS[@]} -eq 0 ] && { echo "!! $DEC খালি — আগে mvrp-surface.sh চালাও"; exit 1; }

# ইনস্কোপ package চেনার একমাত্র সংজ্ঞা, mvrp-pull.sh-এর সাথে ভাগ করা।
. "$HERE/lib/inscope-pkgs.sh"

# ================= stale =================
if [ "$MODE" = "stale" ]; then
  LIST="$REP/stale.txt"; : > "$LIST"
  echo "# কোন app আপডেট হয়েছে (কিছু টানা হচ্ছে না)"
  echo "# decoded: ${#PKGS[@]} টা package"
  echo
  NCHK=0; NSTALE=0; NGONE=0
  for p in "${PKGS[@]}"; do
    s=$(stored_ver "$p"); l=$(live_ver "$p")
    if [ -z "$l" ]; then NGONE=$((NGONE+1)); continue; fi
    NCHK=$((NCHK+1))
    if [ -z "$s" ]; then
      printf '%-52s stored=?            live=%s   (manifest-এ version নেই)\n' "$p" "$l"
      echo "$p" >> "$LIST"; NSTALE=$((NSTALE+1))
    elif [ "$s" != "$l" ]; then
      printf '%-52s %s  ->  %s\n' "$p" "$s" "$l"
      echo "$p" >> "$LIST"; NSTALE=$((NSTALE+1))
    fi
  done
  # ---------- কখনো decode হয়নি এমন ইনস্কোপ app ----------
  # এই লুপটা কেবল $DEC-এ থাকা package ঘোরে, তাই **নতুন ইনস্টল করা** app
  # এখানে কখনো আসে না — ওদের decoded ডিরেক্টরিই নেই। আগে স্ক্রিপ্ট
  # "N টা আপডেট হয়েছে" বলে থেমে যেত আর নতুনগুলোর কথা বলত না, যেটা
  # নীরব শূন্য: যা বিবেচনাই করা হয়নি তার অনুপস্থিতি আউটপুটে দেখা যায় না।
  NNEW=0
  while read -r p; do
    [ -n "$p" ] || continue
    [ -d "$DEC/$p" ] && continue
    case "$p" in com.cindrasec.*) continue ;; esac
    printf '%-52s নতুন — কখনো decode হয়নি   live=%s\n' "$p" "$(live_ver "$p")"
    echo "$p" >> "$LIST"; NNEW=$((NNEW+1))
  done < <(adb shell pm list packages 2>/dev/null </dev/null | tr -d '\r' \
             | sed 's/^package://' | grep -E "$MVRP_PKG_RE" | sort -u)

  echo
  echo "== সারাংশ =="
  echo "যাচাই করা: $NCHK   আপডেট হয়েছে: $NSTALE   নতুন: $NNEW   ডিভাইসে নেই: $NGONE"
  NSTALE=$((NSTALE + NNEW))
  if [ "$NCHK" -eq 0 ]; then
    echo "!! BROKEN: একটা app-এরও live version পড়া গেল না — dumpsys ভেঙেছে"
    exit 2
  fi
  if [ "$NSTALE" -eq 0 ]; then
    echo "একটাও বদলায়নি। নতুন কিছু দেখার নেই — এটা শূন্য ফল, ত্রুটি নয়।"
    exit 0
  fi
  echo "তালিকা: $LIST"
  echo "পরের ধাপ: ./mvrp-update-diff.sh refresh"
  exit 0
fi

# ================= refresh =================
if [ "$MODE" = "refresh" ]; then
  LIST="$REP/stale.txt"
  [ -s "$LIST" ] || { echo "!! $LIST খালি — আগে 'stale' চালাও"; exit 1; }
  mapfile -t S < <(cat "$LIST")
  echo "== ${#S[@]} টা app refresh হবে =="
  mkdir -p "$PREV"
  for p in "${S[@]}"; do
    # পুরোনো decode সরিয়ে রাখো — diff-এর জন্য এটাই একমাত্র সাক্ষী
    rm -rf "${PREV:?}/$p"; mkdir -p "$PREV"
    [ -d "$DEC/$p" ] && mv "$DEC/$p" "$PREV/$p"
    rm -rf "${APK:?}/$p"
    # সোর<09cd>সও ফেলে দিতে হবে। নইলে decompile-missing "এর তো সোর্স আছে"
    # বলে এড়িয়ে যায়, আর পরের সুইপ **নতুন manifest-এর সাথে পুরনো কোড**
    # জোড়ে। tycho V128->V170 ঠিক এভাবেই বিয়াল্লিশ রিলিজ পুরনো কোড নিয়ে
    # পড়া হয়েছিল, আর আউটপুটে সেটা বোঝার কোনো উপায় ছিল না।
    rm -rf "${SRC:?}/$p"
  done
  echo "[pull] ${#S[@]} টা package"
  "$HERE/mvrp-pull.sh" "${S[@]}" 2>&1 | tail -5
  echo "[decode]"
  "$HERE/mvrp-surface.sh" "${S[@]}" 2>&1 | tail -12
  echo
  echo "পরের ধাপ: ./mvrp-update-diff.sh diff"
  exit 0
fi

# ================= diff =================
if [ "$MODE" = "diff" ]; then
  LIST="$REP/stale.txt"
  [ -s "$LIST" ] || { echo "!! $LIST খালি — আগে 'stale' চালাও"; exit 1; }
  mapfile -t S < <(cat "$LIST")
  LOG="$REP/diff-$(date +%Y%m%d-%H%M).txt"
  {
  echo "# আপডেট-ডিফ — কেবল নতুন/বদলানো exported component"
  echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# apps : ${#S[@]}"
  echo

  # control: অন্তত একটা app-এর দুই পাশের ছাপ পড়া যাচ্ছে তো?
  OKP=0
  for p in "${S[@]}"; do
    [ -f "$PREV/$p/resources/AndroidManifest.xml" ] && [ -f "$(manifest_of "$p")" ] && OKP=$((OKP+1))
  done
  if [ "$OKP" -eq 0 ]; then
    echo "!! BROKEN: একটাও app-এর পুরোনো+নতুন manifest জোড়া পাওয়া গেল না।"
    echo "   'refresh' চলেছিল তো? $PREV দেখো।"
    exit 2
  fi
  echo "POSITIVE  $OKP/${#S[@]} টা app-এর দুই পাশের manifest পড়া গেছে"
  echo

  TOTNEW=0
  for p in "${S[@]}"; do
    o="$PREV/$p/resources/AndroidManifest.xml"
    n=$(manifest_of "$p")
    if [ ! -f "$o" ] || [ ! -f "$n" ]; then
      echo "-- $p : এক পাশ নেই, তুলনা করা গেল না (অনিষ্পন্ন, শূন্য নয়)"
      continue
    fi
    # comm locale-এর collation ক্রম ধরে নেয়, কিন্তু python-এর sorted()
    # কোডপয়েন্ট-ক্রমে সাজায়। দুটো মিলল না বলে comm "not in sorted order"
    # সতর্ক করে — আর তবু আউটপুট দেয়, ভুল আউটপুট। নীরব দূষণ।
    # দুই পাশে একই ক্রম বাধ্য করা হচ্ছে: LC_ALL=C।
    added=$(LC_ALL=C comm -13 \
              <(comps "$o" | LC_ALL=C sort) \
              <(comps "$n" | LC_ALL=C sort) 2>"$REP/.comm.err")
    if [ -s "$REP/.comm.err" ]; then
      echo "!! $p : comm অভিযোগ করেছে — এই তুলনাটা বিশ্বাস করা যাবে না"
      sed 's/^/     /' "$REP/.comm.err"
      : > "$REP/.comm.err"
      continue
    fi
    [ -z "$added" ] && continue
    c=$(grep -c . <<<"$added"); TOTNEW=$((TOTNEW+c))
    echo "== $p   (+$c)"
    while IFS=$'\t' read -r kind name perm; do
      [ -z "$kind" ] && continue
      if [ "$perm" = "-" ]; then
        echo "  *** [$kind] $name   — exported, permission নেই"
      else
        echo "      [$kind] $name   perm=$perm"
      fi
    done <<<"$added"
    echo
  done

  echo "== সারাংশ =="
  echo "নতুন exported component: $TOTNEW"
  cat <<'NOTE'

== পড়ার নিয়ম ==
*** চিহ্নিত = exported আর permission-বিহীন। এগুলোই আগে, কারণ এখানে
    manifest-স্তরে কোনো পাহারাই নেই।
perm= দেওয়া গুলো পরে: permission-টা অনাথ কিনা দেখতে ./mvrp-orphan.sh,
    আর অনাথ হলে ./mvrp-orphan-test.sh দিয়ে differential।
কিছুই না এলে সেটা শূন্য ফল — উপরের POSITIVE লাইনটা বলছে তুলনা হয়েছে।
নতুন component মানেই বাগ নয়। তিনটে প্রশ্ন ক্রমে: বাইরে থেকে পৌঁছানো যায়?
পৌঁছে কী নিয়ন্ত্রণ করা যায়? তাতে কার সীমা পার হয়?
NOTE
  } 2>&1 | tee "$LOG"
  echo
  echo "রিপোর্ট: $LOG"
  exit 0
fi

echo "ব্যবহার: $0 [stale|refresh|diff]"
exit 1
