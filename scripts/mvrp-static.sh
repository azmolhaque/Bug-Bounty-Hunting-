#!/usr/bin/env bash
# mvrp-static.sh — decompile করা সোর্সে Mobile VRP-র **নাম-ধরে-পুরস্কৃত**
#                  তিনটে শ্রেণি খোঁজো।
#
# rules থেকে, আক্ষরিক:
#   "Path traversal / zip path traversal vulnerabilities leading to
#    arbitrary file write"
#   "Intent redirections leading to launching non-exported application
#    components"
#   "Vulnerabilities caused by unsafe usage of pending intents"
#
# এগুলো bind বা deeplink দিয়ে ধরা যায় না — কোডের নকশা-ত্রুটি। আমরা এতক্ষণ
# "বাইরে থেকে পৌঁছানো যায় কিনা" খুঁজেছি; এটা ভিন্ন স্তর।
#
# ব্যবহার:  ./mvrp-static.sh [pkg ...]
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
SRC="$OUT/src"; REP="$OUT/static"; mkdir -p "$REP"
LOG="$REP/static-$(date +%Y%m%d-%H%M).txt"

# ---- exported component মানচিত্র ----
# প্রার্থী ফাইলের ক্লাস যদি exported, permission-বিহীন component না হয়,
# বাইরের app পৌঁছাবেই না — তখন নকশা-ত্রুটি থাকলেও crossing নেই।
# এই ছাঁকনিটা হাতে করা মানে ৩৪টা প্রার্থী একে একে manifest-এ খোঁজা।
DECODED="$OUT/decoded"
expmap() {   # expmap <pkg> -> exported+unguarded ক্লাসের তালিকা
  local m="$DECODED/$1/resources/AndroidManifest.xml"
  [ -f "$m" ] || return 0
  python3 -I - "$m" <<'PY2'
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=None): return e.get("{%s}%s"%(AND,n),d)
app=ET.parse(sys.argv[1]).getroot().find("application")
for k in ("activity","activity-alias","service","receiver","provider"):
    for el in app.findall(k):
        if a(el,"enabled")=="false" or a(el,"permission"): continue
        exp=a(el,"exported")
        if exp=="true" or (exp is None and el.findall("intent-filter")):
            n=a(el,"name") or ""
            if n: print(n)
PY2
}
cls_of() { sed 's|^.*/sources/||; s|\.java$||; s|/|.|g' <<<"$1"; }

# ---- intent redirection-এর আসল আকার ----
# আগের শর্ত ছিল আলগা: "getParcelableExtra( আছে আর startActivity আছে আর
# Intent import করা"। তাতে Fitbit-এর FastPairLandingActivity ধরা পড়েছিল,
# অথচ সে extras থেকে তোলে একটা BluetoothDevice:
#     (BluetoothDevice) getIntent().getParcelableExtra("android.bluetooth.device.extra.DEVICE")
# আর যে Intent-টা start হয় সেটা ভেতরেই বানানো। শর্তটা কখনো দাবি করেনি যে
# তোলা parcelable-টাই start হওয়া Intent — সেটাই পুরো শ্রেণির সংজ্ঞা।
#
# jadx আসল আকারটা এভাবে লেখে (S43 ProjectorActivity):
#     startActivity((Intent) intent.getParcelableExtra("next_activity_result_key"));
# তাই (Intent) cast, বা Intent.class সহ typed overload — এটাই শর্ত।
# `Intent\.class` লিখলে `PendingIntent.class`-ও মেলে — Photos-এর AlbumActivity
# ঠিক ওই কারণে প্রার্থী হয়েছিল, অথচ সে extras থেকে একটা PendingIntent তোলে।
# আর সেটা উল্টো দিকের জিনিস: বাইরে থেকে পাওয়া PendingIntent পাঠালে তা
# আক্রমণকারীর পরিচয়েই চলে। তাই `Intent` শব্দের আগে অক্ষর থাকা চলবে না।
IR_RE='\(Intent\)[^;]*getParcelable|getParcelable(ArrayList)?Extra\([^)]*[^A-Za-z]Intent\.class'

# ---- zip traversal: পাহারার সব বৈধ রূপ ----
# আগের শর্ত ছিল "getCanonicalPath / getCanonicalFile / startsWith( নেই"।
# Fitbit-এর nbd.java ওতে প্রার্থী হয়ে এসেছিল, অথচ সে path-এর প্রতিটা অংশ
# ধরে হেঁটে `..` খোঁজে:
#     for (File f = new File(name); f != null; f = f.getParentFile())
#         if (f.getName().equals("..")) ...
# সেটা canonical-যাচাইয়ের বৈধ বিকল্প। অনুপস্থিতিকে প্রমাণ ভাবা হয়েছিল।
# তাই পাহারার তালিকায় component-walk, Path.normalize, আর ফাইলে ".."
# স্ট্রিং থাকা — সব ধরা হচ্ছে। lead-জেনারেটরে নির্ভুলতাই দামি।
ZIP_GUARD='getCanonicalPath|getCanonicalFile|startsWith\(|normalize\(\)|toPath\(\)|"\.\."'
# traversal-এর শর্ত: entry-র নাম **আক্রমণকারীর হাতে** থাকতে হবে, অর্থাৎ
# entry গুলো ঘুরে দেখা হচ্ছে, বা getEntry()-তে একটা চলক যাচ্ছে।
# Voice Access-এর jbd.java প্রার্থী হয়েছিল অথচ সে চায় getEntry("classes.dex")
# — ধ্রুবক নাম, ধ্রুবক গন্তব্য। পাহারার কিছুই নেই কারণ পাহারা দেওয়ার মতো
# কোনো চলকই নেই। শর্তটা কখনো দাবি করেনি নামটা entry থেকে আসছে।
ZIP_ITER='getNextEntry\(|\.entries\(\)|getEntry\([^")]'
# পাহারা অন্য ফাইলে থাকতে পারে। Messages-এর fauv.java প্রার্থী হয়েছিল কারণ
# তার নিজের ভেতরে ".." নেই — কিন্তু সে নামটা নেয় fiae.a(entry) থেকে, আর
# fiae.java-তে seekh-এর ZipFolderOpener-এর হুবহু একই component-walk আছে।
# একই লাইব্রেরির নতুন সংস্করণ, guard একটা helper-এ তোলা।
#
# এটা আলগা regex নয়, বিশ্লেষণের সীমা: যাচাই ফাইল-ভিত্তিক, dataflow নয়।
# সমাধান: যে ফাইলে ZipEntry আর ".." দুটোই আছে সেটা "পাহারা-helper", আর
# প্রার্থী ওদের কাউকে ডাকলে নামটা পরিশোধিত হয়ে আসছে ধরে নাও।
zip_files() {   # zip_files <sources-dir>
  local d="$1" helpers cand re
  helpers=$(grep -rlE 'ZipEntry' --include='*.java' "$d" 2>/dev/null \
    | xargs -r grep -lE '"\.\."' 2>/dev/null \
    | sed 's|.*/||; s|\.java$||' | sort -u)
  cand=$(grep -rlE 'ZipEntry|ZipInputStream|TarArchive' --include='*.java' "$d" 2>/dev/null \
    | xargs -r grep -lE "$ZIP_ITER" 2>/dev/null \
    | xargs -r grep -lE 'new File\(|appendPath\(' 2>/dev/null \
    | xargs -r grep -LE "$ZIP_GUARD" 2>/dev/null)
  [ -z "$cand" ] && return 0
  if [ -z "$helpers" ]; then printf '%s\n' "$cand"; return 0; fi
  re=$(printf '%s' "$helpers" | tr '\n' '|' | sed 's/|$//')
  printf '%s\n' "$cand" | xargs -r grep -LE "(^|[^A-Za-z0-9_])($re)\." 2>/dev/null
}

# ---- archive থেকে গতিশীল কোড লোড ----
# jbd.java খুঁজতে গিয়ে পাওয়া: সে একটা zip খুলে classes.dex বের করে লেখে।
# traversal নয়, কিন্তু অনেক দামি — archive আক্রমণকারীর নাগালে থাকলে ফল ACE,
# rules-এর সর্বোচ্চ শ্রেণি। এই শ্রেণিটা sweep-এ ছিলই না।
DEX_RE='DexClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DexFile|loadDex|"classes\.dex"'

# ---- অনিরাপদ PendingIntent: শর্ত তিনটে ----
# প্রথম রানে ১৪৩ ফাইল, আর তালিকা দেখলেই বোঝা যায় কেন অর্থহীন:
# MediaSessionCompat, androidx/compose, io/flutter, bumptech/glide, expo —
# তৃতীয় পক্ষের লাইব্রেরি, যা kill_list-এ স্পষ্ট ("Non-Google SDK/library ->
# report to the maintainer first")। ওগুলো গুনে রাখাও ভুল ছিল।
#
# বাকি দুটো শর্ত শ্রেণির সংজ্ঞা থেকেই আসে:
#   ২. PendingIntent আসলে **তৈরি** হচ্ছে, শুধু ধ্রুবকটা ফাইলে থাকা নয়
#   ৩. base Intent-এ component পিন করা নেই — setComponent/setClass/setPackage
#      বা new Intent(ctx, Foo.class) থাকলে গ্রাহকের ভরার জায়গা নেই
PI_LIB='/sources/(androidx|android/support|kotlin|kotlinx|io/flutter|com/bumptech|expo|com/squareup|okhttp3|com/facebook|org/chromium|j\$)/'
PI_CREATE='PendingIntent\.get(Activity|Activities|Broadcast|Service|ForegroundService)'
PI_PINNED='setComponent\(|setClass\(|setClassName\(|setPackage\(|new Intent\([^;]*\.class'
# সংখ্যাটা anchor করতেই হবে: 335544320 (= FLAG_ACTIVITY_NEW_TASK|CLEAR_TOP,
# একটা Intent flag) -এর ভেতরে 33554432 আছে। Wallet-এর WalletTileService ঠিক
# এভাবেই তালিকায় এসেছিল, অথচ তার PendingIntent 67108864 = FLAG_IMMUTABLE।
# ত্রুটি ১৩-এর যমজ: substring-কে token ভাবা।
PI_MUT='(^|[^0-9])33554432([^0-9]|$)'
pi_files() {   # pi_files <sources-dir>
  grep -rlE "$PI_MUT" --include='*.java' "$1" 2>/dev/null \
    | xargs -r grep -lE "$PI_CREATE" 2>/dev/null \
    | xargs -r grep -LE "$PI_PINNED" 2>/dev/null \
    | grep -vE "$PI_LIB"
}
IR_START='startActivity|startActivities|startService|startForegroundService|sendBroadcast|sendOrderedBroadcast|bindService'
ir_files() {   # ir_files <sources-dir>
  grep -rlE "$IR_RE" --include='*.java' "$1" 2>/dev/null \
    | xargs -r grep -lE "$IR_START" 2>/dev/null
}

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$SRC" 2>/dev/null | grep -v '\.log$')
[ ${#pkgs[@]} -eq 0 ] && { echo "!! $SRC খালি — আগে mvrp-decompile.sh চালাও"; exit 1; }

# PendingIntent ফ্ল্যাগ ধ্রুবক (jadx int হিসেবেই লেখে)
#   FLAG_IMMUTABLE = 67108864   FLAG_MUTABLE = 33554432
IMM=67108864
MUT=33554432

{
echo "# static sweep — Mobile VRP-র পুরস্কৃত শ্রেণি"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# apps : ${#pkgs[@]}"
echo

# ---- CONTROL ----
# Wellbeing-এ আমরা হাতে পড়ে জানি getCallingUid-ভিত্তিক যাচাই **আছে**
# (lrg.java)। grep যদি সেটাও না পায়, তাহলে পথ/প্যাটার্ন ভাঙা, ফলাফল অর্থহীন।
echo "== CONTROL =="
CTL=0
for c in "$SRC"/*/sources/defpackage/lrg.java; do
  [ -f "$c" ] && grep -q 'getPackagesForUid' "$c" && CTL=1
done
if [ "$CTL" -eq 1 ]; then
  echo "POSITIVE  জানা কোড (wellbeing lrg.java, getPackagesForUid) grep-এ ধরা পড়ছে"
else
  echo "(wellbeing-এর সোর্স নেই — control চালানো গেল না। ফলাফল দুর্বল।)"
fi

# intent-redirection প্যাটার্নটা দুটো fixture-এ বাঁধা: একটা জানা-আসল আকার,
# একটা জানা-মিথ্যা আকার (Fitbit FastPairLandingActivity, যেটা আগের আলগা
# শর্তে ধরা পড়েছিল)। প্যাটার্ন negative-টা ধরলে রান বাতিল — কারণ তখন
# প্রতিটা "প্রার্থী" আবার হাতে যাচাই করতে হবে, আর সেটাই সময় খায়।
FIX=$(mktemp -d); mkdir -p "$FIX/sources"
cat > "$FIX/sources/Pos.java" <<'J'
import android.content.Intent;
public class Pos extends android.app.Activity {
  protected void onCreate(android.os.Bundle b) {
    startActivity((Intent) getIntent().getParcelableExtra("next_activity_result_key"));
  }
}
J
cat > "$FIX/sources/Neg.java" <<'J'
import android.bluetooth.BluetoothDevice;
import android.content.Intent;
public class Neg extends android.app.Activity {
  protected void onCreate(android.os.Bundle b) {
    BluetoothDevice d = (BluetoothDevice) getIntent().getParcelableExtra("android.bluetooth.device.extra.DEVICE");
    Intent aD = new Intent(this, Neg.class);
    startActivity(aD);
  }
}
J
cat > "$FIX/sources/Neg2.java" <<'J'
import android.app.PendingIntent;
import android.content.Intent;
public class Neg2 extends android.app.Activity {
  protected void onCreate(android.os.Bundle b) {
    PendingIntent p = getIntent().getParcelableExtra("EXTRA_NATIVE_SHARESHEET_RELAUNCH_INTENT", PendingIntent.class);
    startActivity(new Intent(this, Neg2.class));
  }
}
J
HITS=$(ir_files "$FIX/sources" | sed "s|^$FIX/sources/||" | sort | tr '\n' ' ')
case "$HITS" in
  "Pos.java "*) [ "$HITS" = "Pos.java " ] \
      && echo "POSITIVE  IR প্যাটার্ন: আসল আকার ধরেছে, BluetoothDevice আকার ধরেনি" \
      || { echo "!! IR প্যাটার্ন মিথ্যা-ধনাত্মক দিচ্ছে: [$HITS] — থামলাম"; rm -rf "$FIX"; exit 2; } ;;
  *) echo "!! IR প্যাটার্ন জানা-আসল আকারই ধরতে পারছে না: [$HITS] — থামলাম"; rm -rf "$FIX"; exit 2 ;;
esac

# zip প্যাটার্নও একই ভাবে বাঁধা: একটা পাহারা-বিহীন extractor, আর একটা
# component-walk দিয়ে পাহারা দেওয়া (Fitbit nbd.java-র আকার)।
cat > "$FIX/sources/ZVuln.java" <<'J'
import java.util.zip.ZipEntry; import java.util.zip.ZipFile; import java.io.File;
public class ZVuln {
  void x(ZipFile z, File dir) throws Exception {
    ZipEntry e = z.entries().nextElement();
    File out = new File(dir, e.getName());
    new java.io.FileOutputStream(out).close();
  }
}
J
cat > "$FIX/sources/ZSafe.java" <<'J'
import java.util.zip.ZipEntry; import java.util.zip.ZipFile; import java.io.File;
public class ZSafe {
  void x(ZipFile z, File dir) throws Exception {
    ZipEntry e = z.entries().nextElement();
    String name = e.getName();
    for (File p = new File(name); p != null; p = p.getParentFile())
      if (p.getName().equals("..")) throw new SecurityException("traversal");
    new java.io.FileOutputStream(new File(dir, name)).close();
  }
}
J
cat > "$FIX/sources/ZConst.java" <<'J'
import java.util.zip.ZipEntry; import java.util.zip.ZipFile; import java.io.File;
public class ZConst {
  void x(File apk, File dir) throws Exception {
    ZipFile z = new ZipFile(apk);
    ZipEntry e = z.getEntry("classes.dex");
    File out = new File(dir, "dex");
    new java.io.FileOutputStream(out).close();
  }
}
J
# পাহারা অন্য ফাইলে: helper-টা নাম পরিশোধন করে, ডাকা ফাইলে ".." নেই
cat > "$FIX/sources/ZHelper.java" <<'J'
import java.util.zip.ZipEntry; import java.util.zip.ZipException; import java.io.File;
public final class ZHelper {
  public static String a(ZipEntry e) throws ZipException {
    String name = e.getName();
    if (name.contains("..")) {
      for (File f = new File(name); f != null; f = f.getParentFile())
        if (f.getName().equals("..")) throw new ZipException("Illegal name: " + name);
    }
    return name;
  }
}
J
cat > "$FIX/sources/ZViaHelper.java" <<'J'
import java.util.zip.ZipEntry; import java.util.zip.ZipInputStream; import java.io.File;
public class ZViaHelper {
  void x(ZipInputStream z, File dir) throws Exception {
    ZipEntry e;
    while ((e = z.getNextEntry()) != null) new File(dir, ZHelper.a(e));
  }
}
J
ZHITS=$(zip_files "$FIX/sources" | sed "s|^$FIX/sources/||" | sort | tr '\n' ' ')
rm -rf "$FIX"
if [ "$ZHITS" = "ZVuln.java " ]; then
  echo "POSITIVE  zip প্যাটার্ন: পাহারা-বিহীন ধরেছে, component-walk পাহারা ধরেনি"
else
  echo "!! zip প্যাটার্ন ভুল: [$ZHITS] (চাই: ZVuln.java) — থামলাম"; exit 2
fi
echo

TOT_PI=0; TOT_IR=0; TOT_ZIP=0; TOT_HOT=0; TOT_DEX=0
for pkg in "${pkgs[@]}"; do
  d="$SRC/$pkg/sources"
  [ -d "$d" ] || continue
  N=$(find "$d" -name '*.java' | wc -l)
  echo "== $pkg  ($N java)"

  # ---- ১. অনিরাপদ PendingIntent ----
  # FLAG_MUTABLE স্পষ্টভাবে দেওয়া = ডেভেলপার ইচ্ছে করে mutable চেয়েছে।
  # base Intent implicit (component সেট করা নেই) হলে গ্রাহক সেটা ভরে
  # app-এর পরিচয়ে যেকোনো জায়গায় পাঠাতে পারে।
  # খালি সংখ্যা খোঁজা যথেষ্ট নয়: 33554432 = 2^25, desugar করা java.util
  # concurrency কোডে bit mask হিসেবে এসেই যায় (j$/util/concurrent/*.java)।
  # ফাইলে PendingIntent-ও থাকতে হবে।
  PI=$(pi_files "$d" | head -20)
  if [ -n "$PI" ]; then
    c=$(wc -l <<<"$PI"); TOT_PI=$((TOT_PI+c))
    echo "  [PendingIntent] FLAG_MUTABLE ($MUT) — $c ফাইল"
    sed 's|^.*/sources/|      |' <<<"$PI" | head -8
  fi

  # ---- ২. Intent redirection ----
  # exported component extras থেকে একটা Intent তুলে সেটা start করলে,
  # বাইরের app ভেতরের non-exported component-এ পৌঁছাতে পারে।
  IR=$(ir_files "$d" | head -40)
  if [ -n "$IR" ]; then
    c=$(wc -l <<<"$IR"); TOT_IR=$((TOT_IR+c))
    echo "  [IntentRedirect] extras থেকে Intent + start — $c ফাইল"
    EXP=$(expmap "$pkg")
    HOT=""
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      k=$(cls_of "$f")
      grep -qxF "$k" <<<"$EXP" && HOT="$HOT$f\n"
    done <<<"$IR"
    if [ -n "$HOT" ]; then
      echo "  *** এর মধ্যে exported + permission-বিহীন:"
      printf '%b' "$HOT" | sed 's|^.*/sources/|      >>> |'
      TOT_HOT=$((TOT_HOT+$(printf '%b' "$HOT" | grep -c . )))
    else
      echo "      (একটাও exported component নয় — বাইরে থেকে পৌঁছানো যায় না)"
    fi
  fi

  # ---- ৪. archive থেকে dex লোড (ACE-র সম্ভাবনা) ----
  # Play Core-এর SplitCompat বাদ: ওটা প্রতিটা Google app-এ ঢোকানো থাকে, আর
  # split গুলো পড়ে app-এর নিজের প্রাইভেট ডিরেক্টরি থেকে যেখানে বাইরের app
  # লিখতে পারে না। প্রথম রানে চারটে hit-ই এটাই ছিল — সর্বত্র-উপস্থিত
  # লাইব্রেরি ধরলে শ্রেণিটা কোনো তথ্যই দেয় না (CVE-2020-8913, ২০২০-এ সারানো)।
  DX=$(grep -rlE "$DEX_RE" --include='*.java' "$d" 2>/dev/null \
       | xargs -r grep -lE 'ZipEntry|ZipFile|ZipInputStream|\.apk|\.zip' 2>/dev/null \
       | xargs -r grep -LE 'SplitCompat|makePathElements|splitcompat' 2>/dev/null | head -10)
  if [ -n "$DX" ]; then
    c=$(grep -c . <<<"$DX"); TOT_DEX=$((TOT_DEX+c))
    echo "  [DexFromArchive] archive + dex লোডার — $c ফাইল  *** ACE শ্রেণি"
    sed 's|^.*/sources/|      |' <<<"$DX" | head -8
  fi

  # ---- ৩. Zip / path traversal ----
  # ZipEntry.getName() সরাসরি new File(dir, name)-এ গেলে ../ দিয়ে
  # ডিরেক্টরির বাইরে লেখা যায় — rules-এ "arbitrary file write"।
  # canonical path যাচাই থাকলে নিরাপদ, তাই সেটাও দেখি।
  ZP=$(zip_files "$d" | head -20)
  if [ -n "$ZP" ]; then
    c=$(wc -l <<<"$ZP"); TOT_ZIP=$((TOT_ZIP+c))
    echo "  [ZipTraversal] zip + new File, canonical যাচাই নেই — $c ফাইল"
    sed 's|^.*/sources/|      |' <<<"$ZP" | head -8
  fi
  echo
done

echo "== সারাংশ =="
printf 'PendingIntent(MUTABLE): %s ফাইল\nIntentRedirect: %s ফাইল  (exported: %s)\nZipTraversal: %s ফাইল\nDexFromArchive: %s ফাইল\n' \
  "$TOT_PI" "$TOT_IR" "$TOT_HOT" "$TOT_ZIP" "$TOT_DEX"
cat <<'NOTE'

== পড়ার নিয়ম ==
এগুলো **প্রার্থী, finding নয়** — grep নকশা দেখে, প্রসঙ্গ দেখে না।
প্রতিটার জন্য তিনটে প্রশ্ন, ক্রমে:
  ১. যে component এটা ব্যবহার করে সে কি exported আর permission-বিহীন?
     না হলে বাইরের app পৌঁছাবেই না — বাদ।
  ২. PendingIntent-এর base Intent কি implicit (component সেট নেই)?
     setComponent/setClass থাকলে ভরার জায়গা নেই — বাদ।
  ৩. পৌঁছে attacker **কী পায়**? non-exported component চালু করা, বা
     app-এর ডিরেক্টরির বাইরে ফাইল লেখা — তবেই crossing।
     ফাইল লেখা পেলে থেমো না: rules বলে actual impact-এ টাকা, potential-এ নয়।
     .so overwrite করে ACE দেখানোই $2,250 থেকে $7,500-এ তোলে।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
