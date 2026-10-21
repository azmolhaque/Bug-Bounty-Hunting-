#!/usr/bin/env bash
# mvrp-perms.sh — "Orphaned permissions" ধরো।
#
# কেন এটা আগে: Mobile VRP rules-এ qualifying তালিকায় নাম ধরে লেখা আছে —
#   "Orphaned permissions"
# মানে এটা অনুমান না, program নিজে বলেছে এর টাকা দেয়।
#
# আক্রমণটা কী:
#   একটা component লেখা আছে android:permission="com.foo.BAR" দিয়ে। দেখতে সুরক্ষিত।
#   কিন্তু সেই permission-টা যদি —
#     (ক) protectionLevel=normal হয়  -> install করলেই যেকোনো app পেয়ে যায়, guard অর্থহীন
#     (খ) কোনো package declare-ই না করে -> malicious app নিজে declare করে নিজেকে দিতে পারে
#   তাহলে তালা আছে, চাবি সবার হাতে।
#
# ব্যবহার:  ./mvrp-perms.sh                      # decoded সব app
#           ./mvrp-perms.sh com.fitbit.FitbitMobile
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; REP="$OUT/perms"
mkdir -p "$REP"
MAP="$REP/device-permissions.txt"
LOG="$REP/perms-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

# ---- ডিভাইসের permission মানচিত্র একবার তোলো ----
echo "[1/3] device permission map..."
# -g দরকার। `pm list permissions -f` একা চালালে **grouped permission বাদ
# পড়ে** — CAMERA, READ_CONTACTS, CALL_PHONE, ACCESS_COARSE_LOCATION কোনোটাই
# আসে না। ফল: ওগুলো "এই ডিভাইসে ঘোষিত নয়" দেখায়, আর platform-এর নিজের
# permission মিথ্যা করে অনাথ/PLATFORM শ্রেণিতে চলে যায়। এই ত্রুটি
# mvrp-orphan.sh-এ আগে সারানো হয়েছিল, এখানে রয়ে গিয়েছিল।
adb shell pm list permissions -f -g 2>/dev/null | tr -d '\r' > "$MAP"
LINES=$(wc -l < "$MAP")
echo "      $LINES lines -> $MAP"
if [ "$LINES" -lt 100 ]; then
  echo "!! CONTROL FAIL: permission map খুব ছোট ($LINES)। adb ঠিকমতো কথা বলছে না।"
  exit 3
fi

# perm|package|protectionLevel বানাও
awk '
  /^[ \t]*\+?[ \t]*permission:/ {
      if (p!="") print p "|" pk "|" pl
      p=$0; sub(/^[ \t]*\+?[ \t]*permission:/,"",p); pk=""; pl=""; next }
  /^[ \t]*package:/        { pk=$0; sub(/^[ \t]*package:/,"",pk) }
  /^[ \t]*protectionLevel:/{ pl=$0; sub(/^[ \t]*protectionLevel:/,"",pl) }
  END { if (p!="") print p "|" pk "|" pl }
' "$MAP" | sed 's/[[:space:]]*$//' > "$REP/.parsed"

PARSED=$(wc -l < "$REP/.parsed")
echo "      parsed $PARSED permissions"

# নিজের probe app যে permission ঘোষণা করে সেগুলো বাদ দাও। না দিলে আমরা যে
# অনাথ permission খুঁজছি, আমাদের নিজের app সেটা ঘোষণা করে বসে থাকায় সেটা
# আর অনাথ দেখায় না — আর "সমস্যা মিটে গেছে" বলে মনে হয়।
SELF_RE="${MVRP_SELF_RE:-^com\.cindrasec\.}"
SELFN=$(awk -F'|' -v re="$SELF_RE" '$2 ~ re' "$REP/.parsed" | grep -c . || true)
if [ "$SELFN" -gt 0 ]; then
  echo "      নিজের app ঘোষিত $SELFN টা permission বাদ দেওয়া হলো ($SELF_RE)"
  awk -F'|' -v re="$SELF_RE" '$2 !~ re' "$REP/.parsed" > "$REP/.parsed.tmp"
  mv "$REP/.parsed.tmp" "$REP/.parsed"
  PARSED=$(wc -l < "$REP/.parsed")
  echo "      বাকি $PARSED"
fi

lookup() { grep -m1 "^$1|" "$REP/.parsed" 2>/dev/null; }

# ---- CONTROL ----
echo "[2/3] control..."
POS=$(lookup "android.permission.BLUETOOTH_PRIVILEGED")
SEN=$(lookup "com.canary.not.a.real.permission.DOES_NOT_EXIST")
echo "      POSITIVE android.permission.BLUETOOTH_PRIVILEGED -> ${POS:-NOT FOUND}"
echo "      SENTINEL com.canary.not.a.real.permission...      -> ${SEN:-NOT FOUND (সঠিক)}"
case "$POS" in
  *signature*) : ;;
  *) echo "!! CONTROL FAIL: পরিচিত signature permission পাওয়া গেল না বা ভুল level।"
     echo "!! parser ভাঙা — এই রানের ফলাফল বিশ্বাস কোরো না।"; exit 3;;
esac
[ -n "$SEN" ] && { echo "!! CONTROL FAIL: বানানো permission-ও 'পাওয়া গেছে'। lookup ভাঙা।"; exit 3; }
echo "      control ঠিক আছে।"

# ---- target ----
pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')

{
echo "# Orphaned / weak guard permission sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# map    : $PARSED permissions declared on this device"
echo

for pkg in "${pkgs[@]}"; do
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue

  # component guard attributes (uses-permission নয় — ওটা চাওয়া, পাহারা নয়)
  mapfile -t guards < <(grep -o 'android:\(read\|write\)\?[Pp]ermission="[^"]*"' "$m" \
                        | sed 's/.*="//;s/"$//' | sort -u | grep -v '^$')
  [ ${#guards[@]} -eq 0 ] && continue

  hits=""
  for g in "${guards[@]}"; do
    row=$(lookup "$g")
    if [ -z "$row" ]; then
      # android.permission.* প্ল্যাটফর্মের নিজস্ব namespace। সেখানে একটা নাম
      # pm list permissions-এ না দেখালেও তা "দখলযোগ্য" নয় — প্ল্যাটফর্ম নিজের
      # manifest-এ সেটা সংজ্ঞায়িত করে, আর নতুন API-র permission পুরনো OS-এ
      # স্বাভাবিকভাবেই অনুপস্থিত থাকে (BIND_APP_FUNCTION_SERVICE = API 36)।
      # এগুলোকে SQUATTABLE বলা মানে ভুল পথে সময় নষ্ট।
      case "$g" in
        android.permission.*|android.*.permission.*)
          hits+="  PLATFORM    $g\n              এই ডিভাইসে ঘোষিত নয় (সম্ভবত নতুন API-র)। platform namespace — দখলযোগ্য নয়।\n"
          continue;;
      esac
      hits+="  SQUATTABLE  $g\n              কোনো package declare করে না -> malicious app নিজে declare করে self-grant করতে পারে\n"
      continue
    fi
    decl=$(cut -d'|' -f2 <<<"$row"); lvl=$(cut -d'|' -f3- <<<"$row")
    case "$lvl" in
      *signature*|*knownSigner*) : ;;                       # ঠিক আছে
      normal|*normal*)  hits+="  OPEN        $g\n              protectionLevel=$lvl  declared by=$decl\n              -> install করলেই যেকোনো app পায়। guard অর্থহীন।\n";;
      *dangerous*)      hits+="  GRANTABLE   $g\n              protectionLevel=$lvl  declared by=$decl\n              -> user prompt-এ পাওয়া যায়।\n";;
      *)                hits+="  CHECK       $g\n              protectionLevel=$lvl  declared by=$decl\n";;
    esac
  done

  if [ -n "$hits" ]; then
    echo "== $pkg  (${#guards[@]} guard permission)"
    printf '%b' "$hits"
    echo
  fi
done

echo "== পড়ার নিয়ম =="
cat <<'NOTE'
SQUATTABLE  সবচেয়ে দামি। পরের ধাপ: একটা ছোট app লেখো যেটা ওই permission
            <permission android:name="..." android:protectionLevel="normal"/>
            হিসেবে declare করে, তারপর guarded component-এ পৌঁছায়।
            পৌঁছাতে পারলে -> তখন জিজ্ঞেস করো কী পেলে। data না পেলে kill list।
OPEN        guard আছে কিন্তু normal level -> যেকোনো app পায়। component-এ
            পৌঁছে দেখো সেখানে আসলে কী আছে।
GRANTABLE   user prompt লাগে। rules বলে "unreasonable user interaction" বাদ,
            তাই এক-ট্যাপে না হলে ছেড়ে দাও।
CHECK       হাতে দেখো।

মনে রাখো: পৌঁছানো = precondition, finding নয় (CLAUDE.md FO-8)।
"attacker আসলে কী পেল?" -> token/medical/message না হলে DROP.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "[3/3] রিপোর্ট: $LOG"
