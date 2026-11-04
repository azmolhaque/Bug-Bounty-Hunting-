#!/usr/bin/env bash
# mvrp-intent-forward.sh — exported components that carry someone else's Intent.
#
# Why this class and not the last one. Six times now the shape has been: an
# open manifest with `Binder.getCallingUid()` underneath (S47, S55, S56, S59,
# Wellbeing, Photos). That wall does not exist here. A component whose job is
# to take an Intent from a caller and start it cannot defend itself by
# checking the caller — forwarding *is* the feature. The program rules name
# the class directly:
#
#     Intent redirection -> launching non-exported components
#
# And the orphaned-permission class is spent: two findings, different apps,
# different impact, both closed as duplicates of the same generic marker 1469
# within minutes. Quality was not the variable there. Class was.
#
# What it does: for every exported component in a decoded manifest, find that
# class in the decompiled sources and look for a caller-supplied Intent
# reaching a dispatch call.
#
# What it cannot do, stated so a zero is readable: jadx renames obfuscated
# classes, so a component whose manifest name does not exist as a source file
# is reported as UNREADABLE rather than silently counted as clean. Those are
# not evidence of absence.
#
# Usage:
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-intent-forward.sh
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-intent-forward.sh com.google.android.gms
#   ./scripts/mvrp-intent-forward.sh --selftest
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; SRC="$OUT/src"
REP="$OUT/intentfwd"; mkdir -p "$REP"
LOG="$REP/intentfwd-$(date +%Y%m%d-%H%M).txt"

# A caller-supplied Intent arriving. Each of these yields an object the app did
# not construct.
SOURCE_RE='getParcelableExtra|getParcelableArrayListExtra|Intent\.parseUri|Intent\.getIntent|getIntentSender|android\.intent\.extra\.INTENT|EXTRA_INTENT|getBundleExtra'
# Somewhere that object is dispatched under the app's own identity.
SINK_RE='startActivit(y|yForResult|ies)|startService|startForegroundService|sendBroadcast|sendOrderedBroadcast|bindService|startIntentSender|PendingIntent\.(getActivity|getBroadcast|getService)|setResult'

selftest() {
  local t; t=$(mktemp -d)
  cat > "$t/Good.java" <<'EOF'
public class Good {
  protected void onCreate(Bundle b) {
    Intent next = (Intent) getIntent().getParcelableExtra("android.intent.extra.INTENT");
    startActivity(next);
  }
}
EOF
  cat > "$t/Parsed.java" <<'EOF'
public class Parsed {
  void go(String s) throws Exception {
    Intent i = Intent.parseUri(s, 0);
    startActivityForResult(i, 1);
  }
}
EOF
  cat > "$t/Clean.java" <<'EOF'
public class Clean {
  void go() {
    Intent i = new Intent(this, Other.class);
    i.putExtra("x", getIntent().getStringExtra("x"));
    startActivity(i);
  }
}
EOF
  local fail=0
  for f in Good Parsed; do
    grep -qE "$SOURCE_RE" "$t/$f.java" && grep -qE "$SINK_RE" "$t/$f.java" \
      || { echo "!! selftest: $f should have matched"; fail=1; }
  done
  # Clean has a sink and reads a String extra, but never a caller-built Intent.
  if grep -qE "$SOURCE_RE" "$t/Clean.java"; then
    echo "!! selftest: Clean matched a source it should not have"; fail=1
  fi
  rm -rf "$t"
  [ "$fail" -eq 0 ] && echo "POSITIVE  patterns match forwarding and ignore a locally built Intent"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

[ -d "$DEC" ] || { echo "!! no decoded manifests at $DEC"; exit 1; }
[ -d "$SRC" ] || { echo "!! no decompiled sources at $SRC — run mvrp-decompile-missing.sh"; exit 1; }

exported() {   # exported <manifest> -> "kind<TAB>class<TAB>permission"
  python3 -I - "$1" <<'PY'
import sys, xml.etree.ElementTree as ET
AND = "http://schemas.android.com/apk/res/android"
def a(e, n, d=""): return e.get("{%s}%s" % (AND, n), d)
try: root = ET.parse(sys.argv[1]).getroot()
except Exception: sys.exit(0)
app = root.find("application")
if app is None: sys.exit(0)
pkg = root.get("package", "")
for k in ("activity", "activity-alias", "service", "receiver"):
    for el in app.findall(k):
        if a(el, "enabled") == "false": continue
        exp = a(el, "exported")
        if not (exp == "true" or (exp == "" and el.findall("intent-filter"))): continue
        name = a(el, "targetActivity") or a(el, "name")
        if name.startswith("."): name = pkg + name
        print("%s\t%s\t%s" % (k, name, a(el, "permission") or "-"))
PY
}

{
echo "# intent forwarding sweep — exported components that dispatch a caller's Intent"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# source : $OUT"
echo

echo "== CONTROL =="
selftest || exit 2
echo

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')
echo "== ${#pkgs[@]} package(s) =="

NHIT=0; NREAD=0; NUNREAD=0; NNOSRC=0; NSTRONG=0; NWEAK=0; NINTENT=0; NSTALE=0
for pkg in "${pkgs[@]}"; do
  case "$pkg" in com.cindrasec.*) continue ;; esac
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue
  tree="$SRC/$pkg/sources"
  if [ ! -d "$tree" ]; then NNOSRC=$((NNOSRC+1)); continue; fi

  # The manifest comes from the APK on the device; the sources come from
  # whenever jadx last ran. `refresh` used to replace one and not the other,
  # so an updated app was read as a new manifest against months-old code —
  # tycho was swept at V170 with V128's sources and nothing in the output
  # said so. A tree older than its manifest is reported, not used.
  if [ "$m" -nt "$tree" ]; then
    NSTALE=$((NSTALE+1))
    echo "  !! $pkg: sources are older than the manifest — decompile again before trusting this"
    continue
  fi

  printed=0
  while IFS=$'\t' read -r kind cls perm; do
    [ -n "${cls:-}" ] || continue
    f="$tree/$(echo "$cls" | tr '.' '/').java"
    if [ ! -f "$f" ]; then NUNREAD=$((NUNREAD+1)); continue; fi
    NREAD=$((NREAD+1))
    grep -qE "$SOURCE_RE" "$f" || continue
    grep -qE "$SINK_RE"  "$f" || continue
    # Where the Intent comes from decides whether an attacker can set it.
    # In an activity, `onActivityResult(int, int, Intent)`'s Intent is the
    # *child's* result, not the caller's — three of the first three candidates
    # died exactly there (Docs ProjectorActivity:502, Home DeeplinkActivity:357
    # and Tasks' trampoline). In a receiver or a service, the Intent parameter
    # is whoever sent it. And `getIntent()` in an activity is the launch Intent,
    # which is the caller's.
    case "$kind" in
      receiver|service) via="caller (onReceive/onStartCommand)" ;;
      *)
        if grep -qE "getIntent\(\)[^;]*($SOURCE_RE)" "$f"; then
          via="caller (getIntent)"
        elif grep -qE 'onActivityResult' "$f"; then
          via="UNCLEAR — file has onActivityResult; check which Intent"
        else
          via="caller (getIntent)"
        fi ;;
    esac
    # What the caller actually hands over. Most hits take a Uri, a Bundle or an
    # app's own parcelable, and none of those is intent redirection — four of
    # the first pass's candidates were read before this was obvious. Only an
    # Intent can be dispatched at someone else's component; an IntentSender or
    # PendingIntent runs as whoever built it, so it only matters when the app
    # attaches its own data to it (`send(ctx, code, fillIn)` rather than
    # `send()`), which Photos did not.
    types=""
    grep -E "$SOURCE_RE" "$f" | grep -qE 'Intent\.class|\(Intent\)|parseUri|android\.intent\.extra\.INTENT|EXTRA_INTENT' && types="$types Intent"
    grep -E "$SOURCE_RE" "$f" | grep -q 'IntentSender'   && types="$types IntentSender"
    grep -E "$SOURCE_RE" "$f" | grep -q 'PendingIntent'  && types="$types PendingIntent"
    grep -E "$SOURCE_RE" "$f" | grep -q 'Uri'            && types="$types Uri"
    grep -E "$SOURCE_RE" "$f" | grep -q 'getBundleExtra' && types="$types Bundle"
    [ -n "$types" ] || types=" other"

    NHIT=$((NHIT+1))
    case "$via" in UNCLEAR*) NWEAK=$((NWEAK+1)) ;; *) NSTRONG=$((NSTRONG+1)) ;; esac
    case "$types" in *Intent*) NINTENT=$((NINTENT+1)) ;; esac
    [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
    echo "  [$kind] $cls"
    echo "      guard: $perm"
    echo "      from : $via"
    echo "      takes:$types"
    grep -nE "$SOURCE_RE" "$f" | head -3 | sed 's/^/        src  /'
    grep -nE "$SINK_RE"   "$f" | head -3 | sed 's/^/        sink /'
  done < <(exported "$m")
done

echo
echo "== summary =="
echo "components read            : $NREAD"
echo "both a source and a sink   : $NHIT"
echo "  of those, caller-supplied: $NSTRONG   <- read these"
echo "  of those, unclear source : $NWEAK   (onActivityResult in the file)"
echo "  of those, taking an Intent: $NINTENT   <- only these can be redirected"
echo "class not in the sources   : $NUNREAD   (obfuscated or split out — NOT clean)"
echo "packages without sources   : $NNOSRC   (run mvrp-decompile-missing.sh)"
echo "packages with STALE sources: $NSTALE   <- manifest newer than code; not read"

cat <<'NOTE'

== reading it ==
A hit means one file mentions both a caller-supplied Intent and a dispatch
call. It does not mean they are the same object — that is the next read, by
hand, and most will not survive it.

What survives is the shape the rules pay for: the component takes an Intent
from whoever asked, and starts it with the app's own identity. The finding is
not that it forwards; it is the non-exported component you reached through it,
or the permission you borrowed. Reach one, show what came back, and stop.

"class not in the sources" is the honest unknown here. jadx renames obfuscated
classes, so those components were not examined at all. They are not clean.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
