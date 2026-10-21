#!/usr/bin/env bash
# mvrp-bindtest.sh — stop reading, start binding.
#
# Static triage ran out of road: the caller check for a gRPC endpoint lives
# one reference away from the service class, so reading two files per
# component cannot tell a real boundary from an absent one. The device can.
#
# Three outcomes, and the difference between the first two cost a defect to
# learn once already:
#   DENIED     bindService() returned false — the system refused the bind
#   GATE-ONLY  bindService() returned true and no connection ever arrived;
#              the manifest let it through and something later did not
#   CONNECTED  onServiceConnected fired with a live binder, descriptor shown
#
# CONNECTED is not a finding. It is permission to ask the only question that
# has ever mattered here: what does it hand over?
#
# Needs the permissionless probe installed:
#   cd poc/mvrp-probe && AJ=~/tools/android-12/android.jar ./build.sh
#   adb install -r out/mvrp-probe.apk
#
# Usage:
#   ./mvrp-bindtest.sh                 # the shortlist below
#   ./mvrp-bindtest.sh <pkg> <cls>     # one target
#   ./mvrp-bindtest.sh -f targets.txt  # "pkg<space>cls" per line
set -uo pipefail

PROBE="com.cindrasec.mvrpprobe"
ACT="$PROBE/com.cindrasec.mvrpprobe.MainActivity"
WAIT="${WAIT:-6}"
OUT="${MVRP_OUT:-$HOME/mvrp}"; REP="$OUT/bindtest"; mkdir -p "$REP"
LOG="$REP/bindtest-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! no device"; exit 1; }
adb shell pm path "$PROBE" </dev/null 2>/dev/null | tr -d '\r' | grep -qF 'package:' \
  || { echo "!! $PROBE is not installed — build and install it first"; exit 1; }

# Highest payoff first, judged by what the component would be handing over if
# nothing stops us: health records, message content, backups, account data.
# Every one of these came out of the hand-back sweep with no permission guard
# at all, or a normal-level one that any app is granted at install.
read -r -d '' SHORTLIST <<'TARGETS' || true
com.google.android.apps.healthdata androidx.health.platform.client.impl.sdkservice.HealthDataSdkService
com.google.android.apps.healthdata com.google.android.apps.healthdata.service.androidx.HealthCoreService
com.google.android.apps.fitness androidx.health.platform.client.impl.sdkservice.HealthDataSdkService
com.fitbit.FitbitMobile androidx.health.platform.client.impl.sdkservice.HealthDataSdkService
com.google.android.apps.messaging com.google.android.ims.messaging.MessagingEngineEndpointService
com.google.android.apps.messaging com.google.android.apps.messaging.external.p2p.impl.ExternalRcsEndpointService
com.google.android.apps.messaging com.google.android.apps.messaging.backup.CustomD2DSourceEndpointService
com.google.android.apps.photos com.google.android.apps.photos.backup.apiservice.PhotosBackupApiService
com.google.android.apps.photos com.google.android.apps.photos.restore.apiservice.PhotosRestoreApiService
com.google.android.apps.tachyon com.google.android.apps.tachyon.contacts.reachability.ReachabilityService
com.google.android.apps.tachyon com.google.android.apps.tachyon.contacts.sync.DuoAccountService
com.google.android.apps.wear.companion com.google.android.apps.wear.companion.feature.sleepstate.server.service.SleepStateExportedService
com.google.android.gm com.android.email.service.EasAuthenticatorService
TARGETS

TARGETS_IN=""
case "${1:-}" in
  -f) TARGETS_IN=$(cat "$2") ;;
  "") TARGETS_IN="$SHORTLIST" ;;
  *)  TARGETS_IN="$1 $2" ;;
esac

probe_once() {   # probe_once <pkg> <cls> -> verdict line
  adb logcat -c </dev/null >/dev/null 2>&1
  adb shell am start -n "$ACT" --es action bind --es pkg "$1" --es cls "$2" \
      </dev/null >/dev/null 2>&1
  sleep "$WAIT"
  local out ret desc
  out=$(adb logcat -d MVRP:I '*:S' </dev/null 2>/dev/null | tr -d '\r')
  adb shell am force-stop "$PROBE" </dev/null >/dev/null 2>&1

  ret=$(printf '%s\n' "$out" | grep -oE 'bindService\(\) returned (true|false)' | tail -1)
  if printf '%s\n' "$out" | grep -q '^.*BOUND '; then
    desc=$(printf '%s\n' "$out" | grep -oE 'descriptor = .*' | tail -1)
    printf 'CONNECTED  %s\n' "${desc:-descriptor unreadable}"
  elif printf '%s\n' "$out" | grep -qE 'THROWN|SECURITY'; then
    # bindService does not only return false: with a manifest permission in
    # the way it throws SecurityException, and the first version of this
    # script matched neither branch and called that NO-SIGNAL — a refusal
    # read as a broken probe.
    printf 'DENIED     %s\n' "$(printf '%s\n' "$out" | grep -oE '(THROWN|SECURITY).*' | tail -1 | cut -c1-110)"
  elif printf '%s\n' "$ret" | grep -q 'true'; then
    printf 'GATE-ONLY  bind accepted, no connection within %ss\n' "$WAIT"
  elif printf '%s\n' "$ret" | grep -q 'false'; then
    printf 'DENIED     bindService() returned false\n'
  else
    printf 'NO-SIGNAL  the probe logged nothing — it did not run\n'
  fi
}

{
echo "# bind test"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# wait : ${WAIT}s per target"
echo

# ---- control 1: our own service ----
# This was AGSA's suggest service, on the grounds that it is known to connect.
# It is — to a probe that declares the orphaned QSB permission, which this one
# does not, so the control failed and called the probe broken when the probe
# was fine. A control has to measure our pipeline, not another app's policy.
POS=$(probe_once "$PROBE" com.cindrasec.mvrpprobe.SelfService)
case "$POS" in
  CONNECTED*) echo "POSITIVE  our own SelfService -> $POS" ;;
  *) echo "!! BROKEN: binding our own service came back: $POS"
     echo "!!         am start, onServiceConnected or logcat is not working."
     echo "!!         Rebuild the probe; it needs SelfService in the manifest."; exit 2 ;;
esac

# ---- control 2: a class that does not exist ----
NEG=$(probe_once com.google.android.apps.photos com.cindrasec.NoSuchService)
case "$NEG" in
  DENIED*|NO-SIGNAL*) echo "NEGATIVE  nonexistent class -> $NEG" ;;
  *) echo "!! BROKEN: binding a class that does not exist came back: $NEG"
     echo "!!         The verdicts below cannot be told apart from noise."; exit 2 ;;
esac
echo

while IFS= read -r line; do
  [ -n "$line" ] || continue
  pkg=$(printf '%s' "$line" | awk '{print $1}')
  cls=$(printf '%s' "$line" | awk '{print $2}')
  [ -n "$pkg" ] && [ -n "$cls" ] || continue
  v=$(probe_once "$pkg" "$cls")
  printf '%-10s %-38s %s\n' "${v%% *}" "${cls##*.}" "$pkg"
  case "$v" in CONNECTED*) printf '           %s\n' "${v#CONNECTED  }" ;; esac
done <<< "$TARGETS_IN"

cat <<'NOTE'

== reading it ==
DENIED and GATE-ONLY are finished: the first was refused outright, the second
was let past the manifest and stopped by something that does not announce
itself. Neither is worth more time.

CONNECTED means a live binder in an unprivileged app's hands. The descriptor
says whether there is an AIDL interface to speak or a raw Binder to work out.
Then the only question: call it, and see what comes back. Metadata and empty
responses are not findings — this project has the scars to prove it.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
