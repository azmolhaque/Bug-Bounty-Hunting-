#!/usr/bin/env bash
# mvrp-callercheck.sh — of the components that hand something back, which ones
# verify who is asking?
#
# Why this filter, and why it is the one that matters:
#   The hand-back sweep returns 173 components. Reading them all is a week.
#   But almost every dead end in this project died at the same step: the
#   component was reachable, it did hand something back, and then it checked
#   the caller and refused. AGSA's OneSearchSuggestService let the bind
#   through and then rejected every call from a non-first-party uid.
#   CameraPreviewProvider in Google Home checks getCallingPackage() and
#   verifies the signature. Those checks are invisible in the manifest and
#   are the real boundary.
#
#   LockProximityReceiver, the one that did not check, is the one that paid.
#
# So: UNCHECKED is where to spend time. CHECKED is where not to.
#
# A caller check found here does not mean the component is safe — the check
# may be wrong, or reachable around. It means read it last, not first.
#
# Usage:
#   ./mvrp-callercheck.sh                       # newest handback report
#   ./mvrp-callercheck.sh <handback report file>
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
SRC="$OUT/src"
REP="$OUT/handback"

RPT="${1:-}"
if [ -z "$RPT" ]; then
  RPT=$(ls -1t "$REP"/handback-*.txt 2>/dev/null | head -1)
fi
[ -n "$RPT" ] && [ -f "$RPT" ] || { echo "!! no hand-back report; run mvrp-handback.sh first"; exit 1; }

# What verifying the caller looks like in decompiled first-party code.
CHECK='getCallingUid|getCallingPackage|getCallingPid|checkCallingPermission|enforceCallingPermission|checkCallingOrSelfPermission|enforceCallingOrSelfPermission|SecurityPolicy|checkSignatures|GoogleSignatureVerifier|isGooglePackage|PackageManager\.SIGNATURE_MATCH'

# class -> source file, following one level of extends the way the hand-back
# sweep does, so the two agree about where a component's code lives.
srcfile() {   # srcfile <pkg> <class>
  local pkg="$1" cls="$2" d="$SRC/$1/sources"
  local f="$d/${cls//.//}.java"
  [ -f "$f" ] && { printf '%s' "$f"; return 0; }
  return 1
}
supfile() {   # supfile <pkg> <file>
  local pkg="$1" f="$2" d="$SRC/$1/sources" sup supf
  sup=$(grep -ohE 'class [A-Za-z0-9_$]+ +extends +[A-Za-z0-9_.$]+' "$f" 2>/dev/null | head -1 | awk '{print $NF}')
  [ -n "${sup:-}" ] || return 1
  case "$sup" in
    *.*) supf="$d/${sup//.//}.java" ;;
    *)   supf="$(dirname "$f")/$sup.java"; [ -f "$supf" ] || supf="$d/defpackage/$sup.java" ;;
  esac
  [ -f "$supf" ] && { printf '%s' "$supf"; return 0; }
  return 1
}

verdict() {   # verdict <pkg> <class> -> CHECKED <what> | UNCHECKED | NOSRC
  local pkg="$1" cls="$2" f sup hits
  f=$(srcfile "$pkg" "$cls") || { echo "NOSRC"; return; }
  hits=$(grep -ohE "$CHECK" "$f" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ -z "$hits" ] && sup=$(supfile "$pkg" "$f"); then
    hits=$(grep -ohE "$CHECK" "$sup" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
    [ -n "$hits" ] && hits="$hits (via parent)"
  fi
  [ -n "$hits" ] && echo "CHECKED $hits" || echo "UNCHECKED"
}

# ---- controls: two components whose answer is already established ----
# CameraPreviewProvider checks getCallingPackage() in openFile and query and
# verifies the signature. LockProximityReceiver checks nothing — that is the
# whole of G-F003. If either comes out the other way, this tool is wrong and
# its verdicts on 173 unknown components are worthless.
HOME_PKG=com.google.android.apps.chromecast.app
POSV=$(verdict "$HOME_PKG" com.google.android.libraries.home.notifications.fable.CameraPreviewProvider)
NEGV=$(verdict "$HOME_PKG" com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver)
case "$POSV" in
  CHECKED*) ;;
  NOSRC)    echo "!! BROKEN: control source missing — is Google Home decompiled?"; exit 2 ;;
  *)        echo "!! BROKEN: CameraPreviewProvider read as $POSV; it does check the caller"; exit 2 ;;
esac
case "$NEGV" in
  UNCHECKED) ;;
  NOSRC)     echo "!! BROKEN: control source missing"; exit 2 ;;
  *)         echo "!! BROKEN: LockProximityReceiver read as $NEGV; it checks nothing"; exit 2 ;;
esac
echo "POSITIVE  CameraPreviewProvider -> $POSV"
echo "NEGATIVE  LockProximityReceiver -> $NEGV"

# ---- third control: a check that lives somewhere else ----
# AGSA's OneSearchSuggestService was taken apart earlier in this project. It
# enforces a first-party-only gRPC SecurityPolicy, but the policy is in gitv
# and gitp, not in the service class or its parent. Reading only those two
# files calls it unchecked, which is wrong in the direction that wastes the
# most time: it sends you to read a component that will refuse you.
AGSA=com.google.android.googlequicksearchbox
AGSAV=$(verdict "$AGSA" com.google.android.apps.search.googleapp.search.suggest.plugins.onesearch.server.OneSearchSuggestService)
case "$AGSAV" in
  CHECKED*) echo "POSITIVE  OneSearchSuggestService -> $AGSAV" ;;
  NOSRC)    echo "SKIPPED   OneSearchSuggestService (AGSA not decompiled)" ;;
  *)        echo "LIMIT     OneSearchSuggestService -> $AGSAV"
            echo "          That service is known to enforce a first-party-only gRPC"
            echo "          policy, in gitv/gitp rather than in its own class. So this"
            echo "          tool cannot see checks that live one reference away, and"
            echo "          every UNCHECKED below means only: no check in the component"
            echo "          class or its direct parent. Treat it as a reading order,"
            echo "          not as a verdict." ;;
esac
echo

echo "# caller-check triage of $(basename "$RPT")"
echo

CUR=""
UNC=0; CHK=0; NOS=0
while IFS= read -r line; do
  case "$line" in
    "== "*)
      CUR="${line#== }"; CUR="${CUR%% *}" ;;
    "   "*)
      [ -n "$CUR" ] || continue
      guard=$(printf '%s' "$line" | awk '{print $1}')
      kind=$(printf '%s' "$line" | awk '{print $2}')
      cls=$(printf '%s' "$line" | awk '{print $3}')
      case "$guard" in NONE|ORPHAN|NORMAL) ;; *) continue ;; esac
      [ -n "$cls" ] || continue
      v=$(verdict "$CUR" "$cls")
      case "$v" in
        UNCHECKED) UNC=$((UNC+1)); printf 'UNCHECKED  %-7s %-9s %s  %s\n' "$guard" "$kind" "$CUR" "$cls" ;;
        NOSRC)     NOS=$((NOS+1)) ;;
        *)         CHK=$((CHK+1)) ;;
      esac ;;
  esac
done < "$RPT"

echo
echo "== $UNC with no check in the component class or its parent, $CHK that check there, $NOS without source =="
cat <<'NOTE'

Only the unchecked are listed, and "unchecked" means only that the component
class and its direct parent contain no caller check. A gRPC endpoint keeps its
SecurityPolicy in another class entirely, so many of these will refuse you at
the first call. The list is a reading order, not a set of findings.

That is still not a finding. The next question is the one that cost a tier
last time: what does it hand over? Read the unchecked ones in this order —
whatever touches accounts, messages, backups or tokens first.
NOTE
