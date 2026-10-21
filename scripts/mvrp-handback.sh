#!/usr/bin/env bash
# mvrp-handback.sh — exported components that HAND SOMETHING BACK to the caller.
#
# Why this axis, and why only now:
#   G-F003 was logged for weeks as "two exported components are reachable".
#   That was measured and true and worth about nothing. What changed its tier
#   was a question never asked: once you reach it, what does it DO? The answer
#   for FirstDockActivity was that it takes an IntentSender out of the caller's
#   intent, fills it with the signed-in account, and fires it.
#
#   Reachability is a precondition. The hand-back is the finding. Every sweep
#   before this one measured the precondition.
#
# What it looks for, per component:
#   1. exported=true in the manifest
#   2. a guard that cannot keep anyone out:
#        NONE     - no android:permission at all
#        ORPHAN   - names a permission no installed package defines
#        NORMAL   - names a real permission at protectionLevel=normal, which
#                   any app can request and is granted without a prompt
#      (SIGNATURE and DANGEROUS guards are reported but not flagged: those
#       actually hold.)
#   3. the component's source contains a hand-back pattern:
#        android.intent.extra.INTENT, startIntentSenderForResult,
#        ResultReceiver, Messenger, PendingIntent read from the intent,
#        or setResult with extras.
#
# A hit is a lead, not a finding. The component has to be read: what goes into
# what it hands back decides whether there is anything there at all.
#
# Usage:
#   ./mvrp-handback.sh                      # every decompiled app
#   ./mvrp-handback.sh com.google.android.apps.cloudconsole
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"
SRC="$OUT/src"
MAP="$OUT/perms/device-permissions.txt"
REP="$OUT/handback"; mkdir -p "$REP"
LOG="$REP/handback-$(date +%Y%m%d-%H%M).txt"

# The fixture: a component whose answer is already known, because it is the one
# in the submitted report. If the sweep cannot find this, the sweep is broken
# and its silence on every other app means nothing.
FIX_PKG="${MVRP_FIX_PKG:-com.google.android.apps.chromecast.app}"
FIX_CLS="${MVRP_FIX_CLS:-FirstDockActivity}"

[ -d "$DEC" ] || { echo "!! no decoded manifests at $DEC"; exit 1; }
[ -d "$SRC" ] || { echo "!! no decompiled sources at $SRC"; exit 1; }
[ -s "$MAP" ] || { echo "!! no device permission map at $MAP (run mvrp-perms.sh)"; exit 1; }

# permission name -> protection level, from `pm list permissions -f -g`.
#
# Both shapes have to parse. Without -g the lines read "+ permission:NAME";
# with -g they are indented "permission:NAME" under a "group:" header. The
# map is built with -g because without it the grouped permissions — CAMERA,
# READ_CONTACTS, CALL_PHONE, ACCESS_COARSE_LOCATION — are simply absent, and
# every guard naming one of them reads as orphaned.
#
# Permissions declared by this researcher's own probe apps are skipped. They
# declare the very names under investigation, so leaving them in makes an
# orphaned guard look defined.
declare -A PROT
SELF_RE="${MVRP_SELF_RE:-^com\.cindrasec\.}"
cur=""; curpkg=""
while IFS= read -r line; do
  case "$line" in
    group:*) continue ;;
    *permission:*)
      cur="${line##*permission:}"; cur="${cur%% *}"; curpkg="" ;;
    *package:*)
      [ -n "$cur" ] && { curpkg="${line##*package:}"; curpkg="${curpkg%% *}"; } ;;
    *protectionLevel:*)
      if [ -n "$cur" ]; then
        case "$curpkg" in
          com.cindrasec.*) ;;
          *) PROT["$cur"]="${line##*protectionLevel:}" ;;
        esac
      fi
      cur=""; curpkg="" ;;
  esac
done < <(tr -d '\r' < "$MAP")

# ---- control 1: the permission map parsed into something usable ----
KNOWN=${#PROT[@]}
if [ "$KNOWN" -lt 200 ]; then
  echo "!! BROKEN: only $KNOWN permissions parsed from the map; expected hundreds"
  exit 2
fi
P_POS="${PROT[android.permission.CAMERA]:-}"
P_NEG="${PROT[com.canary.not.a.real.permission]:-}"
[ -n "$P_POS" ] || { echo "!! BROKEN: CAMERA not in the map, lookup is wrong"; exit 2; }
[ -z "$P_NEG" ] || { echo "!! BROKEN: an invented permission resolved, lookup is wrong"; exit 2; }

guard_class() {   # guard_class <permission name or empty>
  local p="$1"
  [ -z "$p" ] && { echo NONE; return; }
  local lvl="${PROT[$p]:-}"
  if [ -z "$lvl" ]; then echo ORPHAN; return; fi
  case "$lvl" in
    normal*)    echo NORMAL ;;
    dangerous*) echo DANGEROUS ;;
    *)          echo SIGNATURE ;;
  esac
}

# What "hands something back" means depends on the kind of component, and the
# first version only spoke activity. A service's hand-back is the binder it
# returns from onBind; a provider's is query/openFile/call. Searching every
# component for setResult and IntentSender missed, among others, the four
# normal-guarded services in Google Messages — which is the opposite of the
# point, since those are not orphan-guarded and so are not in the bucket the
# last report was closed into.
HB_COMMON='android\.intent\.extra\.INTENT|startIntentSenderForResult|IntentSender|ResultReceiver|android\.os\.Messenger'
HB_ACTIVITY="$HB_COMMON|setResult\s*\("
HB_RECEIVER="$HB_COMMON|setResultData|setResultExtras|getResultExtras"
HB_SERVICE="$HB_COMMON|IBinder +onBind|\.Stub\b|asBinder"
HB_PROVIDER="$HB_COMMON|public +[A-Za-z<>\[\] ]+ +(query|call|openFile|openAssetFile) *\("

handback_re() {   # handback_re <kind>
  case "$1" in
    service)            printf '%s' "$HB_SERVICE" ;;
    provider)           printf '%s' "$HB_PROVIDER" ;;
    receiver)           printf '%s' "$HB_RECEIVER" ;;
    *)                  printf '%s' "$HB_ACTIVITY" ;;
  esac
}

scan_pkg() {   # scan_pkg <pkg>  -> lines: GUARD<TAB>kind<TAB>component<TAB>hits
  local pkg="$1"
  local man="$DEC/$pkg/resources/AndroidManifest.xml"
  local srcdir="$SRC/$pkg/sources"
  # A missing manifest or missing sources is not "nothing found". Say which,
  # on stderr, so a zero in the report is a measured zero.
  [ -f "$man" ] || { echo "SKIP $pkg: no decoded manifest" >&2; return 0; }
  [ -d "$srcdir" ] || { echo "SKIP $pkg: not decompiled" >&2; return 0; }
  if [ "$(find "$srcdir" -name '*.java' -print -quit 2>/dev/null | grep -c . )" -eq 0 ]; then
    echo "SKIP $pkg: source tree exists but holds no java" >&2; return 0
  fi

  # Attributes sit on their own lines in these manifests, so collapse first and
  # take whole opening tags. Matching line by line finds nothing and says so
  # silently, which is how an earlier check "proved" there were no providers.
  tr '\n' ' ' < "$man" \
  | grep -oE '<(activity|activity-alias|receiver|service|provider)[^>]*>' \
  | while IFS= read -r tag; do
      case "$tag" in *'android:exported="true"'*) ;; *) continue ;; esac
      local name perm kind
      name=$(printf '%s' "$tag" | grep -oE 'android:name="[^"]*"' | head -1 | cut -d'"' -f2)
      perm=$(printf '%s' "$tag" | grep -oE 'android:permission="[^"]*"' | head -1 | cut -d'"' -f2)
      [ -n "$name" ] || continue
      kind=$(printf '%s' "$tag" | grep -oE '^<[a-z-]+' | tr -d '<')

      local g; g=$(guard_class "${perm:-}")
      case "$g" in NONE|ORPHAN|NORMAL) ;; *) continue ;; esac

      # class name -> source path. targetClass for an alias is elsewhere, so an
      # alias that resolves to nothing is skipped rather than guessed at.
      local rel="${name//.//}.java"
      local f="$srcdir/$rel"
      [ -f "$f" ] || continue

      local hits via re
      re=$(handback_re "$kind")
      hits=$(grep -ohE "$re" "$f" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
      via=""

      # Many exported classes are thin: the component declares nothing and its
      # superclass does the work. FirstDockActivity happened to hold its own
      # hand-back, so the first version of this only read the component file
      # and would have called a whole app clean on that basis. One level of
      # `extends` is followed — jadx puts obfuscated parents in defpackage/.
      if [ -z "$hits" ]; then
        local sup supf
        sup=$(grep -ohE 'class [A-Za-z0-9_$]+ +extends +[A-Za-z0-9_.$]+' "$f" 2>/dev/null \
              | head -1 | awk '{print $NF}')
        if [ -n "${sup:-}" ]; then
          case "$sup" in
            *.*) supf="$srcdir/${sup//.//}.java" ;;
            *)   supf="$(dirname "$f")/$sup.java"
                 [ -f "$supf" ] || supf="$srcdir/defpackage/$sup.java" ;;
          esac
          if [ -f "$supf" ]; then
            hits=$(grep -ohE "$re" "$supf" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
            [ -n "$hits" ] && via=" (via $sup)"
          fi
        fi
      fi

      [ -n "$hits" ] || continue
      printf '%s\t%s\t%s\t%s%s\n' "$g" "$kind" "$name" "$hits" "$via"
    done
}

PKGS=()
if [ $# -gt 0 ]; then PKGS=("$@"); else
  while IFS= read -r d; do PKGS+=("$(basename "$d")"); done < <(find "$DEC" -mindepth 1 -maxdepth 1 -type d | sort)
fi

{
echo "# hand-back sweep — exported, weakly guarded, and gives the caller something"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# apps   : ${#PKGS[@]}"
echo "# perms  : $KNOWN known on this device"
echo

# ---- control 2: the known answer ----
# FirstDockActivity is guarded by an orphaned permission and hands over an
# IntentSender. If it does not come out of the sweep, nothing else that does
# not come out means anything either.
FIXOUT=$(scan_pkg "$FIX_PKG" | grep -F "$FIX_CLS" || true)
if [ -z "$FIXOUT" ]; then
  echo "!! BROKEN: the fixture $FIX_CLS was not flagged."
  echo "!!         That component is known to match, so the sweep is not working."
  echo "!!         Every empty result below would be meaningless. Stopping."
  exit 2
fi
echo "POSITIVE  fixture found:"
printf '%s\n' "$FIXOUT" | sed 's/^/          /'
echo

TOTAL=0
SKIPS="$REP/.skips.$$"; : > "$SKIPS"
for p in "${PKGS[@]}"; do
  out=$(scan_pkg "$p" 2>>"$SKIPS")
  n=$(printf '%s' "$out" | grep -c . || true)
  [ "$n" -eq 0 ] && continue
  TOTAL=$((TOTAL+n))
  echo "== $p  ($n)"
  printf '%s\n' "$out" | sort | sed 's/^/   /'
  echo
done

echo "== total: $TOTAL components across ${#PKGS[@]} apps =="
NSKIP=$(grep -c . "$SKIPS" || true)
if [ "$NSKIP" -gt 0 ]; then
  echo
  echo "== $NSKIP app(s) could not be looked at — their zero means nothing =="
  sed 's/^/   /' "$SKIPS"
fi
rm -f "$SKIPS"
cat <<'NOTE'

== what to do with this ==
Each line is a component that any app can reach and that hands the caller
something back. That is where the finding was last time, but the line itself
is not a finding: read what the component puts into what it hands over.

Order of attention:
  1. ORPHAN guards in Tier 1 apps (Play Services, AGSA, Google Cloud, Gmail)
  2. NORMAL guards anywhere — a normal-level permission is not a guard, any
     app is granted it at install with no prompt
  3. NONE in anything that touches accounts, tokens or another app's data

Read the component before believing the line. Last time the answer was an
account; most of the time it will be nothing.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
