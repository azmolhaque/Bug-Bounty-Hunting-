#!/usr/bin/env bash
# mvrp-manifest-gaps.sh — the parts of a manifest the orphan sweep never read.
#
# Why, in payout terms. G-F004 is an "other" finding: Tier 2 tops out at
# $2,250 because what the attacker gets is a capability, not data. The theft
# column is twice that, and Tier 1 theft is four times. The only honest way to
# reach it is to find a component that returns somebody's data, reachable the
# same way — so this looks where data lives, which is providers, and at the
# three guard constructs the orphan sweep does not parse:
#
#   1. <path-permission>        A provider can be properly guarded at the top
#                               and wide open on one path, or the reverse. This
#                               is the classic place a read guard goes missing,
#                               and mvrp-orphan.sh reads neither.
#   2. <application android:permission>
#                               Applies to every component that does not set
#                               its own. A component with no permission
#                               attribute can still be guarded here — and a
#                               component that looked guarded in the sweep may
#                               be guarded by nothing but this.
#   3. exported providers with no guard at all
#                               They never appear in an orphan list, because
#                               there is no guard to be orphaned.
#
# Everything printed is a lead, not a finding. A provider you can query is a
# precondition (CLAUDE.md 2.6); the finding is the row of someone else's data
# that comes back.
#
# Usage:
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-manifest-gaps.sh
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-manifest-gaps.sh com.google.android.gms
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"
REP="$OUT/gaps"; mkdir -p "$REP"
LOG="$REP/gaps-$(date +%Y%m%d-%H%M).txt"
SELF_RE="${MVRP_SELF_RE:-^com\.cindrasec\.}"

command -v adb >/dev/null || { echo "!! adb missing"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! no device (set ANDROID_SERIAL)"; exit 1; }
[ -d "$DEC" ] || { echo "!! no decoded manifests at $DEC — run mvrp-surface.sh first"; exit 1; }

# ---- the device's permission set, so "undefined" means something ----
DEFSET="$REP/defined-names.txt"
adb shell pm list permissions -g 2>/dev/null </dev/null | tr -d '\r' \
  | sed -n 's/^[[:space:]]*permission:\(.*\)$/\1/p' | sort -u > "$DEFSET"
LVL="$REP/levels.txt"
adb shell pm list permissions -g -f 2>/dev/null </dev/null | tr -d '\r' | awk '
  /^[[:space:]]*[+]?[[:space:]]*group:/ { p=""; next }
  /permission:/      { p=$0; sub(/^.*permission:/,"",p); next }
  /protectionLevel:/ { if (p!="") { l=$0; sub(/^.*protectionLevel:/,"",l); print p"\t"l } }
' | sort -u > "$LVL"

NDEF=$(grep -c . "$DEFSET" || true)

{
echo "# manifest gap sweep — path-permission, application-level guards, open providers"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "# serial : $(adb get-serialno 2>/dev/null | tr -d '\r')"
echo "# source : $OUT"
echo

echo "== CONTROL =="
if [ "$NDEF" -lt 100 ]; then
  echo "!! BROKEN: only $NDEF permissions read from the device — pm list failed."
  echo "!!         Every name below would be called undefined."
  exit 2
fi
echo "POSITIVE  $NDEF permissions defined on this device"
for p in android.permission.INTERNET android.permission.READ_CONTACTS; do
  grep -qx "$p" "$DEFSET" || { echo "!! BROKEN: $p reads as undefined — parsing failed"; exit 2; }
done
echo "POSITIVE  known-defined names parse as defined"
echo

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')
echo "== reading ${#pkgs[@]} manifest(s) =="

NPATH=0; NAPP=0; NOPEN=0; NREAD=0
for pkg in "${pkgs[@]}"; do
  case "$pkg" in com.cindrasec.*) continue ;; esac
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue

  rows=$(python3 -I - "$m" <<'PY'
import sys, xml.etree.ElementTree as ET
AND = "http://schemas.android.com/apk/res/android"
def a(e, n, d=None): return e.get("{%s}%s" % (AND, n), d)

try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(0)
app = root.find("application")
if app is None:
    sys.exit(0)

own = {a(p, "name") for p in root.findall("permission")}
appperm = a(app, "permission")

def exported(el):
    e = a(el, "exported")
    if e is not None:
        return e == "true"
    # A provider with no exported attribute is not exported on any targetSdk
    # this sweep cares about; other components default to exported only when
    # they carry an intent-filter.
    return bool(el.findall("intent-filter")) and el.tag != "provider"

for el in app.findall("provider"):
    if not exported(el):
        continue
    name = a(el, "name") or "?"
    auth = a(el, "authorities") or "?"
    rp = a(el, "readPermission")
    wp = a(el, "writePermission")
    gp = a(el, "permission")
    grant = a(el, "grantUriPermissions")
    eff_read = rp or gp or appperm
    if eff_read is None:
        print("OPEN\t%s\t%s\t%s\t%s" % (name, auth, grant or "false", ""))
    else:
        src = "own" if (rp or gp) else "application"
        print("READ\t%s\t%s\t%s\t%s" % (name, auth, eff_read, src))
    if wp and wp not in own:
        print("WRITE\t%s\t%s\t%s\t%s" % (name, auth, wp, "own"))
    for pp in el.findall("path-permission"):
        path = (a(pp, "path") or a(pp, "pathPrefix") or a(pp, "pathPattern") or "?")
        for attr in ("readPermission", "writePermission", "permission"):
            v = a(pp, attr)
            if v is not None:
                print("PATH\t%s\t%s\t%s\t%s" % (name, path, v, attr))

# Components guarded only by the application-level permission: the sweep that
# reads component attributes sees nothing on these and calls them unguarded,
# or misses that the real guard is one level up.
if appperm:
    for k in ("activity", "activity-alias", "service", "receiver"):
        for el in app.findall(k):
            if not exported(el):
                continue
            if a(el, "permission") is None:
                print("APPGUARD\t%s\t%s\t%s\t%s" % (a(el, "name") or "?", k, appperm, ""))
PY
)
  [ -z "$rows" ] && continue

  printed=0
  while IFS=$'\t' read -r tag name extra perm src; do
    [ -z "$tag" ] && continue
    case "$tag" in
      OPEN)
        [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
        NOPEN=$((NOPEN+1))
        echo "  OPEN-PROVIDER  $name"
        echo "      authorities=$extra  grantUriPermissions=$perm"
        echo "      no read guard anywhere: component, nor application level"
        ;;
      READ|WRITE|PATH|APPGUARD)
        # Only interesting when the guard is weak or absent from the device.
        lvl=$(awk -F'\t' -v p="$perm" '$1==p{print $2}' "$LVL" | head -1)
        if ! grep -qxF "$perm" "$DEFSET"; then
          verdict="ORPHANED — nothing on this device defines it"
        elif printf '%s' "$lvl" | grep -q '^normal'; then
          verdict="WEAK — protectionLevel=$lvl, granted at install to anyone"
        else
          continue
        fi
        [ "$printed" -eq 0 ] && { echo; echo "== $pkg"; printed=1; }
        case "$tag" in
          READ)     NREAD=$((NREAD+1)); echo "  WEAK-READ      $name"; echo "      authorities=$extra  via=$src" ;;
          WRITE)    NREAD=$((NREAD+1)); echo "  WEAK-WRITE     $name"; echo "      authorities=$extra" ;;
          PATH)     NPATH=$((NPATH+1)); echo "  PATH-PERM      $name"; echo "      path=$extra  attr=$src" ;;
          APPGUARD) NAPP=$((NAPP+1));   echo "  APP-LEVEL      $name  [$extra]" ;;
        esac
        echo "      $perm"
        echo "      $verdict"
        ;;
    esac
  done <<< "$rows"
done

echo
echo "== summary =="
echo "exported providers with no read guard at all : $NOPEN"
echo "providers with a weak/orphaned read or write : $NREAD"
echo "path-permission entries, weak or orphaned    : $NPATH"
echo "components guarded only at application level : $NAPP"

cat <<'NOTE'

== what to do with these ==
A provider is the only thing on this list that can hand back somebody's data,
and data is the column that pays double. So for each one, in this order:

  adb shell content query --uri content://<authority>/            # does it answer
  adb shell content query --uri content://<authority>/<guess>

A SecurityException means the guard holds. An empty cursor means it answered
and had nothing — which is still reachability, not a finding. Rows containing
anything that belongs to the device's owner are the finding, and at that point
stop and write it down rather than enumerating further.

path-permission is worth reading by hand even when this prints nothing: a path
guard only applies to paths it matches, so a provider with a strong top-level
guard and a pathPrefix carrying a weaker one is open on that prefix only, and
the prefix is where to aim.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
