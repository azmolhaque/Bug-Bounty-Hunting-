#!/usr/bin/env bash
# build.sh — builds the attacker APK and the control APK.
#
# Both come from the same source tree and the same res/ tree; the only
# difference is the manifest, and the only difference between the manifests is
# the orphaned permission. That is what makes the pair of runs a measurement
# rather than an anecdote.
#
#   ./build.sh            # attacker   -> out/attacker/com.cindrasec.wallpaperpoc.apk
#   ./build.sh control    # control    -> out/control/com.cindrasec.wallpaperctl.apk
#   ./build.sh both
#
# Toolchain and its ARM64 quirks live in ../mvrp-probe/build.sh; this is a thin
# wrapper so there is one builder to fix when a tool moves.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILDER="$HERE/../mvrp-probe/build.sh"
[ -x "$BUILDER" ] || { echo "!! builder missing: $BUILDER"; exit 1; }

one() {   # one <variant> <manifest> <package>
  local variant="$1" manifest="$2" pkg="$3"
  echo
  echo "=== $variant ==="
  MANIFEST="$HERE/$manifest" \
  SRC="$HERE/src" \
  RES="$HERE/res" \
  OUT="$HERE/out/$variant" \
  PKG="$pkg" \
  "$BUILDER"
}

case "${1:-attacker}" in
  attacker) one attacker AndroidManifest.xml         com.cindrasec.wallpaperpoc ;;
  control)  one control  AndroidManifest.control.xml com.cindrasec.wallpaperctl ;;
  both)     one attacker AndroidManifest.xml         com.cindrasec.wallpaperpoc
            one control  AndroidManifest.control.xml com.cindrasec.wallpaperctl ;;
  *) echo "usage: $0 [attacker|control|both]"; exit 1 ;;
esac
