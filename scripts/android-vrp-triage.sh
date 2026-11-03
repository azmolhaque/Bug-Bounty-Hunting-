#!/usr/bin/env bash
# android-vrp-triage.sh — fast scenario-3 triage of a Google Mobile VRP app.
#
# Philosophy (CLAUDE.md §6): automate breadth, manualize depth. This script
# pulls + decompiles an app and RANKS its exported attack surface so you spend
# manual time only on the components that could actually hold a finding. It does
# NOT decide anything — every HOT hit still needs a human to trace it to the
# caller/permission check. A HOT hit is a hypothesis, not a bug.
#
# Scope model: Google Mobile VRP, attacker = scenario 3 (malicious app on device).
# Qualifying classes it looks for: exported-component data theft, intent
# redirection, unsafe (mutable) PendingIntent, FileProvider path traversal.
#
# Usage:
#   ./scripts/android-vrp-triage.sh <package> [outdir]
#   ./scripts/android-vrp-triage.sh --batch pkgs.txt      # triage many, cross-rank
#
# Needs on the hunting box (the Pi): adb (device connected + authorized),
# apktool, jadx on PATH. Pulls only; never writes to the device.
set -uo pipefail

# ------------------------------------------------------------------ kill list
# Packages/prefixes that are NOT Mobile VRP (route elsewhere). Flagged, not run.
is_out_of_scope() {
  case "$1" in
    com.google.android.gms|com.google.android.gsf) return 1 ;;   # GMS *is* Tier1
    com.android.*|com.google.android.providers.*|\
    com.google.android.permissioncontroller|com.google.android.documentsui|\
    com.google.android.networkstack*|com.google.android.ext.*|\
    com.google.android.modulemetadata|com.google.android.healthconnect.controller)
      return 0 ;;   # AOSP / platform module -> Android & Google Devices SRP
    com.android.chrome|com.google.android.webview) return 0 ;;    # Chrome VRP
    *) return 1 ;;
  esac
}

HOT() { printf '\033[1;31m%s\033[0m\n' "$*"; }
WARM(){ printf '\033[1;33m%s\033[0m\n' "$*"; }
COLD(){ printf '\033[0;36m%s\033[0m\n' "$*"; }

triage_one() {
  local PKG="$1" OUT="${2:-$HOME/gapps/$1}"
  command -v adb >/dev/null   || { echo "!! adb not found"; return 1; }
  command -v apktool >/dev/null || { echo "!! apktool not found"; return 1; }
  command -v jadx >/dev/null  || { echo "!! jadx not found"; return 1; }

  if is_out_of_scope "$PKG"; then
    echo "## $PKG — SKIP (kill_list: platform/Chrome -> different program)"; return 0
  fi

  echo "## ===================== $PKG ====================="
  mkdir -p "$OUT"; ( cd "$OUT"
    # 1) pull every split from the device
    adb shell pm path "$PKG" 2>/dev/null | sed 's/package://' | tr -d '\r' \
      | while read -r p; do adb pull "$p" . >/dev/null 2>&1; done
    [ -f base.apk ] || { echo "!! could not pull $PKG (installed? authorized?)"; exit 1; }

    # 2) decompile (idempotent: skip if already done)
    [ -d apktool-out ] || apktool d -f base.apk -o apktool-out >/dev/null 2>&1
    [ -d jadx-out ]    || JAVA_OPTS="-Xmx6g" jadx -d jadx-out base.apk >/dev/null 2>&1

    M=apktool-out/AndroidManifest.xml
    [ -f "$M" ] || { echo "!! apktool failed"; exit 1; }

    # 3) hygiene flags
    echo "--- hygiene ---"
    grep -oE 'allowBackup="[^"]*"|debuggable="[^"]*"|usesCleartextTraffic="[^"]*"' "$M" | sort -u | sed 's/^/  /'

    # 4) rank exported components. HOT = exported with NO android:permission on
    #    the element itself (the in-code check, if any, is all that guards it).
    echo "--- exported surface (HOT = no manifest permission) ---"
    awk '
      /<(activity|activity-alias|service|provider|receiver)[ >]/ {blk=$0; while(blk !~ /\/?>$/ && getline l){blk=blk" "l}
        if (blk ~ /exported="true"/){
          name=""; perm="no-perm"; kind="?"
          if (match(blk,/<([a-z-]+)/,k)) kind=k[1]
          if (match(blk,/android:name="([^"]+)"/,n)) name=n[1]
          if (blk ~ /android:permission="/) perm="guarded"
          hot="WARM"
          if (perm=="no-perm"){
            if (kind=="service" || kind=="provider") hot="HOT"
            else if (blk ~ /<intent-filter/ && blk ~ /android:scheme=/) hot="HOT"
            else hot="WARM"
          } else hot="cold"
          # library noise -> cold
          if (name ~ /phenotype|tiktok\.(experiments|account)|androidx\.work|gms\.common|social\.licenses|appdoctor|profileinstaller/) hot="cold"
          printf "%s\t%s\t%s\t%s\n", hot, kind, perm, name
        }
      }' "$M" | sort | while IFS=$'\t' read -r hot kind perm name; do
        line="[$kind $perm] $name"
        case "$hot" in HOT) HOT "  HOT  $line";; WARM) WARM "  warm $line";; *) COLD "  cold $line";; esac
      done

    # 5) source-level sink patterns (scenario-3 qualifying classes)
    echo "--- sink patterns in app code (com/google/android/apps + the app pkg) ---"
    SRC=jadx-out/sources
    pkgpath="$(echo "$PKG" | tr '.' '/')"
    scan() { grep -rlE "$2" "$SRC/$pkgpath" 2>/dev/null | head -5 | sed "s|$SRC/||;s/^/      /"; }

    echo "  [intent redirection] getParcelableExtra(...Intent) -> startActivity:"
    scan x 'getParcelableExtra\([^)]*(EXTRA_INTENT|\.INTENT|Intent\.class)' || true
    grep -rlE 'startActivity\((\(Intent\))?[a-z]' "$SRC/$pkgpath" 2>/dev/null \
      | xargs -r grep -lE 'getParcelableExtra|getIntentExtra' 2>/dev/null | head -5 | sed "s|$SRC/||;s/^/      /" || true

    echo "  [mutable PendingIntent] FLAG_MUTABLE / getActivity w/o FLAG_IMMUTABLE:"
    scan x 'FLAG_MUTABLE' || true

    echo "  [FileProvider path traversal] custom getCanonicalPath/.. handling:"
    grep -rlE '\.\./|getCanonicalPath|decode\(.*path' "$SRC/$pkgpath" 2>/dev/null \
      | xargs -r grep -lE 'FileProvider|openFile|ParcelFileDescriptor' 2>/dev/null | head -5 | sed "s|$SRC/||;s/^/      /" || true

    echo "  [exported service — caller check present?] onBind + getCallingUid/signature:"
    grep -rlE 'onBind' "$SRC/$pkgpath" 2>/dev/null \
      | xargs -r grep -LE 'getCallingUid|getCallingPackage|checkCallingPermission|SecurityPolicy|signature|kcj\.' 2>/dev/null \
      | head -8 | sed "s|$SRC/||;s/^/      (no visible caller check) /" || true

    echo "  [WebView bridge] addJavascriptInterface + loadUrl from intent:"
    grep -rlE 'addJavascriptInterface' "$SRC/$pkgpath" 2>/dev/null \
      | xargs -r grep -lE 'getIntent|getData\(\)|getStringExtra' 2>/dev/null | head -5 | sed "s|$SRC/||;s/^/      /" || true

    echo "--- next: manually trace each HOT + flagged file to its caller/permission check ---"
  )
}

if [ "${1:-}" = "--batch" ]; then
  LIST="${2:?usage: --batch <file-with-one-package-per-line>}"
  while read -r pkg; do [ -n "$pkg" ] && triage_one "$pkg"; done < "$LIST"
else
  triage_one "${1:?usage: android-vrp-triage.sh <package> [outdir]}" "${2:-}"
fi
