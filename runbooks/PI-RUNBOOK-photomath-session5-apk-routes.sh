#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session5: extract REAL API routes from the Android APK
# Portable: Termux (Android) preferred; also Linux/Pi if you supply an APK.
#
# session4 proved the web client is a static marketing site with NO API calls.
# The real client is the MOBILE app, which calls lapi/rapi/dpcapi.photomath.net
# with auth tokens. Static-mine the APK to recover: the API base URLs, the real
# route paths (object-id routes = IDOR/BOLA targets), GraphQL endpoints, and any
# embedded secrets (report-only). Then probe the REAL routes unauth to classify
# open(200) vs auth-walled(401/403 -> authenticated IDOR target).
#
# APK ACQUISITION (in order; first that works wins):
#   1. PMATH_APK=/path/to/base.apk   (you supply it)
#   2. pm path <pkg>  -> copy installed APK(s)  (Termux, no root needed usually)
#   3. best-effort download from a public mirror (may fail; then install the app
#      from Play Store and re-run — step 2 will pick it up)
#
# SAFETY: static analysis only; the only network to the target is a paced,
# read-only GET probe of discovered routes. NEVER use any secret found. No fuzzing.
#
# Run (Termux): pkg install -y unzip >/dev/null 2>&1; mkdir -p $HOME/pm5
#   OUTDIR=$HOME/pm5 bash runbooks/PI-RUNBOOK-photomath-session5-apk-routes.sh \
#     2>&1 | tee $HOME/pm5/pm5.log
#   (optional: PKG=com.microblink.photomath  or  PMATH_APK=/sdcard/Download/photomath.apk)
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/pm5
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/pm5"
  else OUTDIR="$HOME/pm5"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR/apk" "$OUTDIR/ex"
UA='Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'
PACE="${PACE:-0.35}"
echo "============================================================"
echo "PHOTOMATH APK ROUTE MINING  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Static APK analysis -> real route map. Read-only. Never use found secrets."
echo "============================================================"; echo ""

# ── 1: acquire APK ──
echo "═══ 1: ACQUIRE APK ═══"
: > "$OUTDIR/apks.list"
CANDPKGS="${PKG:-} com.microblink.photomath com.google.android.apps.photomath com.photomath.photomath"
if [ -n "${PMATH_APK:-}" ] && [ -f "$PMATH_APK" ]; then
  cp "$PMATH_APK" "$OUTDIR/apk/base.apk"; echo "$OUTDIR/apk/base.apk" >> "$OUTDIR/apks.list"
  echo "  using supplied PMATH_APK ($(wc -c < "$PMATH_APK") bytes)"
elif command -v pm >/dev/null 2>&1; then
  # find installed package
  FOUND=""
  for P in $CANDPKGS; do
    [ -z "$P" ] && continue
    if pm path "$P" >/dev/null 2>&1; then FOUND="$P"; break; fi
  done
  if [ -z "$FOUND" ]; then
    echo "  no candidate installed. packages matching 'photomath':"
    pm list packages 2>/dev/null | grep -i photomath | sed 's/^/    /' || echo "    (none)"
  else
    echo "  installed package: $FOUND"
    i=0
    pm path "$FOUND" 2>/dev/null | sed 's/^package://' | while read -r AP; do
      [ -z "$AP" ] && continue
      i=$((i+1)); dst="$OUTDIR/apk/split$i.apk"
      if cp "$AP" "$dst" 2>/dev/null; then echo "  copied $AP"; echo "$dst" >> "$OUTDIR/apks.list"
      else echo "  (cannot read $AP without root — try PMATH_APK= a downloaded copy)"; fi
    done
  fi
fi
is_zip(){ [ -s "$1" ] && [ "$(head -c2 "$1" 2>/dev/null)" = "PK" ]; }
if [ ! -s "$OUTDIR/apks.list" ]; then
  echo "  trying mirror downloads (apkpure direct, then xapk)..."
  for P in com.microblink.photomath com.google.android.apps.photomath; do
    # APKPure direct APK
    curl -s -L --max-time 180 -A "$UA" "https://d.apkpure.com/b/APK/$P?version=latest" \
         -o "$OUTDIR/apk/dl.bin" 2>/dev/null
    if is_zip "$OUTDIR/apk/dl.bin"; then
      mv "$OUTDIR/apk/dl.bin" "$OUTDIR/apk/dl.apk"
      echo "$OUTDIR/apk/dl.apk" >> "$OUTDIR/apks.list"
      echo "  apkpure APK ok: $P ($(wc -c < "$OUTDIR/apk/dl.apk") bytes)"; break
    fi
    # APKPure XAPK (split bundle, itself a zip)
    curl -s -L --max-time 180 -A "$UA" "https://d.apkpure.com/b/XAPK/$P?version=latest" \
         -o "$OUTDIR/apk/dl.bin" 2>/dev/null
    if is_zip "$OUTDIR/apk/dl.bin"; then
      mv "$OUTDIR/apk/dl.bin" "$OUTDIR/apk/dl.xapk"
      echo "$OUTDIR/apk/dl.xapk" >> "$OUTDIR/apks.list"
      echo "  apkpure XAPK ok: $P ($(wc -c < "$OUTDIR/apk/dl.xapk") bytes)"; break
    fi
    echo "  apkpure miss for $P (got $(wc -c < "$OUTDIR/apk/dl.bin" 2>/dev/null) bytes, not a zip)"
  done
fi
# drop any non-zip entries that slipped in
if [ -s "$OUTDIR/apks.list" ]; then
  : > "$OUTDIR/apks.valid"
  while read -r A; do is_zip "$A" && echo "$A" >> "$OUTDIR/apks.valid"; done < "$OUTDIR/apks.list"
  mv "$OUTDIR/apks.valid" "$OUTDIR/apks.list"
fi
if [ ! -s "$OUTDIR/apks.list" ]; then
  echo ""
  echo "  !! Could not auto-acquire the APK. Easiest fix:"
  echo "     1) Install Photomath from the Play Store on this device, then re-run."
  echo "     2) OR download an APK and re-run with PMATH_APK=/sdcard/Download/photomath.apk"
  echo ""
  exit 0
fi
echo ""

# ── 2: unzip + extract strings ──
echo "═══ 2: UNPACK + STRING-EXTRACT ═══"
while read -r A; do
  [ -z "$A" ] && continue
  [ "$(head -c2 "$A" 2>/dev/null)" = "PK" ] || { echo "  (not a zip, skipping: $A)"; continue; }
  d="$OUTDIR/ex/$(basename "$A")"; mkdir -p "$d"
  unzip -o -qq "$A" -d "$d" 2>/dev/null || echo "  (unzip failed: $A)"
  # XAPK / split bundle: unpack any nested .apk too
  find "$d" -maxdepth 2 -name '*.apk' 2>/dev/null | while read -r nested; do
    nd="$d/nested-$(basename "$nested" .apk)"; mkdir -p "$nd"
    unzip -o -qq "$nested" -d "$nd" 2>/dev/null || true
  done
done < "$OUTDIR/apks.list"
# concatenate text-ish content from dex/so/arsc/assets via grep -a (no binutils needed)
: > "$OUTDIR/strings.txt"
find "$OUTDIR/ex" -type f \( -name '*.dex' -o -name '*.so' -o -name '*.arsc' -o -name '*.json' \
    -o -name '*.xml' -o -name '*.js' -o -path '*/assets/*' \) -print 2>/dev/null \
  | while read -r f; do
      grep -aoE '[[:print:]]{4,}' "$f" 2>/dev/null >> "$OUTDIR/strings.txt" || true
    done
echo "  extracted $(wc -c < "$OUTDIR/strings.txt") bytes of printable strings"
echo ""

# ── 3: mine routes / hosts / base-urls / secrets ──
echo "═══ 3: ROUTE / HOST / SECRET MINING ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
s=open(os.path.join(O,"strings.txt"),encoding="utf-8",errors="replace").read()

hosts=sorted(set(re.findall(r'([a-z0-9][a-z0-9.-]*\.photomath\.(?:net|com|app))', s)))
fullurls=sorted(set(re.findall(r'https?://[a-z0-9.-]*photomath\.(?:net|com|app)/[A-Za-z0-9_./%{}:+-]{1,90}', s)))
# base url config keys
bases=sorted(set(re.findall(r'(?i)(?:BASE_URL|API_BASE|API_URL|BACKEND_URL|HOST_URL|ENDPOINT)["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']', s)))
# route templates (object-id routes = IDOR targets)
routes=sorted(set(re.findall(r'["\'`](/(?:v[0-9]|api|graphql|rest|users?|accounts?|me|profile|subscription[s]?|purchase[s]?|order[s]?|histor(?:y|ies)|solution[s]?|task[s]?|problem[s]?|book[s]?|content|device[s]?|session[s]?|token[s]?|payment[s]?)[A-Za-z0-9_./{}:%-]{0,70})["\'`]', s)))
gql=sorted(set(re.findall(r'https?://[a-z0-9.-]*photomath\.[a-z]+/[a-z0-9/_-]*graphql[a-z0-9/_-]*', s, re.I)))
idroutes=[r for r in routes if re.search(r'\{[^}]+\}|/%[ds]|/:[A-Za-z]|/[0-9]+(?:/|$)', r)]

secrets=[]
for name,pat in [("AWS akid",r'AKIA[0-9A-Z]{16}'),
                 ("Google API key",r'AIza[0-9A-Za-z_\-]{35}'),
                 ("GCP oauth client",r'[0-9]{10,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com'),
                 ("Firebase db",r'https://[a-z0-9-]+\.firebaseio\.com'),
                 ("Stripe pk",r'pk_(?:live|test)_[0-9A-Za-z]{16,}'),
                 ("Stripe sk",r'sk_live_[0-9A-Za-z]{16,}'),
                 ("Slack",r'xox[baprs]-[0-9A-Za-z-]{10,}'),
                 ("Bearer/secret kv",r'(?i)(secret|api[_-]?key|client[_-]?secret|access[_-]?token|password)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{12,})["\']')]:
    for m in re.finditer(pat,s):
        secrets.append((name,m.group(0)[:80]))

def dump(title, items, lim=80):
    print(f"  {title} ({len(items)}):")
    for x in items[:lim]: print("    "+x)
    print()

dump("API HOSTNAMES", hosts)
dump("BASE-URL CONFIG", bases)
dump("FULL API URLS", fullurls, 80)
print(f"  *** OBJECT-ID ROUTES (IDOR/BOLA candidates) ({len(idroutes)}):")
for r in idroutes[:80]: print("    "+r)
print()
dump("OTHER ROUTE PATHS", [r for r in routes if r not in idroutes], 80)
if gql: dump("GRAPHQL ENDPOINTS", sorted(set(gql)))
seen=set(); sx=[(n,v) for (n,v) in secrets if (n,v) not in seen and not seen.add((n,v))]
if sx:
    print(f"  EMBEDDED SECRETS (report-only, NEVER use) ({len(sx)}):")
    for n,v in sx[:40]: print(f"    [{n}] {v}")
    print()
# queue probe list: full urls + base+idroute combos
probe=set(fullurls)
import urllib.parse as up
for b in bases:
    for r in idroutes+routes:
        probe.add(b.rstrip('/')+r)
open(os.path.join(O,"probe.txt"),"w").write("\n".join(sorted(probe)))
print(f"  -> {len(probe)} real routes queued for unauth probe")
PYEOF
echo ""

# ── 4: probe REAL discovered routes unauth ──
echo "═══ 4: PROBE REAL ROUTES (unauth GET) ═══"
if [ -s "$OUTDIR/probe.txt" ]; then
  n=0
  while read -r U; do
    [ -z "$U" ] && continue
    case "$U" in http*) : ;; *) continue;; esac
    n=$((n+1)); [ "$n" -gt "${MAXPROBE:-120}" ] && { echo "  (capped at $MAXPROBE)"; break; }
    PU=$(printf '%s' "$U" | sed -E 's/\{[^}]+\}/1/g; s/%[ds]/1/g; s#/:[A-Za-z_]+#/1#g')
    m=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" \
         -o "$OUTDIR/pb.tmp" -w '%{http_code}|%{content_type}|%{size_download}' "$PU" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    case "$code" in
      404|000) : ;;
      *) snip=$(head -c 160 "$OUTDIR/pb.tmp" 2>/dev/null | tr '\n\r' '  ')
         f=""; case "$code" in 200) f="[OPEN!]";; 401|403) f="[auth-walled -> IDOR target]";; 405) f="[exists/method]";; esac
         echo "  [$code] $PU  $f"
         echo "    ct=${ct%%;*} size=$size :: ${snip:0:110}"
         echo "$code|$PU" >> "$OUTDIR/route-hits.txt";;
    esac
    sleep "$PACE"
  done < "$OUTDIR/probe.txt"
fi
echo ""
echo "════════════════════════════════════════════"
echo "READ-BACK / NEXT"
echo "════════════════════════════════════════════"
echo "  * [OPEN!] 200 returning real data unauth = finding (verify, minimize, report)."
echo "  * [auth-walled] 401/403 on an object-id route = the IDOR/BOLA target. Next:"
echo "    register a free Photomath test account, capture the bearer token (app login"
echo "    or the in-app web flow), then request another object id and check for"
echo "    cross-account read. ALL with our own test accounts — no real-user data."
echo "  * BASE-URL CONFIG + OBJECT-ID ROUTES above ARE the map for that test."
echo ""
echo "Evidence: $OUTDIR  (strings.txt, probe.txt, route-hits.txt; secrets report-only)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
