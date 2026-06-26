#!/usr/bin/env bash
# =============================================================================
# M024 — SAP origin reachability re-check (settle S22 vs S27 contradiction)
# Portable: Linux / Pi / Termux.
#
# S22 (2026-06-24): /sap/opu/odata/  /sap/bc/  ZMM_HOTEL_SRV  -> 404/35B (claimed
#   SAP ORIGIN 404 reachable past Akamai).
# S27 (2026-06-26): every /sap/* SUB-path -> 404/261B (Akamai generic 404).
# But S27 never re-tested the EXACT S22 paths (bare namespace roots + the real
# Marriott service name). This run does — byte-exact, with the `Server` header
# captured, which is the unambiguous origin-vs-Akamai discriminator:
#   Akamai block  -> Server: AkamaiGHost / AkamaiNetStorage, or x-cache present
#   SAP origin    -> Server: SAP NetWeaver Application Server / ICM, or sap-* hdrs
#
# SAFETY: IN-SCOPE (gateway*.marriott.com). Read-only. No redirects followed
# (avoids OOS IdP). Method tampering uses only safe verbs (no PUT/DELETE bodies).
# X-Bug-Bounty identifying header. Conservative pacing.
#
# Run (Termux): OUTDIR=$HOME/s28 bash runbooks/PI-RUNBOOK-session28-sap-origin-recheck.sh \
#                 2>&1 | tee $HOME/s28/s28.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s28
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s28"
  else OUTDIR="$HOME/s28"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

HOST="gatewaydsapuat2.marriott.com"
BASE="https://$HOST"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'

echo "============================================================"
echo "M024 SAP ORIGIN RE-CHECK  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Host: $HOST   IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# probe METHOD PATH TAG  -> prints code/size + Server + x-cache; saves body+hdr.
# Metric format uses only numeric fields (space-safe). content_type/server read
# from the captured header file (robust against spaces/empties).
probe() {
  local method="$1" path="$2" tag="$3"
  local out="$OUTDIR/$tag.txt" hdr="$OUTDIR/$tag.hdr" m
  m=$(curl -s -X "$method" -o "$out" -D "$hdr" \
        -H "User-Agent: $UA" -H "$IDH" -H 'Accept: application/json' \
        --max-time 15 \
        -w '%{http_code} %{size_download}' \
        "$BASE$path" 2>/dev/null) || m="000 0"
  local code="${m% *}" size="${m#* }"
  local server xcache via sap
  server=$(grep -i '^server:'   "$hdr" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2- || true)
  xcache=$(grep -i '^x-cache:'  "$hdr" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2- || true)
  via=$(grep -i '^via:'         "$hdr" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2- || true)
  sap=$(grep -iE '^(sap-|x-sap-)' "$hdr" 2>/dev/null | head -1 | tr -d '\r' || true)
  printf '  [%-3s %6sB] %-6s %-44s\n' "$code" "$size" "$method" "$path"
  printf '         Server=%-28s x-cache=%-10s\n' "${server:-(none)}" "${xcache:-(none)}"
  [ -n "$via" ] && printf '         Via=%s\n' "$via"
  [ -n "$sap" ] && printf '         SAP-HDR=%s   <-- ORIGIN SIGNAL\n' "$sap"
  echo "$code $size" > "$OUTDIR/$tag.meta"
  sleep 0.5
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 1: EXACT S22 DIFFERENTIAL PATHS (the 35B claim) ═══"
probe GET "/sap/opu/odata/"                       p1-odata-root
probe GET "/sap/bc/"                              p1-bc-root
probe GET "/sap/opu/odata/sap/ZMM_HOTEL_SRV"      p1-zmmhotel
probe GET "/sap/opu/odata/sap/ZMM_HOTEL_SRV/"     p1-zmmhotel-sl
probe GET "/sap/opu/odata/sap/ZMM_HOTEL_SRV/\$metadata" p1-zmmhotel-meta
probe GET "/sap/"                                 p1-sap-root
echo ""

echo "═══ PHASE 2: METHOD TAMPERING (root returned 405 on GET) ═══"
for M in GET HEAD POST OPTIONS PUT; do
  probe "$M" "/" "p2-root-$M"
done
echo "  (OPTIONS may reveal Allow: header; POST/PUT may reach a different handler)"
probe OPTIONS "/sap/opu/odata/"                   p2-odata-opt
echo ""

echo "═══ PHASE 3: ORIGIN-vs-AKAMAI VERDICT ═══"
python3 - << 'PYEOF'
import os, glob, re
O = os.environ["OUTDIR"]
def hdrs(tag):
    p = os.path.join(O, tag+".hdr")
    return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""
def meta(tag):
    p = os.path.join(O, tag+".meta")
    return open(p).read().split() if os.path.exists(p) else ["---","0"]

origin_signals, akamai_signals = [], []
for hdr in glob.glob(os.path.join(O, "*.hdr")):
    tag = os.path.basename(hdr)[:-4]
    h = open(hdr, encoding="utf-8", errors="replace").read().lower()
    if re.search(r'server:\s*(sap|icm|netweaver)', h) or re.search(r'\nsap-\w', h) or 'sap-system' in h:
        origin_signals.append(tag)
    if 'akamaighost' in h or 'akamainetstorage' in h or 'x-cache:' in h or 'edgesuite' in h:
        akamai_signals.append(tag)

print("Paths with SAP ORIGIN header signals :", origin_signals or "NONE")
print("Paths with Akamai signals            :", akamai_signals or "NONE")
print()
# Size landscape
sizes = {}
for m in glob.glob(os.path.join(O, "*.meta")):
    tag = os.path.basename(m)[:-5]
    c, s = open(m).read().split()
    sizes.setdefault((c, s), []).append(tag)
print("Response (code,size) clusters:")
for (c, s), tags in sorted(sizes.items(), key=lambda x: -len(x[1])):
    print(f"  {c}/{s}B  x{len(tags):2d}  e.g. {tags[0]}")
print()
if origin_signals:
    print(">>> SAP ORIGIN IS REACHABLE on the paths above — PURSUE: enumerate")
    print(">>> services/$metadata on the reachable path pattern (build session29).")
else:
    print(">>> NO origin signal on any path. Host is fully Akamai-fronted from this")
    print(">>> network position (same class as gatewaydsapdev2/M023 dead-ends).")
    print(">>> The S22 '35B' was almost certainly a transient Akamai 404 variant,")
    print(">>> not SAP origin. RECOMMEND: pivot target — M024 is WAF-locked here.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
