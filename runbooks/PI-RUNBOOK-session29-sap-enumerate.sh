#!/usr/bin/env bash
# =============================================================================
# M024 — SAP origin confirmed reachable; enumerate the surface (session29)
# Portable: Linux / Pi / Termux.
#
# S28 result: GET /sap/* -> 404/35B with NO Akamai markers (Server/x-cache/
# edgesuite all absent) = SAP ORIGIN reachable past Akamai. POST/PUT root ->
# AkamaiGHost (edge rejects verbs). Some /sap/* sub-paths returned 261B (Akamai)
# in S27 — the suspected variable is the `Accept: application/json` header.
#
# This run:
#   A. Confirm 35B is SAP (print the body — SAP ICM/Gateway 404 signature).
#   B. ISOLATE the 261B-vs-35B variable: same path, Accept on vs off.
#   C. OData service catalog without the ';v=2' matrix param (that triggers an
#      Akamai 403); multiple catalog forms.
#   D. Curated SAP OData service existence scan — flag anything NOT 404/35B
#      (401=exists+auth, 200=open data, 403/500=exists). ~55 names, paced — well
#      under any rate policy, NOT mass fuzzing.
#   E. SAP standard info/ICF endpoints with Accept header.
#
# SAFETY: IN-SCOPE (gateway*.marriott.com). Read-only GET. No redirects. No
# writes. X-Bug-Bounty header. 0.5s pacing.
#
# Run (Termux): OUTDIR=$HOME/s29 bash runbooks/PI-RUNBOOK-session29-sap-enumerate.sh \
#                 2>&1 | tee $HOME/s29/s29.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s29
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s29"
  else OUTDIR="$HOME/s29"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

HOST="gatewaydsapuat2.marriott.com"
BASE="https://$HOST"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'

echo "============================================================"
echo "M024 SAP ENUMERATE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Host: $HOST   IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# probe PATH TAG [ACCEPT]  — ACCEPT defaults to application/json; pass "none" to omit
probe() {
  local path="$1" tag="$2" accept="${3:-application/json}"
  local out="$OUTDIR/$tag.txt" hdr="$OUTDIR/$tag.hdr" m hdrs=()
  hdrs=(-H "User-Agent: $UA" -H "$IDH")
  [ "$accept" != "none" ] && hdrs+=(-H "Accept: $accept")
  m=$(curl -s -o "$out" -D "$hdr" "${hdrs[@]}" --max-time 15 \
        -w '%{http_code} %{size_download}' "$BASE$path" 2>/dev/null) || m="000 0"
  local code="${m% *}" size="${m#* }"
  local server xcache
  server=$(grep -i '^server:'  "$hdr" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2- || true)
  xcache=$(grep -i '^x-cache:' "$hdr" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2- || true)
  echo "$code $size" > "$OUTDIR/$tag.meta"
  # Mark anything that is NOT the origin 404/35B and NOT Akamai 261B
  local mark=""
  if [ "$code" != "404" ]; then mark=" *** $code ***"; fi
  printf '  [%-3s %6sB] %-50s%s\n' "$code" "$size" "$path" "$mark"
  [ -n "$server" ] && printf '         Server=%s\n' "$server"
  sleep 0.5
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: CONFIRM 35B IS SAP ORIGIN (print body + headers) ═══"
probe "/sap/opu/odata/" a-odataroot
echo "  --- /sap/opu/odata/ body (verbatim) ---"
cat "$OUTDIR/a-odataroot.txt"; echo
echo "  --- /sap/opu/odata/ response headers ---"
cat "$OUTDIR/a-odataroot.hdr" 2>/dev/null | tr -d '\r'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: ISOLATE 261B-vs-35B VARIABLE (Accept header) ═══"
echo "Same path, Accept on vs off:"
probe "/sap/opu/odata/sap/GWSAMPLE_BASIC/"       b-gw-json  application/json
probe "/sap/opu/odata/sap/GWSAMPLE_BASIC/"       b-gw-none  none
probe "/sap/opu/odata/sap/GWSAMPLE_BASIC/\$metadata" b-gwmeta-json application/json
probe "/sap/opu/odata/sap/GWSAMPLE_BASIC/\$metadata" b-gwmeta-none none
echo ""
echo "[B verdict]:"
python3 - << 'PYEOF'
import os
O=os.environ["OUTDIR"]
def m(t):
    p=os.path.join(O,t+".meta"); return open(p).read().split() if os.path.exists(p) else ["-","-"]
for label,t in [("GW root  Accept:json","b-gw-json"),("GW root  no Accept","b-gw-none"),
                ("GW meta  Accept:json","b-gwmeta-json"),("GW meta  no Accept","b-gwmeta-none")]:
    c,s=m(t); print(f"  {label:24s}: {c}/{s}B")
print("  -> if 'Accept:json'=35B and 'no Accept'=261B, the header reaches origin.")
print("  -> if both 261B, the variable is the path/service, not Accept.")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: ODATA SERVICE CATALOG (no ';v=2' — avoids Akamai 403) ═══"
probe "/sap/opu/odata/IWFND/CATALOGSERVICE/ServiceCollection?\$format=json" c-cat-svc
probe "/sap/opu/odata/IWFND/CATALOGSERVICE/"                                c-cat-root
probe "/sap/opu/odata/iwfnd/catalogservice/ServiceCollection?\$format=json" c-cat-lc
probe "/sap/opu/odata4/iwfnd/config/default/iwfnd/catalog/0002/ServiceGroups?\$format=json" c-cat4
probe "/sap/opu/odata/IWFND/CATALOGSERVICE/Annotations?\$format=json"       c-cat-anno
echo ""
echo "  [C] catalog body (first 600B if any returned non-404):"
for t in c-cat-svc c-cat-root c-cat-lc c-cat4; do
  read -r code _ < "$OUTDIR/$t.meta"
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "  --- $t (HTTP $code) ---"; head -c 600 "$OUTDIR/$t.txt"; echo
  fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE D: SAP ODATA SERVICE EXISTENCE SCAN (flag non-404) ═══"
echo "401/200/403/500 = service EXISTS; 404/35B = not present. Curated list."
SERVICES="
GWSAMPLE_BASIC ZGWSAMPLE_BASIC ZMM_HOTEL_SRV ZMM_HOTEL ZHOTEL_SRV ZHOTELSRV
ZPROPERTY_SRV ZPROPERTYMASTER_SRV ZRATE_SRV ZRATES_SRV ZRESERVATION_SRV
ZGUEST_SRV ZCUSTOMER_SRV ZPARTNER_SRV ZVENDOR_SRV ZSUPPLIER_SRV ZINVOICE_SRV
ZPAYMENT_SRV ZPO_SRV ZPURCHASE_SRV ZFI_SRV ZCO_SRV ZSD_SRV ZMM_SRV ZHR_SRV
ZHCM_SRV ZEMPLOYEE_SRV ZUSER_SRV ZAUTH_SRV ZLOGIN_SRV API_BUSINESS_PARTNER
API_PRODUCT_SRV API_SALES_ORDER_SRV API_PURCHASEORDER_PROCESS_SRV
ZMARRIOTT_SRV ZMAR_SRV ZMI_SRV ZBONVOY_SRV ZLOYALTY_SRV ZBOOKING_SRV
ZFRANCHISE_SRV ZOWNER_SRV ZCOMMISSION_SRV ZTAX_SRV ZGL_SRV ZAP_SRV ZAR_SRV
CATALOGSERVICE PAGE_BUILDER_PERS PAGE_BUILDER_CONF INTEROP TASKPROCESSING
ZUI5_SRV ZFIORI_SRV ZWORKFLOW_SRV ZBANK_SRV ZTREASURY_SRV
"
i=0
for S in $SERVICES; do
  i=$((i+1))
  probe "/sap/opu/odata/sap/$S/" "d-$(printf '%02d' $i)-$S"
done
echo ""
echo "[D] services that EXIST (non-404 response):"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]; hits=[]
for f in sorted(glob.glob(os.path.join(O,"d-*.meta"))):
    c,s=open(f).read().split()
    if c not in ("404","000"):
        name=os.path.basename(f)[:-5].split("-",2)[-1]
        hits.append((name,c,s))
if hits:
    for n,c,s in hits: print(f"  *** {n}: HTTP {c} ({s}B)")
    print(f"\n  {len(hits)} candidate service(s) exist — probe $metadata + entity sets next.")
else:
    print("  none — all probed services returned origin 404/35B (not published, or")
    print("  unauth blocked at SAP ICF with a 404). Catalog is the path; see Phase C.")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE E: SAP INFO / ICF ENDPOINTS (with Accept) ═══"
probe "/sap/public/info"                      e-info        none
probe "/sap/public/info"                      e-info-json   application/json
probe "/sap/bc/ping"                          e-ping
probe "/sap/opu/odata/sap/"                   e-odatasap
probe "/sap/opu/"                             e-opu
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
clusters={}
for f in glob.glob(os.path.join(O,"*.meta")):
    c,s=open(f).read().split(); clusters.setdefault((c,s),0)
    clusters[(c,s)]+=1
print("Response (code,size) clusters:")
for (c,s),n in sorted(clusters.items(),key=lambda x:-x[1]):
    print(f"  {c}/{s}B  x{n}")
print()
# anything that isn't 404/35B, 404/261B, 405/0B, or a method-edge response
interesting=[]
for f in glob.glob(os.path.join(O,"*.meta")):
    c,s=open(f).read().split()
    if (c,s) not in [("404","35"),("404","261"),("404","0"),("405","0"),("000","0")] \
       and c not in ("411","501","500"):
        interesting.append((os.path.basename(f)[:-5],c,s))
if interesting:
    print("INTERESTING (pursue):")
    for t,c,s in interesting: print(f"  * {t}: {c}/{s}B")
else:
    print("No service/catalog responded beyond origin-404. Next options:")
    print("  - SAP ICF default services list (BSP /sap/bc/bsp/sap/, WebGUI)")
    print("  - SAP Web Dispatcher admin /sap/wdisp/admin (if exposed)")
    print("  - If truly nothing unauth, M024 origin is reachable but locked down;")
    print("    weigh effort vs pivot to M004 (franchise app, reachable code).")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
