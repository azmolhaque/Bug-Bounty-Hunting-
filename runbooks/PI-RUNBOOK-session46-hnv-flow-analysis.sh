#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV: how does the LEGIT client call reservationDetails? (s46)
# Portable: Linux / Pi / Termux.
#
# The IDOR-vs-intended question can't be settled with synthetic ids. This run
# reads HnV's OWN JS to learn the intended contract:
#   - The exact reservationDetails GraphQL operation the client sends (does it
#     include last_name as a required variable? or confirmation_id only?)
#   - The "find reservation" / guest-lookup flow (is last_name client-required?)
#   - Any authenticated "My Trips"/account path that calls reservationDetails
#     with confirmation_id ONLY (proves the resolver supports a conf-id-only code
#     path -> unauth access to it = authorization flaw, not intended lookup)
#
# This is read-only JS analysis (no API calls beyond fetching public assets).
# It builds the case; the definitive confirmation still needs a real own-booking
# confirmation_id (see M025).
#
# Run (Termux): OUTDIR=$HOME/s46 bash runbooks/PI-RUNBOOK-session46-hnv-flow-analysis.sh \
#                 2>&1 | tee $HOME/s46/s46.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s46
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s46"
  else OUTDIR="$HOME/s46"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"

echo "============================================================"
echo "HNV FLOW ANALYSIS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

# Grab homepage + a few route pages that likely embed the reservation flow JS.
for P in "/" "/en-us/find-reservation" "/find-reservation" "/en-us/trips" "/trips" \
         "/en-us/account/trips" "/reservation" "/en-us/guest/reservation"; do
  tag="pg-$(echo "$P"|tr -c A-Za-z0-9 _)"
  curl -s -o "$OUTDIR/$tag.html" -c "$JAR" -b "$JAR" -H "User-Agent: $UA" -H "$IDH" \
    --max-time 20 -w "  GET %{url_effective} -> %{http_code} %{size_download}B\n" "$B$P" 2>/dev/null || true
done
echo ""

echo "═══ DOWNLOAD JS BUNDLES ═══"
python3 - << 'PYEOF'
import os,re,glob
O=os.environ["OUTDIR"]; js=set()
for f in glob.glob(os.path.join(O,"pg-*.html")):
    h=open(f,encoding="utf-8",errors="replace").read()
    js|=set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I))
open(os.path.join(O,"js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(js)} unique JS refs")
PYEOF
: > "$OUTDIR/alljs.txt"; i=0
while read -r J && [ $i -lt 30 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -b "$JAR" -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  printf '\n/*---*/\n' >> "$OUTDIR/alljs.txt"
  i=$((i+1)); sleep 0.15
done < "$OUTDIR/js.txt"
echo "  mined $(wc -c < "$OUTDIR/alljs.txt" 2>/dev/null||echo 0) bytes"
echo ""

echo "═══ A: reservationDetails OPERATION(S) AS THE CLIENT SENDS THEM ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
# GraphQL query strings mentioning reservationDetails (with surrounding op header)
for m in re.finditer(r'reservationDetails', js):
    s=max(0,m.start()-220); e=min(len(js),m.end()+260)
    seg=js[s:e]
    # only print windows that look like a gql operation (have 'query' or '$')
    if 'query' in seg or '$' in seg:
        print("  ...",seg.replace("\n"," ")[:460]); print()
PYEOF
echo ""

echo "═══ B: DOES THE CLIENT TREAT last_name AS REQUIRED? ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
# operation variable signatures touching reservationDetails / last_name
sigs=set(re.findall(r'query\s+\w*[Rr]eservation\w*\s*\(([^)]{0,160})\)', js))
for s in sigs: print("  op vars:", s.strip())
# how last_name is wired in the reservation flow
for kw in ["last_name","lastName","confirmation_id","confirmationId","guest-info","findReservation","find_reservation"]:
    n=len(re.findall(re.escape(kw),js))
    print(f"  '{kw}' occurrences: {n}")
# is last_name a String! (required) anywhere near reservation?
req=re.findall(r'(last_name|confirmation_id)\s*:\s*\$?\w*\s*[,)]|\$\w+\s*:\s*(String!|ID!)', js)
PYEOF
echo ""

echo "═══ C: AUTHENTICATED 'MY TRIPS' PATH (conf-id-only call?) ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
for kw in ["myTrips","my-trips","/trips","upcomingTrips","tripDetails","getTrips","hvmi_signInToken","loggedInUser"]:
    n=len(re.findall(re.escape(kw),js))
    if n: print(f"  '{kw}': {n}")
# windows where reservationDetails is called with only confirmation_id (no last_name nearby)
hits=0
for m in re.finditer(r'reservationDetails\s*\(([^)]{0,120})\)', js):
    args=m.group(1)
    if 'confirmation' in args and 'last_name' not in args and 'lastName' not in args:
        print("  conf-id-only call site:", args.strip()[:120]); hits+=1
print(f"  conf-id-only reservationDetails call sites: {hits}")
PYEOF
echo ""

echo "════════════════════════════════════════════"
echo "INTERPRETATION"
echo "════════════════════════════════════════════"
echo "  - If the client's reservationDetails op declares last_name as String!"
echo "    (required) and the FIND-RESERVATION form requires it -> the intended"
echo "    contract is conf-id + last_name. The API leaving last_name OPTIONAL and"
echo "    executing unauth is the deviation worth confirming (real id needed)."
echo "  - If there is a conf-id-ONLY call site (e.g. authenticated My Trips) -> the"
echo "    resolver is designed to return data from confirmation_id alone; reaching"
echo "    that path UNAUTHENTICATED = broken authorization (strong IDOR case)."
echo "  - Either way, the definitive PoC is one OWN confirmation_id queried"
echo "    conf-id-only while logged out (see M025). Do NOT use third-party ids."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
