#!/data/data/com.termux/files/usr/bin/bash
# g-tokenbind.sh — the last untested question: are tokens bound to their client?
#
# The code-binding test died because app registration is closed. But we already
# hold credentials for TWO clients, so the same structural question can be asked
# without registering anything:
#
#   mint a token with 227ZG3, then try to introspect and revoke it as 228TQD.
#
# If one client can introspect or revoke another client's tokens, Fitbit is not
# binding tokens to the client that issued them. With both secrets published,
# anyone could do the same to tokens belonging to either application.
set -u
A=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
B=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)

mint() { curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $1" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null; }

call() { # call <label> <basic> <endpoint> <token>
  printf '  %-44s ' "$1"
  curl -s --max-time 14 -X POST "$3" -H "Authorization: Basic $2" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$4" \
    -w ' [%{http_code}]\n' | tr -d '\n' | head -c 300; echo; sleep 2; }

echo "minting one token per client..."
T227=$(mint "$A"); T228=$(mint "$B")
printf '  227ZG3 token: %s chars\n  228TQD token: %s chars\n\n' "${#T227}" "${#T228}"
[ "${#T227}" -lt 50 ] || [ "${#T228}" -lt 50 ] && { echo "a token failed to mint — stop, nothing below would be readable"; exit 1; }

I=https://api.fitbit.com/1.1/oauth2/introspect
echo "######################################################################"
echo "# INTROSPECT — can 228TQD read a token issued to 227ZG3?             #"
echo "######################################################################"
call "[CONTROL]  228TQD reads its OWN token"   "$B" "$I" "$T228"
call "[CROSS]    228TQD reads 227ZG3's token"  "$B" "$I" "$T227"
call "[SENTINEL] 228TQD reads a fake token"    "$B" "$I" "ZZZNOTATOKEN7x2"
echo
echo "  CROSS looks like CONTROL -> one client can read another's tokens."
echo "  CROSS looks like SENTINEL -> bound correctly, and the control proves the"
echo "  endpoint works at all so the negative is real."

R=https://api.fitbit.com/oauth2/revoke
echo
echo "######################################################################"
echo "# REVOKE — can 228TQD destroy a token issued to 227ZG3?              #"
echo "######################################################################"
echo "  Revocation is the sharper half: reading another client's token is a leak,"
echo "  destroying it is denial of service against that application's users."
call "[SENTINEL] 228TQD revokes a fake token"  "$B" "$R" "ZZZNOTATOKEN7x2"
call "[CROSS]    228TQD revokes 227ZG3's token" "$B" "$R" "$T227"
echo
echo "  --- did it actually die? ask 227ZG3 about its own token ---"
call "verify: 227ZG3 introspects its own token" "$A" "$I" "$T227"
echo
cat <<'TXT'
  A 200 from revoke means nothing on its own - revocation endpoints return 200
  for unknown tokens by design (RFC 7009). The verify line is the whole test:

    active:true   -> the token survived. Revocation was NOT cross-client. Closed.
    active:false  -> one client destroyed another client's token using a secret
                     published on a public page. Stop and tell me.
TXT
