#!/data/data/com.termux/files/usr/bin/bash
# f-delegate.sh — map Fitbit's delegate endpoints by asking what they require.
#
# The bundle names two endpoints we have never touched:
#     GET_DELEGATE_TOKEN    oauth2/delegate
#     DELEGATE_TOKEN_LOGIN  oauth2/delegate/token
# plus a DELEGATE_LOGIN_FAILURE constant and a delegateLogin action in the UI.
#
# "Delegate" means acting on behalf of someone else, which is exactly where an
# ownership check goes missing. grant_type=delegate_token was unsupported, but
# these are separate ENDPOINTS, not grants, and may be governed differently.
#
# METHOD: ask the endpoints what parameters they want, the same way the social and
# mfa_sms grants were mapped. Error messages name the next required field, so a
# handful of requests draws the whole shape without exploiting anything.
#
# SAFETY: client credentials only - the two whose secrets are already public and
# already reported. Every identifier sent is fabricated. No user is referenced.
set -u
A=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
B=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)

q() { # q <label> <method> <url> <authheader> <data>
  printf '  %-44s ' "$1"
  if [ -z "$5" ]; then
    curl -s --max-time 14 -X "$2" "$3" ${4:+-H "Authorization: $4"} -w ' [%{http_code}]\n'
  else
    curl -s --max-time 14 -X "$2" "$3" ${4:+-H "Authorization: $4"} \
      -H 'Content-Type: application/x-www-form-urlencoded' -d "$5" -w ' [%{http_code}]\n'
  fi | tr -d '\n' | head -c 300; echo; sleep 2; }

echo "######################################################################"
echo "# oauth2/delegate — what is it, and what does it want?               #"
echo "######################################################################"
q "[SENTINEL] a path that cannot exist" POST "https://api.fitbit.com/oauth2/zzz_not_a_path_7x2" "Basic $B" ""
q "GET  /oauth2/delegate"               GET  "https://api.fitbit.com/oauth2/delegate"           "Basic $B" ""
q "POST /oauth2/delegate (empty)"       POST "https://api.fitbit.com/oauth2/delegate"           "Basic $B" ""
q "POST /oauth2/delegate (no auth)"     POST "https://api.fitbit.com/oauth2/delegate"           ""         ""

echo
echo "######################################################################"
echo "# oauth2/delegate/token — the login half                             #"
echo "######################################################################"
q "POST /oauth2/delegate/token (empty)" POST "https://api.fitbit.com/oauth2/delegate/token"     "Basic $B" ""
q "  + grant_type=delegate_token"       POST "https://api.fitbit.com/oauth2/delegate/token"     "Basic $B" "grant_type=delegate_token"
q "  + a fabricated delegate token"     POST "https://api.fitbit.com/oauth2/delegate/token"     "Basic $B" "grant_type=delegate_token&delegateToken=ZZZINVALID7x2"
q "  (no auth)"                         POST "https://api.fitbit.com/oauth2/delegate/token"     ""         "grant_type=delegate_token&delegateToken=ZZZINVALID7x2"

echo
echo "######################################################################"
echo "# does the OTHER client see the same thing?                          #"
echo "######################################################################"
q "227ZG3 POST /oauth2/delegate"        POST "https://api.fitbit.com/oauth2/delegate"           "Basic $A" ""

cat <<'TXT'

  HOW TO READ

    Rows differ from the SENTINEL
        -> the endpoints are real and are telling us their shape. Note exactly
           which parameter each one asks for next; that is the map, and it is how
           the social and mfa_sms grants were charted.

    Everything matches the SENTINEL
        -> these endpoints are not reachable from outside and the lead closes here.

    Any row returns a TOKEN
        -> stop. A delegate token obtained with a published client secret is a far
           bigger finding than G-F002, and that one response is the proof.

  If a row asks for a user identifier, STOP and tell me rather than supplying one.
  The right next step there is careful, and it is not "try a number".
TXT
