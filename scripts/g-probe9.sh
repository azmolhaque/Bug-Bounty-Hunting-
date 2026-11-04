#!/data/data/com.termux/files/usr/bin/bash
# g-probe9.sh — the last question worth asking: WHICH GRANT TYPES do these
# first-party clients accept?
#
# So far the impact is bounded by one thing: with the secret you can authenticate
# as the app, but you still need a victim's authorization code, and redirect_uri
# validation is strict. That holds for the AUTHORIZATION CODE flow.
#
# It does not have to hold for other grants. First-party clients are sometimes
# allowed the resource-owner-password grant, which skips the browser, the consent
# screen, the redirect_uri and the login page's reCAPTCHA entirely. If "Fitbit Web
# Application" accepts grant_type=password, then the published secret lets anyone
# submit email/password pairs straight to the token endpoint as Fitbit's own first-
# party client — and that is a materially bigger finding than credential exposure.
#
# SAFETY: the only account named below is OUR OWN test account, and the password is
# deliberately wrong. Each grant is tried ONCE. No list, no retry, no second account.
# This measures which grants EXIST; it is not an authentication attempt against anyone.
set -u
ID=228TQD; SEC=7659f9d9ecc92d6dc1ee0d1774e9744a
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)
OWN='azmol01717534550@gmail.com'

g() { # g <label> <postdata>
  printf '  %-40s ' "$1"
  curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token \
    -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "$2" -w ' [HTTP %{http_code}]\n' 2>/dev/null | tr -d '\n' | head -c 330; echo
  sleep 2
}

echo "######################################################################"
echo "# Which grant types does 'Fitbit Web Application' (228TQD) accept?   #"
echo "######################################################################"
g "[BASELINE] authorization_code" "grant_type=authorization_code&code=ZZZINVALID7x2&redirect_uri=https://example.com/"
g "[BASELINE] client_credentials" "grant_type=client_credentials"
g "[SENTINEL] not_a_real_grant"   "grant_type=zzz_not_a_real_grant_7x2"
echo
echo "  The sentinel is the key. Whatever Fitbit says for a grant that cannot exist"
echo "  is what 'not supported' looks like. Any grant below that answers DIFFERENTLY"
echo "  from the sentinel is a grant this client actually has."
echo
g "password (own acct, WRONG pw)"  "grant_type=password&username=$OWN&password=zzz-deliberately-wrong-7x2"
g "device_code"                    "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=ZZZINVALID7x2"
g "token-exchange"                 "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=ZZZINVALID7x2&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
echo
cat <<'TXT'
  HOW TO READ:
    password == sentinel ("unsupported_grant_type")
        -> ROPC is off. Impact stays where it is. Report as written.

    password != sentinel  (e.g. invalid_grant, "invalid username or password")
        -> ROPC IS ENABLED for Fitbit's own first-party client, and the secret to
           use it is published on the login page. That means credentials can be
           submitted straight to the token endpoint, skipping the web login's
           reCAPTCHA and whatever protections sit on it. STOP THERE. Do not try a
           second password, do not try another account - one request already
           proves the grant exists, and anything more is brute force.
TXT

echo
echo "######################################################################"
echo "# One host the CSP named that is not in Google's published list      #"
echo "######################################################################"
for h in corporate-webapps.fitbit.com web-api.fitbit.com zzz-canary-7x2.fitbit.com; do
  ip=$(dig +short +time=2 "$h" | grep -E '^[0-9.]+$' | head -1)
  printf '  %-34s %-16s ' "$h" "${ip:--}"
  [ -z "$ip" ] && { echo NO-DNS; continue; }
  curl -s -o /dev/null --max-time 8 -w '%{http_code} %{size_download}b %{redirect_url}\n' "https://$h/"
  sleep 0.7
done
