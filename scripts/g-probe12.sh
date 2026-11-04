#!/data/data/com.termux/files/usr/bin/bash
# g-probe12.sh — what does the `social` grant want next?
#
# WHY THIS MATTERS
# The published credential unlocks grant_type=social, and the endpoint's first
# complaint is "Missing required parameter facebookUID or googleUID". A grant that
# resolves a Fitbit account from a SOCIAL PROVIDER'S USER ID is interesting,
# because a Google or Facebook UID is not a secret — it is handed to every app a
# person signs into. If that id alone is enough, the published client secret plus
# a public identifier would be an authentication bypass.
#
# IT MAY ALSO BE PERFECTLY SAFE: the grant almost certainly wants a signed token
# from the provider as well, and the UID is just a lookup key. This asks WHICH.
#
# SAFETY RULES BUILT IN
#   - the UID used is all zeros: a value that belongs to NO ONE and cannot exist.
#   - one request per shape. No list. No real person's identifier. No retry.
#   - we are reading the endpoint's PARAMETER REQUIREMENTS, not authenticating.
#   - if any response stops asking for parameters and starts returning data or a
#     token, STOP: that is the finding, and continuing would be unauthorised access.
set -u
ID=228TQD; SEC=7659f9d9ecc92d6dc1ee0d1774e9744a
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)
FAKE=000000000000000000000

g() { printf '  %-46s ' "$1"; curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token \
   -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' -d "$2" \
   -w ' [HTTP %{http_code}]\n' 2>/dev/null | tr -d '\n' | head -c 300; echo; sleep 2; }

echo "######################################################################"
echo "# grant_type=social — what else does it require?                     #"
echo "######################################################################"
g "googleUID only (all zeros, nobody's id)"   "grant_type=social&googleUID=$FAKE"
g "+ a fabricated provider token"             "grant_type=social&googleUID=$FAKE&googleAccessToken=ZZZINVALID7x2"
g "facebookUID only (all zeros)"              "grant_type=social&facebookUID=$FAKE"
echo
echo "######################################################################"
echo "# grant_type=mfa_sms — what else does it require?                    #"
echo "######################################################################"
g "mfaToken only (fabricated)"                "grant_type=mfa_sms&mfaToken=ZZZINVALID7x2"
g "mfaToken + code"                           "grant_type=mfa_sms&mfaToken=ZZZINVALID7x2&code=000000"
echo
cat <<'TXT'
  HOW TO READ — and when to stop

    "Missing parameters: <something>"
        the grant needs more. Note WHAT it needs and stop there. If what it needs
        is a signed token from Google or Facebook, the design is sound and this is
        just a lookup key — write that down, it bounds the finding honestly.

    "invalid_grant" / "user not found" / "invalid token"
        the grant accepted the shape and tried to RESOLVE the identifier. Record
        the exact wording. Do NOT substitute a real identifier to see what happens.

    an access_token comes back
        STOP IMMEDIATELY. Run nothing else. That is a complete authentication
        bypass and the single response is the whole proof.
TXT
