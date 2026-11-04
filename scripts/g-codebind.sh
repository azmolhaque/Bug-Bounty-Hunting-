#!/data/data/com.termux/files/usr/bin/bash
# g-codebind.sh — is an authorization code bound to the client it was issued to?
#
#   usage: bash scripts/g-codebind.sh <MY_CLIENT_ID> <MY_CLIENT_SECRET> <MY_REDIRECT_URI> <CODE>
#
# WHY THIS IS THE LAST REAL CLASS LEFT
# OAuth requires a token endpoint to reject a code presented by a client other than
# the one it was issued to. If Fitbit does not enforce that, then any third-party
# Fitbit app - which anyone can register for free - can take a code its own user
# granted it and redeem it as "Fitbit Web Application" instead, because that
# client's secret is published. A limited third-party consent becomes a
# first-party client's token.
#
# That is client confusion / code injection, it is a named OAuth flaw, and unlike
# everything else tried here it needs nothing but accounts we own.
#
# FOUR-WAY, and the order matters:
#   [SENTINEL] fabricated code + published secret  -> what "bad code" looks like
#   [CROSS]    OUR real code + PUBLISHED secret    -> the actual question
#   [CONTROL]  OUR real code + OUR OWN secret      -> proves the code was valid and unused
#
# The control runs LAST on purpose: redeeming a code consumes it. If the control
# ran first the cross attempt would fail for the wrong reason and we would call it
# secure when it never had a chance.
set -u
MYID="${1:?my client_id}"; MYSEC="${2:?my client_secret}"; MYRED="${3:?my redirect_uri}"; CODE="${4:?the code}"
PUB=$(printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64 -w0 2>/dev/null || printf '228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a' | base64)
MINE=$(printf '%s:%s' "$MYID" "$MYSEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$MYID" "$MYSEC" | base64)

ex() { printf '  %-44s ' "$1"
  curl -s --max-time 15 -X POST https://api.fitbit.com/oauth2/token \
    -H "Authorization: Basic $2" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$3" \
    --data-urlencode "redirect_uri=$MYRED" \
    --data-urlencode "client_id=$4" \
    -w ' [%{http_code}]\n' | tr -d '\n' | head -c 340; echo; sleep 2; }

echo "######################################################################"
echo "# Is an authorization code bound to its client?                      #"
echo "######################################################################"
ex "[SENTINEL] fake code + published secret" "$PUB"  "ZZZINVALIDCODE7x2" "228TQD"
ex "[CROSS]    MY code + PUBLISHED secret"   "$PUB"  "$CODE"             "228TQD"
echo
echo "  (control last — redeeming consumes the code)"
ex "[CONTROL]  MY code + MY OWN secret"      "$MINE" "$CODE"             "$MYID"

cat <<'TXT'

  HOW TO READ

    CROSS returns an access_token
        -> codes are NOT bound to the issuing client. Any third-party Fitbit app
           can redeem its user's code as "Fitbit Web Application" using the
           published secret. STOP THERE - that response is the proof, and the
           report is rewritten around it.

    CROSS == SENTINEL, and CONTROL returns a token
        -> codes ARE bound. Enforced correctly. The control is what makes this
           readable: it proves the code was genuinely valid and unused, so the
           cross attempt failed on binding and not on a stale code.

    CROSS == SENTINEL, and CONTROL ALSO fails
        -> the code was already spent or expired. Proves nothing either way.
           Get a fresh code and rerun. Do NOT record this as secure.
TXT
