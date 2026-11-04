#!/data/data/com.termux/files/usr/bin/bash
# g-probe13.sh — THE DECIDER. What does the app token actually reach?
#
# Fitbit's docs: "Client Credentials ... is used with specific Fitbit API endpoints
# related to business operations." So the token we can mint is not inert — it works
# SOMEWHERE. If anywhere it reaches is something an outsider should not reach, this
# report has real impact. If not, we park it tonight and sleep knowing why.
#
# THREE AUTH STATES on every endpoint, because a 200 means nothing on its own:
#     [APP]  our minted client_access_token
#     [NIL]  no Authorization header            <- if this also 200s, the endpoint is public
#     [FAKE] a fabricated bearer token          <- if this also 200s, the token is not checked
# Only a row where APP differs from BOTH others tells us the token is doing work.
#
# BODIES ARE SUPPRESSED on user-shaped endpoints. Status and size are enough to see a
# boundary break, and that is all we are entitled to look at.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"
ID=228TQD; SEC=7659f9d9ecc92d6dc1ee0d1774e9744a
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)

echo "######################################################################"
echo "# 1. Can the app token be minted WITH SCOPES? (the big one)          #"
echo "######################################################################"
echo "  Our earlier call sent no scope parameter and got scope:\"\". Nobody checked"
echo "  whether asking changes that. If this grant will issue a token carrying"
echo "  heartrate or profile scope, the published secret reaches user data and the"
echo "  whole report changes. If it refuses, that is a hard limit, honestly found."
for sc in "profile" "heartrate" "activity%20heartrate%20location%20sleep%20profile" "" ; do
  printf '  scope=%-46s ' "${sc:-<none>}"
  curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token \
    -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=client_credentials${sc:+&scope=$sc}" \
    | python3 -c "import sys,json,base64
try:
  d=json.load(sys.stdin)
except Exception:
  print('(unparseable)'); raise SystemExit
if 'access_token' in d:
  p=d['access_token'].split('.')[1]; p+='='*(-len(p)%4)
  try: inner=json.loads(base64.urlsafe_b64decode(p))
  except Exception: inner={}
  print('200  scope=%r  jwt.scopes=%r  aud=%r' % (d.get('scope'), inner.get('scopes'), inner.get('aud')))
else:
  e=(d.get('errors') or [{}])[0]; print('ERR  %s  %s' % (e.get('errorType'), (e.get('message') or '')[:90]))"
  sleep 2
done

echo
echo "######################################################################"
echo "# 2. Ask Fitbit what it thinks our token IS                          #"
echo "######################################################################"
TOK=$(curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token \
  -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
printf '  token minted: %s chars\n' "${#TOK}"
printf '  introspect  : '
curl -s --max-time 14 -X POST https://api.fitbit.com/1.1/oauth2/introspect \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$TOK" -w ' [HTTP %{http_code}]\n' | tr -d '\n' | head -c 400; echo
sleep 1.5

echo
echo "######################################################################"
echo "# 3. Where is this token ACCEPTED? three-way, bodies suppressed       #"
echo "######################################################################"
printf '  %-44s %-14s %-14s %-14s\n' ENDPOINT "[APP]" "[NIL]" "[FAKE]"
for ep in \
  "/1/user/-/profile.json" \
  "/1/user/-/apiSubscriptions.json" \
  "/1/apiSubscriptions.json" \
  "/1/user/-/activities/heart/date/today/1d.json" \
  "/1/foods/units.json" \
  "/1/activities.json" \
  "/1/zzz-canary-7x2.json" ; do
  a=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}/%{size_download}b' -H "Authorization: Bearer $TOK" "https://api.fitbit.com$ep")
  n=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}/%{size_download}b' "https://api.fitbit.com$ep")
  f=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}/%{size_download}b' -H "Authorization: Bearer ZZZFAKETOKEN7x2" "https://api.fitbit.com$ep")
  printf '  %-44s %-14s %-14s %-14s%s\n' "$ep" "$a" "$n" "$f" \
    "$( [ "$a" != "$n" ] && [ "$a" != "$f" ] && echo '   <<< TOKEN IS DOING WORK' )"
  sleep 1
done

echo
cat <<'TXT'
  HOW TO READ — and the decision it produces

    Section 1 issues a token whose scope is NOT empty
        -> the published secret reaches user-scoped access. STOP. That is a real,
           payable finding and the report is rewritten around it.

    Section 3 shows any "<<< TOKEN IS DOING WORK" row
        -> tell me the endpoint. If it is user- or business-data shaped, that is
           the impact we have been missing.

    Neither happens
        -> the app token is inert outside endpoints we cannot reach, the secret
           unlocks nothing, and we PARK the report tonight. That is a clean answer,
           and a clean answer is what we came for.
TXT
