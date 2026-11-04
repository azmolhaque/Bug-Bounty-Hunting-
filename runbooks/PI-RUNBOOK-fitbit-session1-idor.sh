#!/usr/bin/env bash
# =============================================================================
# Google VRP — Fitbit Web API privacy/IDOR test (cross-account health-data read)
# Portable: Termux / Linux / Pi.   api.fitbit.com (in scope, authoritative).
#
# Hypothesis: Fitbit lets users set each data category (activity, body/weight,
# heart rate, sleep, friends, devices) to PRIVATE. If account A (a NON-FRIEND) can
# read account B's PRIVATE data via B's user-id, that's a health-data IDOR/BOLA
# (high value). Compares each category read as: OWNER (B), ATTACKER (A, non-friend),
# UNAUTH. Any category where A/unauth gets B's private data = finding.
#
# ── PREP (one-time) ──────────────────────────────────────────────────────────
# 1. Two Fitbit accounts A and B. Make sure A and B are NOT friends.
# 2. In account B: Settings -> Privacy -> set Activity, Body/Weight, Sleep, Heart,
#    Friends to "Only You" (PRIVATE). This is what makes any A-read a real leak.
# 3. Get an OAuth token for EACH account (implicit grant, no server needed):
#    a) https://dev.fitbit.com/apps/new -> create app: Type=Client,
#       Callback=https://localhost/callback, Access=Read-Only. Note the Client ID.
#    b) Open this URL logged in as account A (then again, incognito, as B):
#       https://www.fitbit.com/oauth2/authorize?response_type=token&client_id=CLIENTID&scope=activity%20heartrate%20location%20nutrition%20profile%20settings%20sleep%20social%20weight&expires_in=604800
#    c) After authorizing, the browser redirects to
#       https://localhost/callback#access_token=XXXX&user_id=YYYY&...
#       (page fails to load — that's fine). Copy access_token from the URL bar.
# 4. Run:
#    FITBIT_TOKEN_A=<A token> FITBIT_TOKEN_B=<B token> OUTDIR=$HOME/fb1 \
#      bash runbooks/PI-RUNBOOK-fitbit-session1-idor.sh 2>&1 | tee $HOME/fb1/fb1.log
#
# SAFETY: read-only GET, our own two accounts, in scope. Tokens env-only, MASKED,
# never committed. PII redacted in output (presence/category only). Paced.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/fb1}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${FITBIT_TOKEN_A:?set FITBIT_TOKEN_A=<account A OAuth token> (see PREP in header)}"
: "${FITBIT_TOKEN_B:?set FITBIT_TOKEN_B=<account B OAuth token> (see PREP in header)}"
PACE="${PACE:-2}"
API="https://api.fitbit.com"
DATE="${DATE:-2026-06-29}"
UA='fitbit-research/1.0 (authorized VRP testing)'
mask(){ local k="$1"; [ -n "$k" ] && printf '%s…%s' "${k:0:6}" "${k: -4}" || printf '<none>'; }
echo "============================================================"
echo "FITBIT WEB API IDOR TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "A=$(mask "$FITBIT_TOKEN_A")  B=$(mask "$FITBIT_TOKEN_B")  date=$DATE  pace=${PACE}s"
echo "Own accounts, read-only. Tokens masked; PII redacted."
echo "============================================================"; echo ""

get(){ # path  token('A'|'B'|'')  -> echoes 'code' ; saves body to $OUTDIR/last.json
  local p="$1" t="$2" auth=()
  case "$t" in A) auth=(-H "Authorization: Bearer $FITBIT_TOKEN_A");; B) auth=(-H "Authorization: Bearer $FITBIT_TOKEN_B");; esac
  curl -s -L --max-time 20 -H "User-Agent: $UA" -H 'Accept-Language: en_US' "${auth[@]}" \
    -o "$OUTDIR/last.json" -w '%{http_code}' "$API$p" 2>/dev/null
}

echo "═══ A: derive user-ids + confirm tokens ═══"
code=$(get "/1/user/-/profile.json" A); sleep "$PACE"
UIDA=$(python3 -c "import json;print(json.load(open('$OUTDIR/last.json')).get('user',{}).get('encodedId',''))" 2>/dev/null)
echo "  account A self-profile -> HTTP $code ; A user-id=${UIDA:-FAILED}"
code=$(get "/1/user/-/profile.json" B); sleep "$PACE"
cp "$OUTDIR/last.json" "$OUTDIR/B_profile_owner.json"
UIDB=$(python3 -c "import json;print(json.load(open('$OUTDIR/last.json')).get('user',{}).get('encodedId',''))" 2>/dev/null)
echo "  account B self-profile -> HTTP $code ; B user-id=${UIDB:-FAILED}"
[ -z "$UIDA" ] || [ -z "$UIDB" ] && { echo "  !! token(s) invalid — re-check PREP step 3"; exit 0; }
# friendship sanity: is A friend of B? (should be NO for a clean test)
echo ""

echo "═══ B: CROSS-ACCOUNT READ MATRIX (A reads B's data; should be denied if private) ═══"
echo "  legend: owner=B-token, ATTACKER=A-token reading B's id, unauth=no token"
# category | path-template (use {UID})
CATS="
profile|/1/user/{UID}/profile.json
activities_today|/1/user/{UID}/activities/date/$DATE.json
activities_lifetime|/1/user/{UID}/activities.json
body_weight|/1/user/{UID}/body/log/weight/date/$DATE.json
sleep|/1.2/user/{UID}/sleep/date/$DATE.json
heartrate|/1/user/{UID}/activities/heart/date/$DATE/1d.json
friends|/1.1/user/{UID}/friends.json
devices|/1/user/{UID}/devices.json
"
: > "$OUTDIR/leaks.txt"
printf '%s\n' "$CATS" | while IFS='|' read -r name tmpl; do
  [ -z "$name" ] && continue
  pB="${tmpl/\{UID\}/$UIDB}"
  # owner baseline
  oc=$(get "$pB" B); sleep "$PACE"; osz=$(wc -c < "$OUTDIR/last.json")
  oerr=$(grep -c '"errors"' "$OUTDIR/last.json")
  # attacker (A reading B)
  ac=$(get "$pB" A); sleep "$PACE"; asz=$(wc -c < "$OUTDIR/last.json"); cp "$OUTDIR/last.json" "$OUTDIR/atk_$name.json"
  aerr=$(grep -c '"errors"' "$OUTDIR/last.json")
  # unauth
  uc=$(get "$pB" ""); sleep "$PACE"; usz=$(wc -c < "$OUTDIR/last.json")
  uerr=$(grep -c '"errors"' "$OUTDIR/last.json")
  flag=""
  { [ "$ac" = "200" ] && [ "${aerr:-0}" = "0" ]; } && flag="$flag ATTACKER-READ"
  { [ "$uc" = "200" ] && [ "${uerr:-0}" = "0" ]; } && flag="$flag UNAUTH-READ"
  printf "  %-20s owner=%s(%s)  ATTACKER=%s(%s)  unauth=%s(%s) %s\n" \
    "$name" "$oc" "$osz" "$ac" "$asz" "$uc" "$usz" "${flag:+ <-- $flag}"
  [ -n "$flag" ] && echo "$name|$ac|$uc|$flag" >> "$OUTDIR/leaks.txt"
done
echo ""

echo "═══ C: what did ATTACKER actually read? (field presence, PII redacted) ═══"
if [ -s "$OUTDIR/leaks.txt" ]; then
  while IFS='|' read -r name rest; do
    f="$OUTDIR/atk_$name.json"
    echo "  [$name] attacker view fields:"
    python3 - "$f" <<'PY' 2>/dev/null
import json,sys
d=json.load(open(sys.argv[1]))
def walk(o,pre=""):
    out=[]
    if isinstance(o,dict):
        for k,v in o.items():
            if isinstance(v,(dict,list)): out+=walk(v,pre+k+".")
            else: out.append(pre+k)
    elif isinstance(o,list) and o:
        out+=walk(o[0],pre+"0.")
    return out
keys=sorted(set(walk(d)))
print("     ",keys[:40])
for sk in ("fullName","dateOfBirth","city","state","country","age","gender"):
    # report presence of sensitive profile PII only
    pass
PY
  done < "$OUTDIR/leaks.txt"
fi
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/leaks.txt" ]; then
  echo "  *** CROSS-ACCOUNT / UNAUTH READ of B's data (B set to PRIVATE):"
  sed 's/^/    /' "$OUTDIR/leaks.txt"
  echo "  IMPORTANT: confirm these categories are set to PRIVATE in B's settings."
  echo "  Fitbit treats display name/avatar as PUBLIC by design — those are NOT bugs."
  echo "  A non-friend reading B's PRIVATE steps/weight/heartrate/sleep = real IDOR."
else
  echo "  Clean: A (non-friend) and unauth cannot read B's data. VT-style hardened."
  echo "  Next: test the SOCIAL graph (can A see B's friends list / add itself), or"
  echo "  the subscription/intraday endpoints, or pivot."
fi
echo ""
echo "Evidence: $OUTDIR  (raw json local; tokens never committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
