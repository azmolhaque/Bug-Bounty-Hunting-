#!/data/data/com.termux/files/usr/bin/bash
# H14 T5 — v1 / v2 scope-parity sweep on api.personio.de
#
# HYPOTHESIS
#   The h14-restricted credential holds Employees:Read and nothing else, with
#   readable attributes limited to first_name + last_name.
#   v1 enforces that: /v1/company/attendances, /time-offs and /document-categories
#   all return 403.
#   v2 was only ever tested on ONE path (/v2/persons). v1 and v2 return different
#   error envelopes — {"success":false,...} versus {"personio_trace_id":...} — so
#   they are different code, and endpoint scoping written twice is scoping that
#   can differ.
#
# WHAT COUNTS
#   403 / 401            -> enforced. Correct.
#   404                  -> route absent. Uninteresting.
#   200 on a non-person  -> the credential reached a collection it was never granted.
#   200 on persons with  -> attribute filter leaked on the v2 path.
#     fields beyond first_name / last_name / id
#
# RULES OF ENGAGEMENT — enforced in code, not in this comment (FO-21):
#   0.6s between requests, single threaded, X-Intigriti-Username on every call,
#   GET only, no fuzzing of identifiers.
#
# usage:
#   export PCID='papi-...'      # client id
#   export PCS='papi-...'       # client secret
#   bash h14-v2sweep.sh

set -u
UA='X-Intigriti-Username: gorib'
SLEEP=0.6
BASE='https://api.personio.de'
OUT="${OUT:-$HOME/h14}"; mkdir -p "$OUT"

: "${PCID:?export PCID (client id)}"
: "${PCS:?export PCS (client secret)}"

echo "== auth"
TOK=$(curl -s -X POST "$BASE/v1/auth" -H 'Content-Type: application/json' -H "$UA" \
  -d "{\"client_id\":\"$PCID\",\"client_secret\":\"$PCS\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null)
[ -n "$TOK" ] || { echo "!! auth failed — re-check credentials"; exit 1; }
echo "   token acquired (${#TOK} chars)"
sleep "$SLEEP"

# --- positive control FIRST. Without it nothing below means anything (FO-19).
echo
echo "== POSITIVE CONTROL — /v1/company/employees must return our two granted fields"
ctl=$(curl -s -H "Authorization: Bearer $TOK" -H "$UA" "$BASE/v1/company/employees?limit=1")
printf '%s' "$ctl" | python3 -c "
import sys,json
try:
    a=json.load(sys.stdin)['data'][0]['attributes']
    print('   OK — fields:', ', '.join(sorted(a)))
except Exception:
    print('   !! CONTROL FAILED — everything below is meaningless'); raise SystemExit(1)
" || exit 1
sleep "$SLEEP"

probe() { # $1 = path
  body=$(curl -s -D "$OUT/.h2" --max-time 20 -H "Authorization: Bearer $TOK" -H "$UA" "$BASE$1")
  code=$(awk 'NR==1{print $2}' "$OUT/.h2")
  case "$code" in
    401|403) verdict="enforced" ;;
    404)     verdict="absent" ;;
    200)     verdict="*** REACHED ***" ;;
    *)       verdict="?" ;;
  esac
  printf '  %-42s [%s] %-14s %s\n' "$1" "${code:-000}" "$verdict" \
    "$(printf '%s' "$body" | head -c 110 | tr -d '\n')"
  sleep "$SLEEP"
}

echo
echo "== v2 collections — our credential was granted NONE of these"
for p in \
  /v2/employments /v2/compensations /v2/absence-periods /v2/attendance-periods \
  /v2/documents /v2/custom-reports /v2/projects /v2/cost-centers /v2/departments \
  /v2/legal-entities /v2/teams /v2/offices /v2/positions /v2/org-units \
  /v2/employees /v2/company /v2/goals /v2/trainings
do probe "$p"; done

echo
echo "== v1 equivalents — known-enforced baseline for comparison"
for p in /v1/company/attendances /v1/company/time-offs /v1/company/document-categories \
         /v1/company/custom-reports /v1/company/departments
do probe "$p"; done

echo
echo "== /v2/persons field check — does the attribute filter hold on the v2 path?"
curl -s -H "Authorization: Bearer $TOK" -H "$UA" "$BASE/v2/persons?limit=1" \
 | python3 -c "
import sys,json
d=json.load(sys.stdin)
r=(d.get('_data') or [{}])[0]
keys=[k for k in r if not k.startswith('_')]
print('   fields returned:', ', '.join(sorted(keys)))
extra=[k for k in keys if k not in ('id','first_name','last_name','employments')]
print('   BEYOND GRANT:', extra if extra else 'none')
"
echo
echo "== done. Anything marked *** REACHED *** is the finding."
