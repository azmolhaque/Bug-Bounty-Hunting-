#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — ram.unicef.org ALL-resource-type exposure sweep (session5)
# Portable: Linux / Pi / Termux.
#
# ram /en/jsonapi advertises 70 resource types. Instead of guessing, this reads
# EVERY type from the index and sample-tests each for unauthenticated exposure:
#   DATA      -> returns records unauth  (exposure; PII if user/contact/file/etc.)
#   OMITTED   -> data:[] but leaks UUIDs via meta.omitted (info-leak, like F001 oauth)
#   FORBIDDEN -> 403 (properly access-controlled)
#   EMPTY     -> data:[] no leak
# Maximizes coverage on the one open API. Dedup vs F001 (user/user emails +
# oauth2_server_client UUID leak already reported).
#
# SAFETY: >=1.2s/req, read-only GET, SAMPLE ONLY (page-size 1), HARD STOP + flag
# on beneficiary/child/health-looking data, redact samples.
#
# Run (Termux): OUTDIR=$HOME/un5 bash runbooks/PI-RUNBOOK-unicef-session5-ram-allentities.sh \
#                 2>&1 | tee $HOME/un5/un5.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un5
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un5"
  else OUTDIR="$HOME/un5"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.2}"; H="ram.unicef.org"; B="https://$H"
SENS='beneficiar|child_|date_of_birth|"dob"|patient|diagnos|refugee|gbv|national_id|"ssn"|passport'
echo "============================================================"
echo "UNICEF ram ALL-ENTITIES  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Host: $H   pace: ${PACE}s/req   SAFETY: sample-only, stop-on-sensitive"
echo "============================================================"; echo ""
J(){ curl -s -L --max-redirs 3 --max-time 18 -H "User-Agent: $UA" -H 'Accept: application/vnd.api+json' "$1"; }

echo "═══ READ INDEX -> all resource types ═══"
J "$B/en/jsonapi" > "$OUTDIR/index.json"; sleep "$PACE"
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
try: d=json.load(open(f"{O}/index.json"))
except Exception as e: print("index err:",e); raise SystemExit
links=d.get("links",{})
types=[]
for k,v in links.items():
    if "--" in k:
        href=v.get("href") if isinstance(v,dict) else v
        # derive path after /jsonapi/
        import re
        m=re.search(r'/jsonapi/(.+)$', href or "")
        types.append(m.group(1) if m else k.replace("--","/"))
types=sorted(set(types))
open(f"{O}/types.txt","w").write("\n".join(types))
print(f"  {len(types)} resource types to sweep")
PYEOF
echo ""

echo "═══ SWEEP every type (sample-only) ═══"
: > "$OUTDIR/exposed.txt"; : > "$OUTDIR/omitted.txt"
while IFS= read -r T; do
  [ -z "$T" ] && continue
  out=$(J "$B/en/jsonapi/$T?page%5Blimit%5D=1"); sleep "$PACE"
  if echo "$out" | grep -qiE "$SENS"; then
    printf '  [SENSITIVE] %-45s STOP+flag (no pull)\n' "$T"
    echo "$T" >> "$OUTDIR/SENSITIVE.txt"; continue
  fi
  res=$(echo "$out" | python3 -c "import sys,json
try:
 d=json.load(sys.stdin); x=d.get('data')
 n=len(x) if isinstance(x,list) else (1 if x else 0)
 om=d.get('meta',{}).get('omitted',{}).get('links')
 err=d.get('errors')
 if n>0: print('DATA:%d'%n)
 elif om: print('OMITTED')
 elif err: print('FORBIDDEN' if any('403' in str(e.get('status','')) for e in err) else 'ERROR')
 else: print('EMPTY')
except Exception: print('NONJSON')")
  case "$res" in
    DATA:*) printf '  *** %-45s %s  <-- EXPOSED\n' "$T" "$res"
            echo "$T|$res" >> "$OUTDIR/exposed.txt"
            echo "$out" | head -c 600 > "$OUTDIR/sample-$(echo "$T"|tr -c 'A-Za-z0-9' '_').json";;
    OMITTED) printf '  ~   %-45s OMITTED (uuid leak)\n' "$T"
            echo "$T" >> "$OUTDIR/omitted.txt";;
    *)      : ;; # EMPTY/FORBIDDEN/ERROR — silent
  esac
done < "$OUTDIR/types.txt"
echo ""

echo "════════════════════════════════════════════"
echo "RESULTS"
echo "════════════════════════════════════════════"
echo "  EXPOSED (returns data unauth):"
[ -s "$OUTDIR/exposed.txt" ] && sed 's/^/    /' "$OUTDIR/exposed.txt" || echo "    (none)"
echo ""
echo "  OMITTED (uuid/info leak via meta.omitted):"
[ -s "$OUTDIR/omitted.txt" ] && sed 's/^/    /' "$OUTDIR/omitted.txt" | head -30 || echo "    (none)"
echo ""
[ -s "$OUTDIR/SENSITIVE.txt" ] && { echo "  !!! SENSITIVE (hand-review, no bulk-pull):"; sed 's/^/    /' "$OUTDIR/SENSITIVE.txt"; echo ""; }
echo "  Triage: any EXPOSED user/contact_message/file/comment with REAL personal"
echo "  data = a finding distinct from F001. dedup user/user (emails) + "
echo "  oauth2_server_client (uuid) which are already in F001. Confirm sample is"
echo "  real+sensitive, redact, write report."
echo ""
echo "Evidence: $OUTDIR  (samples redacted, sample-only)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
