#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal /users/{id} PII exposure test (cross-account read)
# Portable: Termux / Linux / Pi.
#
# session2: graph creation is premium-gated (dead). BUT GET /api/v3/users/gorib2
# with account A's key returned account B's profile incl. a real first_name.
# QUESTION: does /users/{username} expose genuinely-PRIVATE fields (email,
# last_name, phone, apikey, 2fa) of ANY user to any other party? Public
# username/profile = intended (worthless). Email/auth-field exposure = real PII
# IDOR. This compares the field set across viewer contexts to decide.
#
# Compares GET /users/<B> as:  (1) UNAUTH, (2) account A (cross-account),
#   (3) account B (owner/baseline).  Flags any private field visible to non-owner.
# All on OUR OWN two accounts — no third-party data harvested.
#
# PREP: VT_KEY=<A> VT_KEY_B=<B> VT_USER_A=<A username> VT_USER_B=<B username>
#   VT_KEY=<A> VT_KEY_B=<B> VT_USER_A=gorib VT_USER_B=gorib2 OUTDIR=$HOME/vt3 \
#     bash runbooks/PI-RUNBOOK-vt-session3-user-pii.sh 2>&1 | tee $HOME/vt3/vt3.log
#
# SAFETY: read-only. Own accounts. Output shows field KEY NAMES + email DOMAIN
# only (local part redacted); raw saved locally, never committed.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vt3}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<account A key>}"
: "${VT_USER_B:?set VT_USER_B=<account B username> (the profile we read)}"
VT_KEY_B="${VT_KEY_B:-}"; VT_USER_A="${VT_USER_A:-}"
PACE="${PACE:-16}"
B="https://www.virustotal.com/api/v3"
UA='vt-research/1.0 (authorized VRP testing)'
mask(){ local k="$1"; [ -n "$k" ] && printf '%s…%s' "${k:0:4}" "${k: -3}" || printf '<none>'; }
echo "============================================================"
echo "VT USER PII EXPOSURE TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "reading /users/$VT_USER_B as: UNAUTH, A=$(mask "$VT_KEY"), B=$(mask "$VT_KEY_B")"
echo "Own accounts only. Field names + email domain only."
echo "============================================================"; echo ""

fetch(){ # authmode label
  local auth="$1" label="$2" hdr=()
  case "$auth" in A) hdr=(-H "x-apikey: $VT_KEY");; B) hdr=(-H "x-apikey: $VT_KEY_B");; esac
  local code
  code=$(curl -s -L --max-time 25 -H "User-Agent: $UA" -H 'Accept: application/json' "${hdr[@]}" \
         -o "$OUTDIR/u_$label.json" -w '%{http_code}' "$B/users/$VT_USER_B" 2>/dev/null) || code=000
  echo "  [$code] /users/$VT_USER_B  ($label)"
  python3 - "$OUTDIR/u_$label.json" "$label" <<'PY' 2>/dev/null
import json,sys,re
try: d=json.load(open(sys.argv[1]))
except Exception: print("    (non-JSON / empty)"); sys.exit()
a=d.get("data",{}).get("attributes",{})
if not a:
    e=d.get("errors") or d.get("error")
    print("    no attributes; err:",str(e)[:120]); sys.exit()
keys=sorted(a.keys())
print("    fields:",keys)
SENS=["email","last_name","phone","phone_number","apikey","api_key","password",
      "two_factor","2fa","mfa","billing","address","country","preferences"]
for k in a:
    lk=k.lower()
    if any(s in lk for s in SENS):
        v=a[k]
        if isinstance(v,str) and "@" in v:
            print(f"    *** SENSITIVE '{k}': @{v.split('@')[-1]} (local part REDACTED)")
        else:
            print(f"    *** SENSITIVE '{k}': present (type {type(v).__name__})")
PY
  sleep "$PACE"
}

echo "═══ read account B's /users object from 3 contexts ═══"
fetch NONE unauth
fetch A    accountA_crossread
[ -n "$VT_KEY_B" ] && fetch B baseline_owner
echo ""

echo "════════════════════════════════════════════"
echo "TRIAGE"
echo "════════════════════════════════════════════"
echo "  Compare the 'fields' lists across contexts:"
echo "   * If UNAUTH already returns first_name etc -> VT profiles are PUBLIC by"
echo "     design; names alone are INTENDED (not a bug)."
echo "   * If account-A cross-read exposes a *** SENSITIVE field (email/last_name/"
echo "     phone/apikey/2fa) that UNAUTH/owner-only should hide -> real PII IDOR:"
echo "     any user can pull that field for any username. THAT is reportable."
echo "   * Decisive escalation: if 'apikey' or auth field ever appears for a"
echo "     non-owner -> account takeover (Critical)."
echo ""
echo "  Next if email/PII leaks: confirm the field is NOT shown on the public web"
echo "  profile (so it's truly private), then we have the before/after differential."
echo ""
echo "Evidence: $OUTDIR (raw json local; do not commit)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
