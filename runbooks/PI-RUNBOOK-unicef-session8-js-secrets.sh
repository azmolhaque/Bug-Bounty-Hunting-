#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — JS secret / leaked-key mining across live hosts (session8)
# Portable: Linux / Pi / Termux.
#
# JSON:API thread exhausted (F001 ram-only; www/weshare/lexonis = false positives).
# Next confirmable class on a soft target: SENSITIVE secrets in client-side JS.
# A working leaked secret = undeniable. We flag only HIGH-CONFIDENCE secret-class
# keys (AWS AKIA, Stripe sk_live, SendGrid, Slack/GitHub tokens, private keys,
# Mapbox SECRET sk., Firebase config) and separately note Google AIza keys for a
# benign restriction check (unrestricted = billable-abuse finding).
#
# SAFETY: read-only GET, paced, in-scope (*.unicef.org). Do NOT use any secret
# found — report only. Skip sensitive-named hosts.
#
# Run (Termux): OUTDIR=$HOME/un8 bash runbooks/PI-RUNBOOK-unicef-session8-js-secrets.sh \
#                 2>&1 | tee $HOME/un8/un8.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un8
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un8"
  else OUTDIR="$HOME/un8"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.5}"
echo "============================================================"
echo "UNICEF JS SECRET MINING  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   (report-only; never use found secrets)"
echo "============================================================"; echo ""

# ── A: enumerate + pick live hosts ──
echo "═══ A: ENUM + LIVE HOSTS ═══"
: > "$OUTDIR/subs.raw"
curl -s --max-time 30 -H "User-Agent: $UA" "https://crt.sh/?q=%25.unicef.org&output=json" 2>/dev/null \
  | grep -oE '[a-zA-Z0-9._-]+\.unicef\.org' >> "$OUTDIR/subs.raw" || true
curl -s --max-time 30 -H "User-Agent: $UA" \
  "https://api.certspotter.com/v1/issuances?domain=unicef.org&include_subdomains=true&expand=dns_names" 2>/dev/null \
  | grep -oE '[a-zA-Z0-9._-]+\.unicef\.org' >> "$OUTDIR/subs.raw" || true
grep -vE 'familylinks|casebook|missing|tracing|child|beneficiar|victim|gbv|protection' "$OUTDIR/subs.raw" \
  | sort -u > "$OUTDIR/subs.txt"
echo "  $(wc -l < "$OUTDIR/subs.txt") candidate hosts"
echo ""

# ── B: fetch homepage + JS, mine secrets ──
echo "═══ B: FETCH JS + MINE (high-confidence secrets only) ═══"
: > "$OUTDIR/allcode.txt"; n=0
while read -r H; do
  [ -z "$H" ] && continue
  n=$((n+1)); [ "$n" -gt "${MAXHOSTS:-80}" ] && break
  page=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  [ -z "$page" ] && { sleep "$PACE"; continue; }
  echo "/*HOST:$H*/" >> "$OUTDIR/allcode.txt"
  echo "$page" >> "$OUTDIR/allcode.txt"
  # extract up to 6 JS urls, fetch them
  echo "$page" | grep -oE 'src=["'"'"'][^"'"'"']+\.js[^"'"'"']*' | sed -E 's/^src=.//' \
    | head -6 | while read -r J; do
      case "$J" in http*) U="$J";; //*) U="https:$J";; /*) U="https://$H$J";; *) U="https://$H/$J";; esac
      echo "/*JS:$U*/" >> "$OUTDIR/allcode.txt"
      curl -s --max-time 12 -H "User-Agent: $UA" "$U" >> "$OUTDIR/allcode.txt" 2>/dev/null || true
      sleep 0.2
    done
  sleep "$PACE"
done < "$OUTDIR/subs.txt"
echo "  mined $(wc -c < "$OUTDIR/allcode.txt") bytes"
echo ""

echo "═══ C: SECRET EXTRACTION ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
code=open(os.path.join(O,"allcode.txt"),encoding="utf-8",errors="replace").read()
# track which host a match is under (rough)
def host_for(pos):
    h=code.rfind("/*HOST:",0,pos)
    if h<0: return "?"
    return code[h+7:code.find("*/",h)]
PATTERNS=[
 ("AWS access key id", r'\bAKIA[0-9A-Z]{16}\b', "CRITICAL"),
 ("Stripe live secret", r'\bsk_live_[0-9a-zA-Z]{24,}\b', "CRITICAL"),
 ("Stripe restricted",  r'\brk_live_[0-9a-zA-Z]{24,}\b', "HIGH"),
 ("SendGrid key",       r'\bSG\.[\w-]{22}\.[\w-]{43}\b', "CRITICAL"),
 ("GitHub token",       r'\bgh[posu]_[0-9A-Za-z]{36,}\b', "CRITICAL"),
 ("Slack token",        r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b', "CRITICAL"),
 ("Mailgun key",        r'\bkey-[0-9a-f]{32}\b', "HIGH"),
 ("Twilio SID/secret",  r'\bSK[0-9a-f]{32}\b', "HIGH"),
 ("Mapbox SECRET token",r'\bsk\.eyJ[\w-]+\.[\w-]+\.[\w-]+', "HIGH"),
 ("Private key block",  r'-----BEGIN [A-Z ]*PRIVATE KEY-----', "CRITICAL"),
 ("Google API key",     r'\bAIza[0-9A-Za-z_\-]{35}\b', "VALIDATE"),
 ("Firebase db url",    r'https://[a-z0-9-]+\.firebaseio\.com', "VALIDATE"),
 ("Algolia admin-ish",  r'(?i)algolia[^"\']{0,30}["\']([0-9a-f]{32})["\']', "VALIDATE"),
 ("Generic secret kv",  r'(?i)(api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "REVIEW"),
]
seen=set(); hits=[]
for name,pat,sev in PATTERNS:
    for m in re.finditer(pat, code):
        val=m.group(0)
        key=(name,val[:60])
        if key in seen: continue
        seen.add(key)
        hits.append((sev,name,val[:80],host_for(m.start())))
order={"CRITICAL":0,"HIGH":1,"VALIDATE":2,"REVIEW":3}
hits.sort(key=lambda x:order.get(x[0],9))
if not hits: print("  no high-confidence secrets matched.")
for sev,name,val,h in hits:
    print(f"  [{sev:8}] {name:22} {val}")
    print(f"             host: {h}")
open(os.path.join(O,"secrets.txt"),"w").write("\n".join(f"{s}\t{n}\t{v}\t{h}" for s,n,v,h in hits))
print()
print("  CRITICAL/HIGH = report immediately (never use the key).")
print("  VALIDATE (Google/Firebase/Algolia) = benign check whether it's restricted")
print("  (unrestricted Google key = billable-abuse finding; referrer-locked = info only).")
PYEOF
echo ""
echo "Evidence: $OUTDIR/secrets.txt  (do NOT use any key; report-only)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
