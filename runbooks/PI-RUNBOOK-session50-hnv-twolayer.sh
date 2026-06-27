#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV encData two-layer key crack (session50)
# Portable: Linux / Pi / Termux.
#
# Architecture (from s49b JS):
#   real_passphrase = AES.decrypt(page.data.encKey, x.gp)   # encKey per-page (in
#       __NEXT_DATA__), x.gp = static JS key
#   encData         = AES.encrypt(graphql_json, real_passphrase)
#
# This run: extract encKey from the homepage __NEXT_DATA__, then for each static-
# key candidate K compute real = decrypt(encKey,K); if real is a clean string,
# decrypt the captured encData with `real` and check for a GraphQL marker. Chained
# two-stage validation pins both keys at once.
#
# INPUT: ENCDATA='U2FsdGVkX1...' (your own captured blob)
# SAFETY: offline crypto + public page/JS. Nothing committed. Read-only.
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s50
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s50"
  else OUTDIR="$HOME/s50"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"
[ -z "${ENCDATA:-}" ] && { echo "ERROR: set ENCDATA='U2FsdGVkX1...'"; exit 1; }
printf '%s' "$ENCDATA" > "$OUTDIR/enc.b64"

echo "============================================================"
echo "HNV TWO-LAYER  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -c "$OUTDIR/jar" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true

echo "═══ PHASE A: EXTRACT page.data.encKey FROM __NEXT_DATA__ ═══"
python3 - << 'PYEOF'
import os,re,json
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
# all encKey occurrences (value usually base64 'U2FsdGVk...' or hex)
ks=re.findall(r'"encKey"\s*:\s*"([^"]+)"', h)
ks=list(dict.fromkeys(ks))
open(os.path.join(O,"enckeys.txt"),"w").write("\n".join(ks))
print(f"  encKey values found: {len(ks)}")
for k in ks[:6]: print("   ",k[:80], f"({len(k)} chars)")
if not ks: print("  (none in homepage __NEXT_DATA__ — encKey may be page-specific)")
PYEOF
echo ""

echo "═══ PHASE B: STATIC-KEY CANDIDATES FROM JS ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
js=sorted(set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I)))
open(os.path.join(O,"js.txt"),"w").write("\n".join(js)); print(f"  {len(js)} js refs")
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
c=set()
# any quoted literal 6-64 chars that contains both letters+digits or looks key-ish
for m in re.finditer(r'["\']([A-Za-z0-9+/=_@.\-]{6,64})["\']', js):
    s=m.group(1)
    if (re.search(r'\d',s) and re.search(r'[A-Za-z]',s)) or len(s) in (16,24,32,44):
        if not s.endswith(('.js','.css','.png','.svg','.json','.woff','.woff2')): c.add(s)
# also short literals right next to 'gp'/'encKey'/'CryptoJS'
for m in re.finditer(r'(?:gp|encKey|secret|passphrase|cryptoKey)\b[^"\']{0,12}["\']([ -~]{4,64})["\']', js, re.I): c.add(m.group(1))
open(os.path.join(O,"static-cands.txt"),"w").write("\n".join(sorted(c)))
print(f"  {len(c)} static-key candidates")
PYEOF
echo ""

echo "═══ PHASE C: CHAINED TWO-STAGE DECRYPT ═══"
dec(){ openssl enc -d -aes-256-cbc -md md5 -a -A -pass pass:"$1" -in "$2" -out "$3" 2>/dev/null; }
ok_str(){ ! LC_ALL=C grep -aq $'\x00' "$1" && python3 -c "open('$1','rb').read().decode('utf-8')" 2>/dev/null; }
FOUND=""
# Try every (encKey x staticCand): real=dec(encKey,cand); then dec(capture,real)
while IFS= read -r EK; do
  [ -z "$EK" ] && continue
  printf '%s' "$EK" > "$OUTDIR/ek.b64"
  while IFS= read -r K; do
    [ -z "$K" ] && continue
    dec "$K" "$OUTDIR/ek.b64" "$OUTDIR/real.bin" || continue
    ok_str "$OUTDIR/real.bin" || continue
    REAL=$(cat "$OUTDIR/real.bin")
    [ ${#REAL} -lt 4 ] || [ ${#REAL} -gt 80 ] && continue
    dec "$REAL" "$OUTDIR/enc.b64" "$OUTDIR/cap.bin" || continue
    if LC_ALL=C grep -aqE 'operationName|"variables"|getProfileDetails|reservationDetails|getTotalReservationData|"query"' "$OUTDIR/cap.bin"; then
      echo "  *** CRACKED!"
      echo "    static x.gp  = [$K]"
      echo "    real passkey = [$REAL]"
      echo "  --- DECRYPTED CAPTURE ---"; head -c 1600 "$OUTDIR/cap.bin"; echo
      printf '%s' "$K" > "$OUTDIR/STATICKEY.txt"; printf '%s' "$REAL" > "$OUTDIR/REALKEY.txt"; cp "$OUTDIR/cap.bin" "$OUTDIR/decrypted.json"
      FOUND=1; break 2
    fi
  done < "$OUTDIR/static-cands.txt"
done < "$OUTDIR/enckeys.txt"

# Fallback: maybe encKey IS used directly as the passphrase (no x.gp layer)
if [ -z "$FOUND" ]; then
  echo "  chained crack failed; trying encKey-as-direct-passphrase..."
  while IFS= read -r EK; do
    [ -z "$EK" ] && continue
    dec "$EK" "$OUTDIR/enc.b64" "$OUTDIR/cap.bin" || continue
    if LC_ALL=C grep -aqE 'operationName|"variables"|getProfileDetails|reservationDetails|"query"' "$OUTDIR/cap.bin"; then
      echo "  *** encKey used DIRECTLY as passphrase: [$EK]"; head -c 1200 "$OUTDIR/cap.bin"; echo
      printf '%s' "$EK" > "$OUTDIR/REALKEY.txt"; cp "$OUTDIR/cap.bin" "$OUTDIR/decrypted.json"; FOUND=1; break
    fi
  done < "$OUTDIR/enckeys.txt"
fi
echo ""

echo "════════════════════════════════════════════"
if [ -n "$FOUND" ]; then
  echo "  PROTOCOL CRACKED. Keys + decrypted op saved locally (NOT committed)."
  echo "  Operation in plaintext:"
  grep -oE '"operationName":"[^"]*"|getProfileDetails|reservationDetails' "$OUTDIR/decrypted.json" 2>/dev/null | sort -u | sed 's/^/    /'
else
  echo "  Not cracked. Likely the capture's encKey differs from the current page's"
  echo "  (per-session encKey). Re-capture: in the SAME browser session, grab BOTH"
  echo "  (a) a /gateway/graphql encData AND (b) view-source the page's __NEXT_DATA__"
  echo "  'encKey' value, paste both. Or paste the JS module defining x.gp's literal."
fi
echo ""
echo "Evidence: $OUTDIR (NOT committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
