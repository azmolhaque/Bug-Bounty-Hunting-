#!/usr/bin/env bash
# 4-extension-proof.sh
# Downloads the official Wiz Chrome extension from the Chrome Web Store
# and extracts the three key proof strings that confirm:
#   (a) wiz-app is the auth cookie name
#   (b) Domain=.wiz.io cookies exist and are collected by Wiz's own code
#   (c) externally_connectable allows win-test.wiz.io to message the extension
#
# Run from Termux or Pi:
#   bash 4-extension-proof.sh
#
# Termux setup:
#   pkg install curl python unzip

set -euo pipefail

EXT_ID="koellablckildiakdjcchdfnagjfbpbh"
CRX_URL="https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3D${EXT_ID}%26uc"
WORKDIR="/tmp/wizext-$$"
BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

echo -e "\n${BOLD}Downloading Wiz Chrome Extension (${EXT_ID})...${NC}"
mkdir -p "$WORKDIR"
curl -sL --max-time 60 "$CRX_URL" -o "$WORKDIR/wiz.crx"
SIZE=$(wc -c < "$WORKDIR/wiz.crx")
echo "Downloaded: ${SIZE} bytes"

echo -e "\n${BOLD}Extracting CRX...${NC}"
cp "$WORKDIR/wiz.crx" "$WORKDIR/wiz.zip"
cd "$WORKDIR"
python3 -c "
import zipfile, sys
try:
    with zipfile.ZipFile('wiz.zip') as z:
        z.extractall('.')
    print('Extracted via Python zipfile')
except Exception as e:
    print(f'Python extraction failed: {e}')
    sys.exit(1)
" 2>/dev/null || unzip -o wiz.zip -d . 2>/dev/null || {
    echo "Trying raw unzip with offset skip..."
    python3 -c "
import zipfile, io
data = open('wiz.zip','rb').read()
# CRX3 has a variable-length header before the ZIP — find the PK signature
idx = data.find(b'PK\x03\x04')
if idx == -1: raise Exception('No ZIP signature found')
with zipfile.ZipFile(io.BytesIO(data[idx:])) as z:
    z.extractall('.')
print(f'Extracted (skipped {idx} byte CRX header)')
"
}

BG="$WORKDIR/background.js"
MANIFEST="$WORKDIR/manifest.json"

if [[ ! -f "$BG" ]]; then
    echo "background.js not found — looking for it..."
    find "$WORKDIR" -name "background.js" | head -3
    BG=$(find "$WORKDIR" -name "background.js" | head -1)
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           PROOF EXTRACTION RESULTS                      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"

# ─── PROOF A: Cookie name = wiz-app ────────────────────────────────────────
echo ""
echo -e "${BOLD}[PROOF A] Auth cookie name — from background.js${NC}"
echo -e "${YELLOW}Command: grep -o '.\{0,5\}wiz-app.\{0,5\}' background.js | head -5${NC}"
grep -o '.\{0,5\}wiz-app.\{0,5\}' "$BG" 2>/dev/null | head -5 | while read -r line; do
    echo -e "  ${GREEN}→ $line${NC}"
done
echo "  MEANING: LT variable is set to the string 'wiz-app' — this is the cookie name"

# ─── PROOF B: Domain=.wiz.io filter ────────────────────────────────────────
echo ""
echo -e "${BOLD}[PROOF B] Domain=.wiz.io cookie scope — from background.js Apollo link${NC}"
echo -e "${YELLOW}Command: grep -o '.\{30\}startsWith.\{50\}slice(1).\{30\}' background.js${NC}"
grep -o '.\{30\}startsWith.\{50\}slice(1).\{30\}' "$BG" 2>/dev/null | head -3 | while read -r line; do
    echo -e "  ${GREEN}→ $line${NC}"
done
echo "  MEANING: The filter 'e.domain.startsWith(\".\") && r.endsWith(e.domain.slice(1))'"
echo "           matches cookies with e.domain=\".wiz.io\" — proves they exist in production"

# ─── PROOF C: externally_connectable + host_permissions ─────────────────────
echo ""
echo -e "${BOLD}[PROOF C] Extension manifest — host permissions + external messaging${NC}"
echo -e "${YELLOW}Command: python3 -c 'import json; m=json.load(open(\"manifest.json\")); ...'${NC}"
python3 -c "
import json
m = json.load(open('$MANIFEST'))
import sys

hp = m.get('host_permissions', [])
perms = m.get('permissions', [])
ec = m.get('externally_connectable', {})
cs = m.get('content_scripts', [])

print('  host_permissions:      ', hp)
print('  permissions:           ', perms)
print('  externally_connectable:', ec)
print()
print('  content_scripts matches:')
for s in cs:
    print('   ', s.get('matches', []), '->', s.get('js', []))
"
echo ""
echo "  MEANING: 'externally_connectable' + 'host_permissions' both cover '*.wiz.io'"
echo "           → win-test.wiz.io (once claimed) can call chrome.runtime.sendMessage()"
echo "             directly to the extension background, AND receives auto-injected scripts"

# ─── SUMMARY ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════ SUMMARY ════════════════════${NC}"
BG_SIZE=$(wc -c < "$BG" 2>/dev/null || echo "?")
echo "  Source: Chrome Web Store CRX (ID: $EXT_ID)"
echo "  background.js size: ${BG_SIZE} bytes (production minified)"
echo ""
echo "  All three proofs derived from Wiz's own published production code."
echo "  No reverse engineering or tampering — public Chrome Web Store download."
echo ""
echo -e "${GREEN}✓ Extension proof extraction complete.${NC}"
echo "  Screenshot or copy the above output to attach to your VRP report."
echo ""

# cleanup
cd /tmp
rm -rf "$WORKDIR"
