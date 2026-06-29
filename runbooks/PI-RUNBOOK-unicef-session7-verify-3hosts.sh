#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — careful classification of 3 flagged user/user endpoints (session7)
# Portable: Linux / Pi / Termux.
#
# session6 safety-flagged 3 hosts (response had child/protection keywords):
#   www.unicef.org, weshare.unicef.org, lexonis.unicef.org
# Determine SAFELY whether each is:
#   (a) a real Drupal user-ACCOUNT exposure (uid/name/mail) = F001-class finding, or
#   (b) a 403/404 HTML page full of UNICEF "child" text = FALSE POSITIVE, or
#   (c) genuine beneficiary/child PII = STOP, escalate carefully.
#
# SAFETY: ONE request per endpoint, page-size 1. Prints only: HTTP code,
# content-type, JSON-or-HTML, attribute KEY NAMES (not values), whether a "mail"
# field exists + the email DOMAIN only (local part REDACTED), and meta total.
# NO full personal records printed or saved. >=1.5s/req.
#
# Run (Termux): OUTDIR=$HOME/un7 bash runbooks/PI-RUNBOOK-unicef-session7-verify-3hosts.sh \
#                 2>&1 | tee $HOME/un7/un7.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un7
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un7"
  else OUTDIR="$HOME/un7"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.6}"
echo "============================================================"
echo "UNICEF VERIFY 3 HOSTS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "SAFETY: 1 req/endpoint, field-names + email-DOMAIN only (local part redacted)"
echo "============================================================"; echo ""

classify(){ # url tag
  local url="$1" tag="$2"
  local m ct code
  m=$(curl -s -L --max-redirs 3 --max-time 18 -H "User-Agent: $UA" \
       -H 'Accept: application/vnd.api+json' -o "$OUTDIR/$tag.body" -D "$OUTDIR/$tag.hdr" \
       -w '%{http_code}|%{content_type}' "$url" 2>/dev/null) || m="000|-"
  code="${m%%|*}"; ct="${m#*|}"
  echo "  $url"
  echo "    HTTP $code | content-type: ${ct%%;*}"
  python3 - "$OUTDIR/$tag.body" << 'PYEOF'
import sys,json,re
raw=open(sys.argv[1],encoding="utf-8",errors="replace").read()
if not raw.strip(): print("    EMPTY body"); sys.exit()
# JSON?
try:
    d=json.loads(raw)
except Exception:
    # HTML -> false positive class
    is_html = raw.lstrip().lower().startswith(("<!doctype","<html")) or "<title" in raw.lower()
    print("    body is HTML/non-JSON ->", "FALSE POSITIVE (site page, not data)" if is_html else "non-JSON (inspect)")
    sys.exit()
data=d.get("data")
errs=d.get("errors")
if errs:
    print("    JSON:API errors:", [e.get("status") for e in errs][:3], "-> access-controlled, no data")
    sys.exit()
if not data:
    print("    JSON:API but data empty ->", "OMITTED leak only" if d.get("meta",{}).get("omitted") else "EMPTY")
    sys.exit()
recs = data if isinstance(data,list) else [data]
r0 = recs[0]
attrs = r0.get("attributes",{}) if isinstance(r0,dict) else {}
keys = sorted(attrs.keys())
print(f"    *** JSON:API DATA: {len(recs)} record(s) in sample")
print(f"    record type: {r0.get('type')}")
print(f"    attribute fields: {keys}")
# mail field? show DOMAIN only
mailval=None
for k in attrs:
    v=attrs[k]
    if isinstance(v,str) and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        mailval=v; mailkey=k; break
if mailval:
    dom=mailval.split("@")[1]
    print(f"    *** EMAIL FIELD '{mailkey}' PRESENT — domain only: @{dom}  (local part REDACTED)")
    print("    => USER-ACCOUNT EMAIL EXPOSURE (F001 class) — CONFIRMED on this host")
else:
    print("    no email-shaped value in attributes (may be usernames/other)")
tot=d.get("meta",{}).get("count") or d.get("meta",{}).get("total")
if tot: print(f"    meta total records: {tot}")
PYEOF
  echo ""
  sleep "$PACE"
}

echo "═══ www.unicef.org (flagship) ═══"
classify "https://www.unicef.org/jsonapi/user/user?page%5Blimit%5D=1" www_bare
classify "https://www.unicef.org/en/jsonapi/user/user?page%5Blimit%5D=1" www_en

echo "═══ weshare.unicef.org ═══"
classify "https://weshare.unicef.org/en/jsonapi/user/user?page%5Blimit%5D=1" weshare_en
classify "https://weshare.unicef.org/jsonapi/user/user?page%5Blimit%5D=1" weshare_bare

echo "═══ lexonis.unicef.org ═══"
classify "https://lexonis.unicef.org/jsonapi/user/user?page%5Blimit%5D=1" lexonis_bare
classify "https://lexonis.unicef.org/en/jsonapi/user/user?page%5Blimit%5D=1" lexonis_en

echo "════════════════════════════════════════════"
echo "READ THE RESULT"
echo "════════════════════════════════════════════"
echo "  *** EMAIL FIELD PRESENT (domain @unicef.org) on a host != ram = CONFIRMED"
echo "  valid finding (F001 class). www.unicef.org would be the flagship — high impact."
echo "  'body is HTML' = FALSE POSITIVE (site chrome matched 'child'), drop it."
echo "  If a record type/fields look like beneficiaries (not staff accounts) = STOP,"
echo "  do not pull, escalate to UNICEF carefully."
echo ""
echo "Evidence: $OUTDIR (field-names + email-domain only; no PII saved)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
