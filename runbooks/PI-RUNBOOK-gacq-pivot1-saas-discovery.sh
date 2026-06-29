#!/usr/bin/env bash
# =============================================================================
# Google VRP — pivot: discover SELF-SERVICE web apps among in-scope acquisitions
# Portable: Termux / Linux / Pi.
#
# Photomath external surface exhausted (hardened gRPC, no unauth bug). Pivot to a
# self-service multi-tenant WEB app where authenticated IDOR/tenant-isolation
# testing needs only a browser + curl. This scans candidate in-scope acquisition
# hosts and flags which offer PUBLIC EMAIL SIGNUP (self-service) vs enterprise
# "contact sales" gates, and which look like real SaaS apps (SPA/login/dashboard)
# = the best IDOR targets. Ranks them so we pick on evidence.
#
# SAFETY: read-only GET, >=0.4s/req, scope-checked (skip anything not IN-SCOPE).
# No account creation here — just fingerprint the signup surface.
#
# Run (Termux): mkdir -p $HOME/gq1; OUTDIR=$HOME/gq1 \
#   bash runbooks/PI-RUNBOOK-gacq-pivot1-saas-discovery.sh 2>&1 | tee $HOME/gq1/gq1.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/gq1}"; export OUTDIR; mkdir -p "$OUTDIR"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK=""
for c in "./scripts/scope-check.sh" "$SD/../scripts/scope-check.sh" "$HOME/bbh/scripts/scope-check.sh"; do
  [ -f "$c" ] && { SCOPE_CHECK="$c"; break; }
done
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.4}"
echo "============================================================"
echo "GOOGLE ACQ — SELF-SERVICE SaaS DISCOVERY  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "scope-check: ${SCOPE_CHECK:-NONE}   pace: ${PACE}s/req   read-only"
echo "============================================================"; echo ""

CANDIDATES="
app.dataform.co
www.dataform.co
cloud.virustotal.com
www.virustotal.com
developers.virustotal.com
accounts.fitbit.com
www.fitbit.com
developer.fitbit.com
www.socratic.com
my.neverware.com
www.waze.com
app.alooma.com
accounts.nest.com
home.nest.com
www.breezometer.com
developers.breezometer.com
www.cameyo.com
online.cameyo.com
portal.isolabs.ai
www.appsheet.com
"

probe(){ # host
  local H="$1"
  if [ -n "$SCOPE_CHECK" ]; then
    case "$(bash "$SCOPE_CHECK" --program google "$H" 2>/dev/null)" in
      *IN-SCOPE*) : ;; *) echo "  skip(oos) $H"; return;; esac
  fi
  local body code ct eff
  body=$(curl -s -L --max-redirs 5 --max-time 18 -H "User-Agent: $UA" \
         -D "$OUTDIR/h.tmp" -o "$OUTDIR/b.tmp" \
         -w '%{http_code}|%{content_type}|%{url_effective}' "https://$H/" 2>/dev/null) || body="000|-|-"
  code="${body%%|*}"; rest="${body#*|}"; ct="${rest%%|*}"; eff="${rest##*|}"
  [ "$code" = "000" ] && { echo "  [000] $H (unreachable)"; return; }
  local b; b=$(tr 'A-Z' 'a-z' < "$OUTDIR/b.tmp" 2>/dev/null)
  local title; title=$(grep -oiE '<title[^>]*>[^<]*' "$OUTDIR/b.tmp" 2>/dev/null | head -1 | sed -E 's/<title[^>]*>//I' | tr -d '\r' | cut -c1-50)
  # signals
  local signup="" login="" spa="" salesgate="" oauth=""
  printf '%s' "$b" | grep -qE 'sign ?up|create (an )?account|get started free|register|/signup|/register|/join|create your account' && signup="SIGNUP"
  printf '%s' "$b" | grep -qE 'sign ?in|log ?in|/login|/signin' && login="login"
  printf '%s' "$b" | grep -qE '__next_data__|ng-version|react|__nuxt|window\.__|data-reactroot|id="root"|id="app"' && spa="SPA"
  printf '%s' "$b" | grep -qE 'contact sales|request a demo|talk to (sales|us)|book a demo|get a quote' && salesgate="SALES-GATE"
  printf '%s' "$b$eff" | grep -qE 'accounts.google.com|oauth|openid|sso' && oauth="oauth/sso"
  # score: self-service signup + SPA = best IDOR target
  local score=0
  [ -n "$signup" ] && score=$((score+3))
  [ -n "$login" ] && score=$((score+1))
  [ -n "$spa" ] && score=$((score+2))
  [ -n "$salesgate" ] && [ -z "$signup" ] && score=$((score-2))
  printf '  [%s] %-28s score=%-2s %s %s %s %s %s  title="%s"\n' \
    "$code" "$H" "$score" "${signup:-—}" "${login:+login}" "${spa:+SPA}" "${oauth:+oauth}" "${salesgate:+SALES}" "$title"
  echo "$score|$H|$code|$signup|$login|$spa|$salesgate|$eff" >> "$OUTDIR/rank.txt"
  sleep "$PACE"
}

echo "═══ PROBE CANDIDATES ═══"
for H in $CANDIDATES; do probe "$H"; done
echo ""

echo "════════════════════════════════════════════"
echo "RANKED (self-service signup + SPA = best IDOR target)"
echo "════════════════════════════════════════════"
sort -t'|' -k1 -rn "$OUTDIR/rank.txt" 2>/dev/null | head -12 | while IFS='|' read -r sc h code su lo spa sg eff; do
  printf "  score %-2s  %-28s  %s%s%s%s\n" "$sc" "$h" "${su:+[signup] }" "${spa:+[SPA] }" "${lo:+[login] }" "${sg:+[sales-gate] }"
done
echo ""
echo "  TOP target = highest score with [signup] (public self-service). Next session:"
echo "  register a free test account there, capture the session/token, enumerate its"
echo "  object-id endpoints, and test cross-account reads (IDOR/BOLA) + tenant"
echo "  isolation — all with our own two test accounts. No real-user data."
echo ""
echo "Evidence: $OUTDIR/rank.txt"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
