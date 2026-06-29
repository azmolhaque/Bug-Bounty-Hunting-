#!/usr/bin/env bash
# =============================================================================
# Google VRP — Nest recon (escalation path; no APK patching needed)
# Portable: Termux / Linux / Pi.
#
# Photomath-auth blocked on-device (ARM can't patch APK). Nest is a browser-
# reachable consumer multi-tenant app: homes ("structures") shared with family
# members + devices -> a real home/family-SHARING IDOR surface (can a removed/
# limited member still read or control devices? can A access B's structure id?).
# First: is the Nest web app still LIVE, or migrated to Google Home (like Fitbit's
# dashboard / Waze Ads)? This recon decides if Nest is viable before we invest.
#
# Maps liveness/migration status + the structures/members/devices API surface.
# SAFETY: read-only GET, paced, scope-checked. No account actions here.
#
# Run (Termux): mkdir -p $HOME/nest1; OUTDIR=$HOME/nest1 \
#   bash runbooks/PI-RUNBOOK-nest-session1-recon.sh 2>&1 | tee $HOME/nest1/nest1.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/nest1}"; export OUTDIR; mkdir -p "$OUTDIR"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK=""
for c in "./scripts/scope-check.sh" "$SD/../scripts/scope-check.sh" "$HOME/bbh/scripts/scope-check.sh"; do
  [ -f "$c" ] && { SCOPE_CHECK="$c"; break; }
done
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.5}"
echo "============================================================"
echo "NEST RECON  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Is the Nest web app live or migrated? Map the sharing/API surface. Read-only."
echo "============================================================"; echo ""
inscope(){ [ -z "$SCOPE_CHECK" ] && return 0; case "$(bash "$SCOPE_CHECK" --program google "$1" 2>/dev/null)" in *IN-SCOPE*) return 0;; *) return 1;; esac; }

HOSTS="home.nest.com api.home.nest.com accounts.nest.com myaccount.nest.com nest.com
beta.home.nest.com developer-api.nest.com community.nest.com nssbridge.nest.com"

echo "═══ A: LIVENESS + MIGRATION CHECK ═══"
for H in $HOSTS; do
  inscope "$H" || { echo "  skip(oos) $H"; continue; }
  m=$(curl -s -L --max-redirs 5 --max-time 15 -H "User-Agent: $UA" -o "$OUTDIR/b.tmp" \
       -w '%{http_code}|%{url_effective}' "https://$H/" 2>/dev/null) || m="000|-"
  code="${m%%|*}"; eff="${m##*|}"
  title=$(grep -oiE '<title[^>]*>[^<]*' "$OUTDIR/b.tmp" 2>/dev/null | head -1 | sed -E 's/<title[^>]*>//I' | tr -d '\r' | cut -c1-46)
  b=$(tr 'A-Z' 'a-z' < "$OUTDIR/b.tmp" 2>/dev/null)
  mig=""; printf '%s' "$b$eff" | grep -qE 'home.google.com|google home app|migrate|moved to google|home.nest.com.*deprecat' && mig="[MIGRATED->GoogleHome?]"
  app=""; printf '%s' "$b" | grep -qE '__next_data__|ng-version|id="root"|window\.__|react' && app="[SPA]"
  echo "  [$code] $H -> ${eff#https://} ${app}${mig} '$title'"
  sleep "$PACE"
done
echo ""

echo "═══ B: API surface — structures/members/devices (unauth = expect 401) ═══"
for H in api.home.nest.com home.nest.com; do
  inscope "$H" || continue
  for p in "/" "/api" "/v1" "/v2" "/api/0.1/user" "/session" "/structures" "/devices" \
           "/api/v1/structures" "/put" "/subscribe"; do
    c=$(curl -s -o "$OUTDIR/r.tmp" -w '%{http_code}' -L --max-redirs 2 --max-time 10 -H "User-Agent: $UA" "https://$H$p" 2>/dev/null)
    case "$c" in
      404|000) : ;;
      *) snip=$(head -c 100 "$OUTDIR/r.tmp" | tr '\n\r' '  ')
         echo "  [$c] $H$p :: ${snip:0:80}";;
    esac
    sleep 0.3
  done
done
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
echo "  * If home.nest.com is a LIVE SPA with a session/structures API (401 unauth)"
echo "    -> viable: register, create a home, invite/remove a 2nd account, test if"
echo "    the removed member retains device access (sharing-revocation IDOR), or if"
echo "    A can read B's structure id. THIS is the high-value Nest bug class."
echo "  * If it redirects to home.google.com / 'use the Google Home app' -> MIGRATED"
echo "    (like Fitbit/Waze) = dead web surface; report back and we reassess."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
