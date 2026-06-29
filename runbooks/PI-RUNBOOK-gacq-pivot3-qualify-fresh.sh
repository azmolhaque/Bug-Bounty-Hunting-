#!/usr/bin/env bash
# =============================================================================
# Google VRP — qualify the freshest acquisition candidates before investing
# Portable: Termux / Linux / Pi.
#
# Broad scan surfaced fresh, less-tested self-service hosts. Before registering
# accounts, QUALIFY them: is it a live app (real API) or a dead/static page? What
# software + version (abandoned acquisitions often run stale, CVE-bearing stacks)?
# Real signup/login forms? This decides where authenticated IDOR / CVE effort pays.
#
# Focus (freshest / lowest dup-risk first):
#   Elastifile (discontinued product, portals still up = likely under-maintained)
#   Botsociety (small acquired SaaS, least-tested, multi-tenant projects)
#   + Fitbit accounts/api + Waze beta as higher-value backups.
#
# SAFETY: read-only GET, paced, in-scope (all from official acquisitions file).
# Light exposure canaries only. No creds, no fuzzing.
#
# Run (Termux): mkdir -p $HOME/gq3; OUTDIR=$HOME/gq3 \
#   bash runbooks/PI-RUNBOOK-gacq-pivot3-qualify-fresh.sh 2>&1 | tee $HOME/gq3/gq3.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/gq3}"; export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.4}"
HOSTS="${HOSTS:-register.elastifile.com partners.elastifile.com www.elastifile.com botsociety.io app.botsociety.io accounts.fitbit.com beta.waze.com}"
echo "============================================================"
echo "QUALIFY FRESH ACQ CANDIDATES  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Read-only. Fingerprint stack/version + app/API surface + exposures."
echo "============================================================"; echo ""

for H in $HOSTS; do
  echo "════════ $H ════════"
  hdr=$(curl -s -I -L --max-redirs 5 --max-time 15 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  code=$(printf '%s' "$hdr" | awk 'toupper($1)~/^HTTP/{c=$2} END{print c+0}')
  body=$(curl -s -L --max-redirs 5 --max-time 15 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  [ -z "$body$hdr" ] && { echo "  unreachable (000)"; echo; continue; }
  # stack
  srv=$(printf '%s' "$hdr" | grep -i '^server:' | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
  xpb=$(printf '%s' "$hdr" | grep -i '^x-powered-by:' | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
  gen=$(printf '%s' "$body" | grep -oiE '<meta name="generator" content="[^"]*"' | head -1 | sed -E 's/.*content="//; s/"//')
  cms=""
  printf '%s' "$body$hdr" | grep -qiE 'wp-content|wp-json|wordpress' && cms="$cms WordPress"
  printf '%s' "$hdr"      | grep -qiE 'x-generator: *Drupal|x-drupal' && cms="$cms Drupal"
  printf '%s' "$body"     | grep -qiE 'hubspot|hs-scripts' && cms="$cms HubSpot"
  printf '%s' "$body"     | grep -qiE 'marketo|munchkin' && cms="$cms Marketo"
  printf '%s' "$body"     | grep -qiE '__next_data__' && cms="$cms Next.js"
  printf '%s' "$body"     | grep -qiE 'ng-version' && cms="$cms Angular"
  title=$(printf '%s' "$body" | grep -oiE '<title[^>]*>[^<]*' | head -1 | sed -E 's/<title[^>]*>//I' | tr -d '\r' | cut -c1-60)
  echo "  [$code] title='$title'"
  echo "  server='${srv}' x-powered-by='${xpb}' generator='${gen}' cms='${cms# }'"
  # app/API signals: forms + JS api refs
  forms=$(printf '%s' "$body" | grep -oiE '<form[^>]*action="[^"]*"' | sed -E 's/.*action="//; s/"//' | head -3 | tr '\n' ' ')
  echo "  form actions: ${forms:-none}"
  apis=$(printf '%s' "$body" | grep -oE 'https?://[a-z0-9.-]*(api|backend|app)[a-z0-9.-]*\.[a-z]+' | sort -u | head -5 | tr '\n' ' ')
  echo "  api hosts in page: ${apis:-none}"
  # WordPress/Drupal version + REST exposure (stale-software signal)
  if printf '%s' "$cms" | grep -qi wordpress; then
    wpv=$(curl -s -L --max-time 10 -H "User-Agent: $UA" "https://$H/?rest_route=/" 2>/dev/null | grep -oE '"name":"[^"]*"' | head -1)
    echo "  wp-json: $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$H/wp-json/" 2>/dev/null) ; users: $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$H/wp-json/wp/v2/users" 2>/dev/null)"
  fi
  # light exposure canaries
  for p in "/.git/config" "/.env" "/server-status" "/robots.txt" "/sitemap.xml" "/api" "/graphql" "/login" "/signup"; do
    c=$(curl -s -o /dev/null -w '%{http_code}' -L --max-redirs 2 --max-time 8 -H "User-Agent: $UA" "https://$H$p" 2>/dev/null)
    case "$c" in 200|401|403) printf "    %-16s -> %s\n" "$p" "$c";; esac
    sleep 0.2
  done
  echo ""
  sleep "$PACE"
done

echo "════════════════════════════════════════════"
echo "TRIAGE"
echo "════════════════════════════════════════════"
echo "  * Stale CMS/framework version (esp. Elastifile, abandoned) -> CVE/exposure"
echo "    path, low dup-risk. wp-json users 200 = user enumeration."
echo "  * Real 'app api hosts' + /api or /graphql 200/401 = live multi-tenant app"
echo "    -> register 2 accounts and run the IDOR test (Botsociety/Fitbit/Waze)."
echo "  * Only marketing CMS (HubSpot/Marketo) + no app api = dead end, skip."
echo "  Pick the one host with the strongest app-API or stale-software signal."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
