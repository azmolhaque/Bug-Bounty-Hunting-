#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session2: VERIFY session1 leads (honest triage)
# Portable: Linux / Pi / Termux.
#
# session1 raised 3 things to settle BEFORE any claim:
#   1. internal.photomath.com returned 200 on /.git/config /.env /actuator/health
#      /server-status /api/v1/namespaces — BUT its homepage is "Sign in - Google
#      Accounts" (server: ESF). Strong hypothesis: Google IAP returns the LOGIN
#      PAGE with HTTP 200 for every path => those 200s are FALSE POSITIVES.
#      DECISIVE TEST: inspect the actual bytes. A real .git/config starts with
#      "[core]"; a real .env has KEY=VALUE; the login page is HTML w/ accounts.google.
#   2. metabase / argocd / cms / portal returned 000 (no HTTP). Diagnose: dead,
#      TLS/SNI failure, or 302 -> accounts.google.com (IAP-walled, not a bug).
#   3. dpcapi-admin.photomath.{com,net} + lapi.photomath.net are LIVE (responded
#      404 at root). Light, safe API path probe for an unauth endpoint.
#
# SAFETY: read-only GET, >=0.5s/req, no exploit, no data pull. We only read enough
# bytes to classify (login page vs real file). Honest verdicts only.
#
# Run (Termux): OUTDIR=$HOME/pm2 bash runbooks/PI-RUNBOOK-photomath-session2-verify.sh \
#                 2>&1 | tee $HOME/pm2/pm2.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/pm2
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/pm2"
  else OUTDIR="$HOME/pm2"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.5}"
echo "============================================================"
echo "PHOTOMATH VERIFY  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Goal: settle session1 leads honestly. Read-only."
echo "============================================================"; echo ""

# ── 1: internal.photomath.com — login-page-vs-real-file decisive test ──
echo "═══ 1: internal.photomath.com — are the 200s REAL or the IAP login page? ═══"
IH="internal.photomath.com"
# baseline: what does a known-bogus random path return? if SAME 200 HTML => catch-all login
RAND="/zzz-$(printf '%s' "$$")-doesnotexist-$(date +%s 2>/dev/null).bogus"
for path in "$RAND" "/.git/config" "/.env" "/actuator/health" "/server-status" "/api/v1/namespaces"; do
  hdrf="$OUTDIR/ih-$(printf '%s' "$path"|tr -c 'A-Za-z0-9' '_').hdr"
  bodyf="$OUTDIR/ih-$(printf '%s' "$path"|tr -c 'A-Za-z0-9' '_').body"
  m=$(curl -s -L --max-redirs 4 --max-time 18 -H "User-Agent: $UA" \
       -o "$bodyf" -D "$hdrf" -w '%{http_code}|%{content_type}|%{size_download}|%{url_effective}' \
       "https://$IH$path" 2>/dev/null) || m="000|-|0|-"
  code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; rest="${rest#*|}"; size="${rest%%|*}"; eff="${rest##*|}"
  # classify body
  head1=$(head -c 200 "$bodyf" 2>/dev/null | tr '\n' ' ')
  cls="?"
  if printf '%s' "$head1" | grep -qiE '^\s*\[core\]|repositoryformatversion'; then cls="*** REAL .git/config"; fi
  if printf '%s' "$head1" | grep -qE '^[A-Z_][A-Z0-9_]*='; then cls="*** REAL .env (KEY=VALUE)"; fi
  if printf '%s' "$head1" | grep -qiE '<!doctype|<html|accounts\.google|Sign in'; then cls="HTML login/site page (FALSE POSITIVE)"; fi
  if printf '%s' "$head1" | grep -qiE '"status"\s*:\s*"UP"|UP'; then [ "$cls" = "?" ] && cls="actuator-ish JSON? inspect"; fi
  echo "  $path"
  echo "    HTTP $code | ct=${ct%%;*} | size=$size | final=${eff##*photomath.com}"
  echo "    class: $cls"
  echo "    first bytes: ${head1:0:120}"
  sleep "$PACE"
done
echo ""
echo "  VERDICT LOGIC: if the random bogus path ALSO returns 200 HTML identical to"
echo "  /.git/config, every 200 is the IAP/login catch-all => FALSE POSITIVE, drop."
echo "  Only a body starting [core] / KEY=VALUE is a real leak."
echo ""

# ── 2: diagnose the 000 hosts (IAP redirect vs dead) ──
echo "═══ 2: why did these return 000? (IAP-wall vs dead vs TLS) ═══"
diag(){ # host
  local H="$1" m code ct eff redir
  m=$(curl -s -L --max-redirs 5 --max-time 18 -H "User-Agent: $UA" \
       -o /dev/null -D "$OUTDIR/diag-$H.hdr" \
       -w '%{http_code}|%{content_type}|%{url_effective}|%{num_redirects}' \
       "https://$H/" 2>/dev/null) || m="000|-|-|0"
  code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; rest="${rest#*|}"; eff="${rest%%|*}"; redir="${rest##*|}"
  # also try without -L to see the first-hop Location
  loc=$(curl -s -I --max-time 12 -H "User-Agent: $UA" "https://$H/" 2>/dev/null | grep -i '^location:' | head -1 | tr -d '\r')
  case "$eff" in
    *accounts.google.com*) tag="IAP-WALLED (redirects to Google login) — not a bug, skip";;
    *) tag="";;
  esac
  echo "  $H -> HTTP $code  redirects=$redir  final=${eff}"
  [ -n "$loc" ] && echo "      first-hop $loc"
  [ -n "$tag" ] && echo "      => $tag"
  sleep "$PACE"
}
for H in metabase.photomath.net argocd-gke-app-us-prod.photomath.net \
         argocd-gke-app-eu-prod.photomath.net argocd-dwh-eu-dev.photomath.net \
         cms.photomath.net portal.photomath.net idp.photomath.net \
         dpcapi.photomath.net baja.photomath.net cuvar.photomath.net \
         mankey.photomath.net zuja.photomath.net; do
  diag "$H"
done
echo ""

# ── 3: light probe of the genuinely-live API hosts ──
echo "═══ 3: LIVE non-IAP API hosts — safe path probe ═══"
probe_host(){ # host
  local H="$1"
  echo "  --- $H ---"
  for p in "/" "/health" "/healthz" "/status" "/version" "/api" "/v1" "/api/v1" \
           "/swagger" "/swagger-ui.html" "/openapi.json" "/v3/api-docs" \
           "/actuator" "/actuator/health" "/metrics" "/.well-known/security.txt"; do
    m=$(curl -s -L --max-redirs 3 --max-time 12 -H "User-Agent: $UA" \
         -o "$OUTDIR/probe.tmp" -w '%{http_code}|%{content_type}|%{size_download}' "https://$H$p" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
      snippet=$(head -c 120 "$OUTDIR/probe.tmp" 2>/dev/null | tr '\n' ' ')
      echo "    [$code] $p  ct=${ct%%;*} size=$size :: ${snippet:0:90}"
    fi
    sleep 0.3
  done
}
for H in dpcapi-admin.photomath.com dpcapi-admin.photomath.net lapi.photomath.net tlapi.photomath.net; do
  probe_host "$H"
done
echo "  (404/000 suppressed; any 200/401/403 with a real app body = follow up)"
echo ""

echo "════════════════════════════════════════════"
echo "HONEST VERDICT CHECKLIST"
echo "════════════════════════════════════════════"
echo "  [1] internal.photomath.com 200s: REAL leak ONLY if a body starts [core] or"
echo "      KEY=VALUE. If all are HTML/login (incl. the bogus path), it's the IAP"
echo "      catch-all — drop it, do NOT report (would be closed as N/A)."
echo "  [2] 000 hosts redirecting to accounts.google.com = IAP-walled. Unauth dead-end."
echo "  [3] dpcapi/lapi: any unauth 200 JSON API / swagger = real surface to pursue."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
