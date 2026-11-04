#!/usr/bin/env bash
# =============================================================================
# Marriott — bilt.marriott.com Laravel attack-surface probe (session35)
# Portable: Linux / Pi / Termux.
#
# Confirmed: bilt.marriott.com is a Laravel app (XSRF-TOKEN + encrypted
# marriott_bilt_partnership_session cookies, Apache, AWS ALB). Client side is
# pure marketing (no API). The real surface is the Laravel framework:
#   - CVE-2021-3129  Ignition unauth RCE when APP_DEBUG=true (Critical)
#   - debug-mode error pages leaking stack traces / env / APP_KEY
#   - Telescope / Horizon / Debugbar dashboards
#   - /.env, storage logs
#
# DETECTION ONLY. We probe for the VULNERABLE CONDITION (Ignition present +
# debug on + dashboards exposed). We do NOT run the execute-solution RCE chain
# (no destructive payloads — detection is sufficient to report responsibly).
#
# SAFETY: bilt.marriott.com explicitly in-scope. Read-only GET + one benign POST
# to /_ignition/health-check (a documented health endpoint, not an exploit).
# No code execution, no writes, no file deletion. X-Bug-Bounty header. Record IP.
#
# Run (Termux): OUTDIR=$HOME/s35 bash runbooks/PI-RUNBOOK-session35-bilt-laravel.sh \
#                 2>&1 | tee $HOME/s35/s35.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s35
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s35"
  else OUTDIR="$HOME/s35"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="bilt.marriott.com"; B="https://$T"

echo "============================================================"
echo "BILT LARAVEL PROBE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

geta() { # METHOD PATH TAG [extra-curl-args...]
  local method="$1" path="$2" tag="$3"; shift 3
  local m
  m=$(curl -s -X "$method" -o "$OUTDIR/$tag.txt" -D "$OUTDIR/$tag.hdr" \
       -H "User-Agent: $UA" -H "$IDH" "$@" --max-time 20 \
       -w '%{http_code}|%{size_download}|%{content_type}' "$B$path" 2>/dev/null) || m="000|0|-"
  echo "$m"
}
show() { # tag path label
  local tag="$1" path="$2" label="$3"
  local m="$4" code="${4%%|*}" rest="${4#*|}" size="${4%%|*}"
  size="$(echo "$4"|cut -d'|' -f2)"; ct="$(echo "$4"|cut -d'|' -f3)"
  printf '  [%-3s %7sB %-22s] %-34s %s\n' "$code" "$size" "${ct%%;*}" "$path" "$label"
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: IGNITION / CVE-2021-3129 DETECTION ═══"
# health-check is a benign Ignition endpoint; presence => Ignition installed.
m=$(geta GET  "/_ignition/health-check" ign-hc); show ign-hc "/_ignition/health-check" "GET" "$m"
echo "    body: $(head -c 200 "$OUTDIR/ign-hc.txt" | tr '\n' ' ')"
m=$(geta POST "/_ignition/health-check" ign-hc-p -H 'Accept: application/json'); show ign-hc-p "/_ignition/health-check" "POST" "$m"
echo "    body: $(head -c 200 "$OUTDIR/ign-hc-p.txt" | tr '\n' ' ')"
# execute-solution: GET it ONLY to fingerprint existence (405/422 = present, NOT exploited)
m=$(geta GET "/_ignition/execute-solution" ign-exec); show ign-exec "/_ignition/execute-solution" "GET (fingerprint only)" "$m"
echo "    body: $(head -c 160 "$OUTDIR/ign-exec.txt" | tr '\n' ' ')"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: DEBUG-MODE / STACK-TRACE LEAK ═══"
# Trigger a benign framework error and see if APP_DEBUG=true leaks a stack trace.
# %00 / malformed route param commonly yields a 500 Whoops page when debug is on.
m=$(geta GET "/en-us/%ff%fe" dbg1); show dbg1 "/en-us/%ff%fe" "malformed path" "$m"
m=$(geta POST "/en-us" dbg2 -H 'Content-Type: application/json' --data '{"x":'); show dbg2 "/en-us (bad JSON POST)" "419/500?" "$m"
for t in dbg1 dbg2; do
  if grep -qiE 'Whoops|Ignition|Illuminate\\|vendor/laravel|APP_KEY|stack trace|Symfony\\Component' "$OUTDIR/$t.txt" 2>/dev/null; then
    echo "    *** DEBUG MODE LEAK in $t — stack trace / framework internals exposed:"
    grep -oiE '(APP_KEY[^"<]{0,60}|/var/www[^"< ]{0,60}|Illuminate\\[A-Za-z\\]{0,40}|vendor/laravel/framework[^"< ]{0,40})' "$OUTDIR/$t.txt" 2>/dev/null | sort -u | head -10 | sed 's/^/        /'
  fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: DEBUG DASHBOARDS + SENSITIVE FILES ═══"
for P in \
  /telescope /telescope/requests "/telescope-api/requests" \
  /horizon /horizon/api/stats /horizon/api/workload \
  /_debugbar/open "/_debugbar/assets/javascript" \
  /.env /.env.example /.env.backup /storage/logs/laravel.log \
  /vendor/composer/installed.json /composer.json /composer.lock \
  /phpinfo.php /info.php /web.config /server-status \
  /api/documentation /docs /log-viewer ; do
  tag="c-$(echo "$P"|tr -c 'A-Za-z0-9' '-')"
  m=$(geta GET "$P" "$tag")
  code="$(echo "$m"|cut -d'|' -f1)"; size="$(echo "$m"|cut -d'|' -f2)"; ct="$(echo "$m"|cut -d'|' -f3)"
  case "$code" in
    404|000|301|302) ;;  # silent
    403) printf '    [403 %sB] %s\n' "$size" "$P";;
    *)   printf '    *** [%s %sB %s] %s\n' "$code" "$size" "${ct%%;*}" "$P"
         head -c 180 "$OUTDIR/$tag.txt" | tr '\n' ' '; echo;;
  esac
  sleep 0.3
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os
O=os.environ["OUTDIR"]
def body(t):
    p=os.path.join(O,t+".txt"); return open(p,encoding="utf-8",errors="replace").read() if os.path.exists(p) else ""
def code(t):
    p=os.path.join(O,t+".hdr");
    if not os.path.exists(p): return "---"
    first=open(p,encoding="utf-8",errors="replace").readline()
    return first.split()[1] if len(first.split())>1 else "?"
ign = ('can_execute' in body('ign-hc')) or ('can_execute' in body('ign-hc-p')) or (code('ign-exec') in ('405','422','500'))
dbg = any(s in (body('dbg1')+body('dbg2')) for s in ('Whoops','Ignition','Illuminate\\','APP_KEY','vendor/laravel'))
print(f"  Ignition present (CVE-2021-3129 surface): {'YES — investigate version/debug' if ign else 'no/!detected'}")
print(f"  Debug mode leaking internals            : {'YES — sensitive info disclosure' if dbg else 'no'}")
print()
if ign and dbg:
    print("  >>> HIGH/CRITICAL: Ignition + debug mode. CVE-2021-3129 likely exploitable.")
    print("  >>> DO NOT run execute-solution (RCE). Document detection: health-check")
    print("  >>> response + debug stack trace. Report as Critical with safe PoC.")
elif dbg:
    print("  >>> HIGH: APP_DEBUG=true exposes stack traces/env. Capture the leaked")
    print("  >>> APP_KEY / DB creds shown in the error page = the finding.")
elif ign:
    print("  >>> Ignition endpoint present but debug not confirmed. Check version for")
    print("  >>> CVE-2021-3129 applicability; debug may be togglable via header.")
else:
    print("  >>> No Ignition/debug surface. Check Phase C dashboards/files above.")
    print("  >>> If all clean, bilt is hardened -> next backup target (mds/ifast/micmt).")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
