#!/usr/bin/env bash
# =============================================================================
# M024 — PingAccess gateway: fingerprint + mapped context-root discovery (s30)
# Portable: Linux / Pi / Termux.
#
# S29 revealed the real stack: Akamai -> PingAccess (PR_INFORMATION header,
# {"code":"404","reason":"Not Found"} JSON). Reaching PingAccess requires
# `Accept: application/json` (HTML requests get Akamai's static 261B 404).
# Every SAP path = PingAccess-404 (unmapped). This is a PingAccess hunt now.
#
# Goal: find ONE mapped application context root (anything that is NOT the
# unmapped PingAccess 404). A mapped resource returns 401/403/302(login)/200 or
# a DIFFERENT body/size. That is the prerequisite for the real prize — a
# PingAccess access-control bypass (next session, conditional on a hit here).
#
# Decision rule: if NOTHING maps, M024 has no discoverable unauth surface from
# this position -> pivot to M004 (franchise app, confirmed reachable code).
#
# SAFETY: IN-SCOPE (gateway*.marriott.com). Read-only GET. No redirects followed.
# X-Bug-Bounty header. Accept: application/json (required to reach gateway).
# Curated ~70 paths, 0.5s pacing — not mass fuzzing.
#
# Run (Termux): OUTDIR=$HOME/s30 bash runbooks/PI-RUNBOOK-session30-pingaccess-roots.sh \
#                 2>&1 | tee $HOME/s30/s30.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s30
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s30"
  else OUTDIR="$HOME/s30"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

HOST="gatewaydsapuat2.marriott.com"
BASE="https://$HOST"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'

echo "============================================================"
echo "M024 PINGACCESS ROOTS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Host: $HOST   IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# Baseline unmapped fingerprint to diff against (code|size|body-hash-ish)
BASELINE_BODY='{"code":"404","reason":"Not Found"}'

probe() {
  local path="$1" tag="$2"
  local out="$OUTDIR/$tag.txt" hdr="$OUTDIR/$tag.hdr" m
  m=$(curl -s -o "$out" -D "$hdr" \
        -H "User-Agent: $UA" -H "$IDH" -H 'Accept: application/json' \
        --max-time 15 \
        -w '%{http_code} %{size_download}' "$BASE$path" 2>/dev/null) || m="000 0"
  local code="${m% *}" size="${m#* }"
  local body; body=$(cat "$out" 2>/dev/null)
  echo "$code $size" > "$OUTDIR/$tag.meta"
  # "INTERESTING" = not the unmapped PingAccess 404 and not Akamai 261B
  if [ "$code" = "404" ] && { [ "$size" = "35" ] || [ "$body" = "$BASELINE_BODY" ]; }; then
    : # unmapped, silent unless verbose
    [ -n "${VERBOSE:-}" ] && printf '  [404 unmapped] %s\n' "$path"
  elif [ "$code" = "404" ] && [ "$size" = "261" ]; then
    [ -n "${VERBOSE:-}" ] && printf '  [404 akamai  ] %s\n' "$path"
  else
    printf '  *** [%-3s %6sB] %-44s\n' "$code" "$size" "$path"
    local server loc auth
    server=$(grep -i '^server:' "$hdr" 2>/dev/null|head -1|tr -d '\r'|cut -d' ' -f2-||true)
    loc=$(grep -i '^location:' "$hdr" 2>/dev/null|head -1|tr -d '\r'|cut -d' ' -f2-||true)
    auth=$(grep -i '^www-authenticate:' "$hdr" 2>/dev/null|head -1|tr -d '\r'||true)
    [ -n "$server" ] && printf '        Server=%s\n' "$server"
    [ -n "$loc" ] && printf '        Location=%s\n' "$loc"
    [ -n "$auth" ] && printf '        %s\n' "$auth"
    printf '        body: %s\n' "$(head -c 160 "$out")"
  fi
  sleep 0.5
}

echo "═══ PHASE A: PINGACCESS FINGERPRINT ═══"
for p in \
  "/pa/heartbeat.ping" "/pa/heartbeat" "/pa/oidc/logout" "/pa/oidc/cb" \
  "/pa/" "/pa/templates/" "/pa-admin-api/v3/api-docs" \
  "/.well-known/openid-configuration" "/pf/heartbeat.ping" ; do
  tag="a-$(echo "$p"|tr -c 'A-Za-z0-9' '-')"
  VERBOSE=1 probe "$p" "$tag"
done
echo ""

echo "═══ PHASE B: CONTEXT-ROOT DISCOVERY (mapped applications) ═══"
echo "(only non-unmapped responses print; PingAccess 404 = unmapped, suppressed)"
ROOTS="
api api/v1 api/v2 api/v3 rest restapi services service svc gateway gw app apps
web mobile public internal external v1 v2 v3 odata odata/v2 odata/v4 soap ws wcf
auth oauth oauth2 oidc token sso saml login signin identity um user users
health healthz status ping metrics actuator info version
mi mi-account miaccount phoenix bonvoy loyalty rewards member members customer
customers profile reservation reservations property properties rate rates
booking bookings partner partners franchise franchisee owner owners commission
commissions payment payments invoice invoices vendor supplier tax finance fi
dsap ds dsp sap-gw hybris commerce content cms portal data dataservices
b2b b2c eai esb integration proxy"
COUNT=0; HITS=0
for R in $ROOTS; do
  COUNT=$((COUNT+1))
  tag="b-$(echo "$R"|tr -c 'A-Za-z0-9' '-')"
  before=$(ls "$OUTDIR"/*.hit 2>/dev/null | wc -l || echo 0)
  probe "/$R/" "$tag"
  # mark a hit-file if interesting (re-read meta)
  read -r c s < "$OUTDIR/$tag.meta"
  if ! { [ "$c" = "404" ] && { [ "$s" = "35" ] || [ "$s" = "261" ]; }; } && [ "$c" != "000" ]; then
    echo "$c $s /$R/" > "$OUTDIR/$tag.hit"; HITS=$((HITS+1))
  fi
done
echo "  scanned $COUNT roots"
echo ""

echo "═══ PHASE C: VERB + TRAILING-VARIANT on any HIT root ═══"
if ls "$OUTDIR"/*.hit >/dev/null 2>&1; then
  for hf in "$OUTDIR"/*.hit; do
    read -r c s path < "$hf"
    base="${path%/}"
    echo "  Hit: $path ($c/$s) — testing variants:"
    for v in "$base" "$base/" "${base}/index" "${base}/v1/" "${base}/api/"; do
      tag="c-$(echo "$v"|tr -c 'A-Za-z0-9' '-')"
      probe "$v" "$tag"
    done
  done
else
  echo "  no mapped roots found — nothing to vary."
fi
echo ""

echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os, glob
O=os.environ["OUTDIR"]
hits=[]
for hf in glob.glob(os.path.join(O,"*.hit")):
    hits.append(open(hf).read().strip())
# also collect fingerprint phase non-404s
fp=[]
for m in glob.glob(os.path.join(O,"a-*.meta")):
    c,s=open(m).read().split()
    if c not in ("404","000"):
        fp.append((os.path.basename(m)[:-5],c,s))

clusters={}
for m in glob.glob(os.path.join(O,"*.meta")):
    c,s=open(m).read().split(); clusters[(c,s)]=clusters.get((c,s),0)+1
print("Response clusters:")
for (c,s),n in sorted(clusters.items(),key=lambda x:-x[1]):
    print(f"  {c}/{s}B  x{n}")
print()
if fp:
    print("PingAccess fingerprint hits:")
    for t,c,s in fp: print(f"  * {t}: {c}/{s}B")
    print()
if hits:
    print(">>> MAPPED CONTEXT ROOT(S) FOUND — PURSUE:")
    for h in hits: print("   ", h)
    print(">>> Next: PingAccess access-control bypass on these (path normalization,")
    print(">>> matrix-param, encoded traversal) to reach protected backend unauth.")
else:
    print(">>> NO mapped context root and no PingAccess fingerprint leak.")
    print(">>> M024 gateway exposes no unauth surface from this position.")
    print(">>> RECOMMENDATION: pivot to M004 (marriottfranchisetransactions) — we")
    print(">>> already have a CONFIRMED reachable auth-bypass there to convert to data.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
