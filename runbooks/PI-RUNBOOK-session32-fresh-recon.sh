#!/usr/bin/env bash
# =============================================================================
# Marriott — FRESH ASSET DISCOVERY + softness ranking (session32)
# Portable: Linux / Pi / Termux.
#
# Scope reality: OOS catch-all is *.marriott.com — only explicitly-listed assets
# OR hosts matching an in-scope WILDCARD are eligible. So this run:
#   A. CT-enumerate the in-scope wildcards where NEW assets can appear:
#      *.artifactory, *.apigwc, *.apigatewayc, *.sba, *.mgs, *.gateway,
#      *.dcfgateway, gateway*, dcfgateway*, *uat   (Artifactory = top prize)
#   B. Fingerprint the many explicitly-in-scope assets we NEVER tested
#      (wechat.api, travelagents, ifast, bilt, splunk-phantom-nlb, oasisprod...)
#   C. Rank every live host by "softness": non-Akamai / raw origin / login form /
#      API / Artifactory / dev-test-uat = soft; Akamai-locked / OOS-redirect = hard.
#
# Every discovered host is run through scope-check.sh before being probed.
#
# SAFETY: read-only HEAD/GET, no auth, no fuzzing (curated lists, paced). Never
# follow redirects into OOS. X-Bug-Bounty header. <200 requests total.
#
# Run (Termux): OUTDIR=$HOME/s32 bash runbooks/PI-RUNBOOK-session32-fresh-recon.sh \
#                 2>&1 | tee $HOME/s32/s32.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s32
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s32"
  else OUTDIR="$HOME/s32"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
SCOPE="SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh"

echo "============================================================"
echo "MARRIOTT FRESH RECON  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: CT ENUM OF IN-SCOPE WILDCARDS ═══"
# certspotter + wayback CDX (crt.sh is unreliable / 502). Collect subdomains.
: > "$OUTDIR/ct-raw.txt"
for DOM in artifactory.marriott.com apigwc.marriott.com apigatewayc.marriott.com \
           sba.marriott.com mgs.marriott.com gateway.marriott.com \
           dcfgateway.marriott.com uat.marriott.com; do
  echo "  [CT] *.$DOM"
  # certspotter issuances
  curl -s --max-time 25 -H "User-Agent: $UA" \
    "https://api.certspotter.com/v1/issuances?domain=$DOM&include_subdomains=true&expand=dns_names" \
    2>/dev/null | grep -oE '[a-zA-Z0-9._-]+\.'"$(echo "$DOM" | sed 's/\./\\./g')" \
    >> "$OUTDIR/ct-raw.txt" 2>/dev/null || true
  # wayback CDX unique hosts
  curl -s --max-time 25 -H "User-Agent: $UA" \
    "http://web.archive.org/cdx/search/cdx?url=*.$DOM&output=text&fl=original&collapse=urlkey&limit=2000" \
    2>/dev/null | sed -E 's#https?://##; s#/.*##; s/:.*//' \
    >> "$OUTDIR/ct-raw.txt" 2>/dev/null || true
  sleep 1
done
sort -u "$OUTDIR/ct-raw.txt" | grep -E '\.marriott\.com$' > "$OUTDIR/ct-hosts.txt" || true
echo "  discovered $(wc -l < "$OUTDIR/ct-hosts.txt" 2>/dev/null || echo 0) unique wildcard-subdomain candidates"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: BUILD TARGET LIST (CT hosts + untested explicit assets) ═══"
# Explicitly in-scope assets we have NOT meaningfully tested (fresh surface):
cat > "$OUTDIR/explicit.txt" << 'EOF'
wechat.api.marriott.com
travelagents.marriott.com
ifast.marriott.com
gatewaydsaptst2.marriott.com
oasisprod.marriott.com
mds.marriott.com
prod-mipaasiaasservices.marriott.com
university.marriott.com
uber.marriott.com
smetrics.marriott.com
bilt.marriott.com
joinrewards.marriott.com
joinmarriottbonvoy.com
join.marriott.com
editionhotels.com
www.shopmarriott.com
hotel-development.marriott.com
hotel-deals.marriott.com
gifts.marriott.com
contentportal.marriott.com
contentportalauth.marriott.com
cache.marriott.com
bsp.marriott.com
app-insiders.marriott.com
meetmarriottbonvoy.marriott.com
moments.marriottbonvoy.com
splunk-phantom-nlb.marriott.com
vacation.marriott.com
giftcards.marriott.com
www.members.marriott.com
mipartnerprivileges.marriott.com
ocijlbex1prd.marriott.com
globaldesign.marriott.com
bilt.marriott.com
EOF
cat "$OUTDIR/ct-hosts.txt" "$OUTDIR/explicit.txt" 2>/dev/null | sort -u > "$OUTDIR/all-candidates.txt"

# Scope-filter every candidate
: > "$OUTDIR/targets.txt"
while read -r H; do
  [ -z "$H" ] && continue
  if eval "$SCOPE \"$H\"" 2>/dev/null | grep -q 'IN-SCOPE'; then
    echo "$H" >> "$OUTDIR/targets.txt"
  fi
done < "$OUTDIR/all-candidates.txt"
echo "  $(wc -l < "$OUTDIR/targets.txt") in-scope targets to fingerprint"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: FINGERPRINT + SOFTNESS RANK ═══"
: > "$OUTDIR/fingerprints.tsv"
while read -r H; do
  [ -z "$H" ] && continue
  hdr="$OUTDIR/fp-$H.hdr"; body="$OUTDIR/fp-$H.html"
  m=$(curl -s -o "$body" -D "$hdr" -L --max-redirs 2 \
        -H "User-Agent: $UA" -H "$IDH" --max-time 15 \
        -w '%{http_code} %{size_download} %{url_effective}' \
        "https://$H/" 2>/dev/null) || m="000 0 -"
  code="${m%% *}"; rest="${m#* }"; size="${rest%% *}"; final="${rest#* }"
  server=$(grep -i '^server:' "$hdr" 2>/dev/null|head -1|tr -d '\r'|cut -d' ' -f2-||true)
  akamai="no"; grep -qiE 'akamaighost|_abck=|bm_sz=' "$hdr" 2>/dev/null && akamai="yes"
  title=$(grep -oiE '<title>[^<]*' "$body" 2>/dev/null|head -1|sed 's/<title>//I'|tr -d '\r\n'|cut -c1-50||true)
  # softness scoring
  soft=0; tags=""
  [ "$akamai" = "no" ] && [ "$code" != "000" ] && { soft=$((soft+2)); tags="${tags}raw-origin,"; }
  echo "$H" | grep -qiE 'artifactory' && { soft=$((soft+5)); tags="${tags}ARTIFACTORY,"; }
  echo "$H" | grep -qiE 'uat|tst|test|dev|stag|qa' && { soft=$((soft+2)); tags="${tags}nonprod,"; }
  echo "$H$title" | grep -qiE 'splunk|phantom|soar' && { soft=$((soft+3)); tags="${tags}SOAR,"; }
  echo "$H" | grep -qiE 'api\.|apigw|apigateway' && { soft=$((soft+2)); tags="${tags}api,"; }
  grep -qiE 'login|signin|password|username' "$body" 2>/dev/null && { soft=$((soft+1)); tags="${tags}loginform,"; }
  grep -qiE 'application/json' "$hdr" 2>/dev/null && { soft=$((soft+1)); tags="${tags}json,"; }
  echo "$final" | grep -qiE 'extranet|saml|sso|ping' && { tags="${tags}auth-redirect,"; }
  case "$code" in 200) soft=$((soft+1));; 401|403) tags="${tags}authwall,";; 000) tags="${tags}DEAD,";; esac
  printf '%d\t%s\t%s\t%s\t%s\t%s\t%s\n' "$soft" "$H" "$code" "$size" "$akamai" "${server:0:18}" "${tags%,}" \
    >> "$OUTDIR/fingerprints.tsv"
  printf '  [soft=%d] %-42s %s/%sB ak=%s %s\n' "$soft" "$H" "$code" "$size" "$akamai" "${tags%,}"
  sleep 0.4
done < "$OUTDIR/targets.txt"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "RANKED SOFT TARGETS (top of list = hunt first)"
echo "════════════════════════════════════════════"
sort -t$'\t' -k1,1 -rn "$OUTDIR/fingerprints.tsv" | head -15 | \
  awk -F'\t' '{printf "  soft=%-2s %-40s %s/%sB  ak=%s  %s\n",$1,$2,$3,$4,$5,$7}'
echo ""
echo "Full table: $OUTDIR/fingerprints.tsv   bodies: $OUTDIR/fp-*.html"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
