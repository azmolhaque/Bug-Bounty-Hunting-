#!/usr/bin/env bash
# =============================================================================
# Google VRP — Waze recon (pivot from Fitbit, which is gated behind GHA migration)
# Portable: Termux / Linux / Pi.
#
# Waze has a rich in-scope surface. Best IDOR target = the Ads / Waze-for-Business
# multi-tenant advertiser platform (biz.waze.com self-service portal + wam-api/
# adsapi); scope.yaml note records a PRIOR biz-portal XSS + location IDOR, so the
# area is fruitful. Community apps (forum/wiki/wazeopedia) may run dated software.
#
# This session maps the live surface:
#   A. liveness + tech fingerprint of in-scope hosts (app/api/biz/community)
#   B. self-service signup detection on biz.waze.com (the advertiser portal)
#   C. JS route-mining of the biz/app frontends for API hosts + object-id routes
#   D. light exposure / stale-software check on community apps
# -> picks the best authenticated IDOR target for session2.
#
# SAFETY: read-only GET, paced, scope-checked. No account creation here.
#
# Run (Termux): mkdir -p $HOME/wz1; OUTDIR=$HOME/wz1 \
#   bash runbooks/PI-RUNBOOK-waze-session1-recon.sh 2>&1 | tee $HOME/wz1/wz1.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/wz1}"; export OUTDIR; mkdir -p "$OUTDIR"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK=""
for c in "./scripts/scope-check.sh" "$SD/../scripts/scope-check.sh" "$HOME/bbh/scripts/scope-check.sh"; do
  [ -f "$c" ] && { SCOPE_CHECK="$c"; break; }
done
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.5}"
echo "============================================================"
echo "WAZE RECON  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "scope-check: ${SCOPE_CHECK:-none}   pace: ${PACE}s/req   read-only"
echo "============================================================"; echo ""

HOSTS="biz.waze.com www.waze.com waze.com wam-api.waze.com adsapi.waze.com api.waze.com
mobile-web.waze.com mobile-web-new.waze.com inbox.waze.com web-login-oauth.waze.com
forum.waze.com wiki.waze.com wazeopedia.waze.com new-wazeopedia.waze.com embed.waze.com"

inscope(){ [ -z "$SCOPE_CHECK" ] && return 0; case "$(bash "$SCOPE_CHECK" --program google "$1" 2>/dev/null)" in *IN-SCOPE*) return 0;; *) return 1;; esac; }

echo "═══ A: LIVENESS + FINGERPRINT ═══"
: > "$OUTDIR/live.txt"
for H in $HOSTS; do
  inscope "$H" || { echo "  skip(oos) $H"; continue; }
  hdr=$(curl -s -I -L --max-redirs 4 --max-time 14 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  code=$(printf '%s' "$hdr" | awk 'toupper($1)~/^HTTP/{c=$2} END{print c+0}')
  body=$(curl -s -L --max-redirs 4 --max-time 14 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  srv=$(printf '%s' "$hdr" | grep -i '^server:' | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
  title=$(printf '%s' "$body" | grep -oiE '<title[^>]*>[^<]*' | head -1 | sed -E 's/<title[^>]*>//I' | tr -d '\r' | cut -c1-48)
  tech=""
  printf '%s' "$body" | grep -qiE '__next_data__' && tech="$tech Next.js"
  printf '%s' "$body" | grep -qiE 'ng-version' && tech="$tech Angular"
  printf '%s' "$body$hdr" | grep -qiE 'phpbb|discourse|mediawiki|wordpress|drupal' && tech="$tech CMS"
  su=""; printf '%s' "$body" | tr 'A-Z' 'a-z' | grep -qE 'sign ?up|create (an )?account|/signup|get started|register' && su="[signup]"
  lo=""; printf '%s' "$body" | tr 'A-Z' 'a-z' | grep -qE 'sign ?in|log ?in|/login|oauth' && lo="[login]"
  [ "${code:-0}" -gt 0 ] 2>/dev/null && { printf "  [%s] %-26s srv='%.18s' %s%s%s '%s'\n" "$code" "$H" "$srv" "$su" "$lo" "${tech:+[${tech# }]}" "$title"; echo "$H|$code|$su|$lo|${tech# }" >> "$OUTDIR/live.txt"; }
  sleep "$PACE"
done
echo ""

echo "═══ B: biz.waze.com signup + JS API route mining ═══"
for H in biz.waze.com www.waze.com; do
  inscope "$H" || continue
  page=$(curl -s -L --max-redirs 4 --max-time 15 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  echo "/*FE:$H*/" >> "$OUTDIR/code.txt"; printf '%s' "$page" >> "$OUTDIR/code.txt"
  printf '%s' "$page" | grep -oE 'src=["'"'"'][^"'"'"']+\.js[^"'"'"']*' | sed -E 's/^src=.//' | head -10 \
    | while read -r J; do
        case "$J" in http*) U="$J";; //*) U="https:$J";; /*) U="https://$H$J";; *) U="https://$H/$J";; esac
        curl -s --max-time 12 -H "User-Agent: $UA" "$U" >> "$OUTDIR/code.txt" 2>/dev/null; echo >> "$OUTDIR/code.txt"
        sleep 0.2
      done
  sleep "$PACE"
done
python3 - <<'PY'
import os,re
O=os.environ["OUTDIR"];
try: c=open(O+"/code.txt",encoding="utf-8",errors="replace").read()
except: c=""
apis=sorted(set(re.findall(r'https?://[a-z0-9.-]*(?:api|waze)[a-z0-9.-]*\.waze\.com[A-Za-z0-9/_{}.:%-]*', c)))[:40]
idroutes=sorted(set(re.findall(r'/[a-z0-9/_-]*\{[a-zA-Z0-9_]+\}[a-z0-9/_{}-]*', c)))[:40]
nouns=sorted(set(re.findall(r'/(?:v[0-9]/)?(?:account|advertiser|campaign|ad|store|location|billing|invoice|user|partner|group|message)[a-zA-Z0-9/_{}-]*', c, re.I)))[:40]
print("  API hosts/paths referenced by the biz/app client:")
for a in apis: print("    "+a)
print("  object-id routes (IDOR candidates):")
for r in idroutes: print("    "+r)
print("  advertiser/account nouns:")
for n in nouns: print("    "+n)
if not (apis or idroutes or nouns): print("    (none extracted — client may be heavily bundled)")
PY
echo ""

echo "═══ C: community apps — stale-software / exposure quick check ═══"
for H in forum.waze.com wiki.waze.com wazeopedia.waze.com new-wazeopedia.waze.com; do
  inscope "$H" || continue
  body=$(curl -s -L --max-redirs 3 --max-time 12 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  gen=$(printf '%s' "$body" | grep -oiE '<meta name="generator" content="[^"]*"' | head -1 | sed -E 's/.*content="//; s/"//')
  mw=$(printf '%s' "$body" | grep -oiE 'MediaWiki [0-9.]+' | head -1)
  phpbb=$(printf '%s' "$body" | grep -oiE 'phpBB[^<]{0,20}' | head -1)
  echo "  $H  generator='${gen}' ${mw:+mediawiki='$mw'} ${phpbb:+phpbb='$phpbb'}"
  for p in "/.git/config" "/api.php?action=query&meta=siteinfo&format=json" "/server-status"; do
    c=$(curl -s -o /dev/null -w '%{http_code}' -L --max-redirs 2 --max-time 8 -H "User-Agent: $UA" "https://$H$p" 2>/dev/null)
    case "$c" in 200) echo "    $p -> 200";; esac; sleep 0.2
  done
  sleep "$PACE"
done
echo ""

echo "════════════════════════════════════════════"
echo "NEXT"
echo "════════════════════════════════════════════"
echo "  * If biz.waze.com shows [signup] + advertiser/campaign object-id routes ->"
echo "    register a free Waze Ads account, capture the session, and IDOR-test"
echo "    cross-advertiser campaign/store/billing reads (the prior-XSS/IDOR area)."
echo "  * If a community app exposes a stale MediaWiki/phpBB version -> CVE/exposure"
echo "    path (low dup-risk). api.php siteinfo reveals exact MediaWiki version."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
