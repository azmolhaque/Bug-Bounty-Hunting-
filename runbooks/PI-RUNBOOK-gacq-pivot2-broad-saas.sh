#!/usr/bin/env bash
# =============================================================================
# Google VRP — BROAD self-service SaaS discovery across the FULL official
# acquisitions list (acquisitions_domains_tiers.asciipb = authoritative scope).
# Portable: Termux / Linux / Pi.
#
# Photomath + VirusTotal exhausted (hardened). The first discovery used a curated
# scope.yaml subset and skipped most acquisition hosts. This widens to the WHOLE
# official acquisitions file, filters to web-app-pattern hosts, and ranks by self-
# service signup + SPA signals to surface a FRESH, less-tested multi-tenant SaaS
# for authenticated IDOR. Every host here is from the authoritative Google
# domain-tiers file => in scope.
#
# SAFETY: read-only GET, paced, web-app hosts only. No account creation here.
#
# Run (Termux): mkdir -p $HOME/gq2; OUTDIR=$HOME/gq2 \
#   bash runbooks/PI-RUNBOOK-gacq-pivot2-broad-saas.sh 2>&1 | tee $HOME/gq2/gq2.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/gq2}"; export OUTDIR; mkdir -p "$OUTDIR"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASC=""
for c in "./config/acquisitions_domains_tiers.asciipb" "$SD/../config/acquisitions_domains_tiers.asciipb" \
         "$HOME/bbh/config/acquisitions_domains_tiers.asciipb"; do
  [ -f "$c" ] && { ASC="$c"; break; }
done
[ -n "$ASC" ] || { echo "acquisitions file not found; run from repo root."; exit 1; }
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.35}"
echo "============================================================"
echo "GOOGLE ACQ — BROAD SaaS DISCOVERY  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "source: $ASC   pace: ${PACE}s/req   read-only"
echo "============================================================"; echo ""

# extract fqdns, drop already-worked brands, keep web-app-pattern hosts + brand apexes
grep -oE 'fqdn: "[^"]+"' "$ASC" | sed -E 's/fqdn: "//; s/"//' \
  | grep -vE 'photomath|virustotal|appsheet|apigeeks' \
  | grep -vE '\.(xml|png)$' \
  | grep -aiE '^(www|app|apps|my|account|accounts|id|auth|login|signin|signup|register|portal|dashboard|console|secure|cloud|go|home|member|members|user|users|developer|developers|partner|partners|business|biz|connect|hub|manage|admin|dev|beta|try|get|web|online|store|shop|customer|client)\.' \
  | sort -u > "$OUTDIR/webhosts.txt"
# also add registrable apexes (2-label) of each brand
grep -oE 'fqdn: "[^"]+"' "$ASC" | sed -E 's/fqdn: "//; s/"//' \
  | grep -vE 'photomath|virustotal|appsheet' \
  | awk -F. 'NF>=2{print $(NF-1)"."$NF}' | sort -u | head -60 >> "$OUTDIR/webhosts.txt"
sort -u "$OUTDIR/webhosts.txt" -o "$OUTDIR/webhosts.txt"
echo "  $(wc -l < "$OUTDIR/webhosts.txt") candidate web hosts"; echo ""

: > "$OUTDIR/rank.txt"; n=0
echo "═══ PROBE (signup/login/SPA signals) ═══"
while read -r H; do
  [ -z "$H" ] && continue
  n=$((n+1)); [ "$n" -gt "${MAXHOSTS:-200}" ] && { echo "  (capped at $MAXHOSTS)"; break; }
  m=$(curl -s -L --max-redirs 5 --max-time 12 -H "User-Agent: $UA" \
       -o "$OUTDIR/b.tmp" -w '%{http_code}|%{url_effective}' "https://$H/" 2>/dev/null) || m="000|-"
  code="${m%%|*}"; eff="${m##*|}"
  [ "$code" = "000" ] && { sleep "$PACE"; continue; }
  b=$(tr 'A-Z' 'a-z' < "$OUTDIR/b.tmp" 2>/dev/null)
  title=$(grep -oiE '<title[^>]*>[^<]*' "$OUTDIR/b.tmp" 2>/dev/null | head -1 | sed -E 's/<title[^>]*>//I' | tr -d '\r' | cut -c1-44)
  su=""; lo=""; spa=""; sg=""
  printf '%s' "$b" | grep -qE 'sign ?up|create (an )?account|get started free|/signup|/register|/join|create your account|start free' && su="signup"
  printf '%s' "$b" | grep -qE 'sign ?in|log ?in|/login|/signin' && lo="login"
  printf '%s' "$b" | grep -qE '__next_data__|ng-version|react|__nuxt|data-reactroot|id="root"|id="app"|window\.__' && spa="SPA"
  printf '%s' "$b" | grep -qE 'contact sales|request a demo|talk to (sales|us)|book a demo' && sg="sales"
  score=0
  [ -n "$su" ] && score=$((score+3)); [ -n "$lo" ] && score=$((score+1)); [ -n "$spa" ] && score=$((score+2))
  [ -n "$sg" ] && [ -z "$su" ] && score=$((score-2))
  # only log things that look like apps (some signal) to cut noise
  if [ -n "$su$lo$spa" ]; then
    printf "  [%s] %-30s s=%-2s %s%s%s%s  %s\n" "$code" "$H" "$score" "${su:+[signup] }" "${spa:+[SPA] }" "${lo:+[login] }" "${sg:+[sales] }" "$title"
    echo "$score|$H|$code|$su|$lo|$spa|$sg|$eff" >> "$OUTDIR/rank.txt"
  fi
  sleep "$PACE"
done < "$OUTDIR/webhosts.txt"
echo ""

echo "════════════════════════════════════════════"
echo "TOP SELF-SERVICE CANDIDATES (signup + SPA = best IDOR target)"
echo "════════════════════════════════════════════"
sort -t'|' -k1 -rn "$OUTDIR/rank.txt" 2>/dev/null | head -15 | while IFS='|' read -r sc h code su lo spa sg eff; do
  printf "  score %-2s  %-30s %s%s%s%s\n" "$sc" "$h" "${su:+[signup] }" "${spa:+[SPA] }" "${lo:+[login] }" "${sg:+[sales-gate] }"
done
echo ""
echo "  Pick the top [signup] host = fresh self-service multi-tenant SaaS. Next:"
echo "  register two free test accounts, capture sessions, enumerate object-id"
echo "  endpoints, test cross-account reads (IDOR/BOLA) + tenant isolation."
echo ""
echo "Evidence: $OUTDIR/rank.txt"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
