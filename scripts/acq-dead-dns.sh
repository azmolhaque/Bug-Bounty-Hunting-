#!/usr/bin/env bash
# acq-dead-dns.sh — what the DEAD hosts actually are.
#
# The live table calls a host DEAD when it did not answer HTTP. That is three
# different facts wearing one label:
#
#   NXDOMAIN        the name does not exist. Nothing to take, nothing to find.
#   CNAME -> third party   the name exists and points somewhere else. If that
#                   somewhere is a service anyone can sign up to and claim a
#                   hostname on, this is the class that has actually paid in
#                   this account: support.pring.jp.
#   A record, no HTTP      there is a machine. It just is not serving 80/443.
#
# TIER0 and TIER1 of the acquisitions table hold twenty-odd DEAD hosts —
# metabase.photomath.net, keybox.looker.com, pbvpn.looker.com,
# rampart.looker.com, corp.looker.com, lookermail.com — and the sweep has
# never asked which of the three they are.
#
# WHAT THIS PRODUCES IS A PRECONDITION, NOT A FINDING. CLAUDE.md § 3 is
# explicit: a dangling CNAME or a DEPLOYMENT_NOT_FOUND page is not a
# subdomain takeover, and the Wiz win-test.wiz.io attempt died exactly there.
# Claimability has to be proven by claiming it and serving a canary. This
# script tells you which host is worth that work. It does not do that work.
#
# Usage:
#   ./scripts/acq-dead-dns.sh ~/acq/live-20261024-1711.tsv
#   ./scripts/acq-dead-dns.sh --selftest
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
LOG="$OUT/deaddns-$STAMP.txt"
TSV="$OUT/deaddns-$STAMP.tsv"

# Services where a hostname is claimed by whoever asks first. A CNAME into one
# of these, with nothing answering, is the shape worth an hour.
#
# Deliberately not a "takeover fingerprint" list: the error body a provider
# serves changes, and matching it is how you end up reporting
# DEPLOYMENT_NOT_FOUND as a finding. This matches the CNAME target only, and
# the verdict it prints is CHECK, never VULNERABLE.
CLAIMABLE='s3[.-].*amazonaws\.com|s3\.amazonaws\.com|cloudfront\.net|github\.io|herokuapp\.com|herokudns\.com|azurewebsites\.net|cloudapp\.(net|azure\.com)|trafficmanager\.net|blob\.core\.windows\.net|firebaseapp\.com|web\.app|netlify\.(app|com)|vercel-dns\.com|vercel\.app|ghost\.io|zendesk\.com|statuspage\.io|pantheonsite\.io|wpengine\.com|readthedocs\.io|surge\.sh|bitbucket\.io|helpscoutdocs\.com|uservoice\.com|desk\.com|createsend\.com|campaignmonitor\.com|unbouncepages\.com|launchrock\.com|tilda\.ws|webflow\.io|myshopify\.com|cargocollective\.com|feedpress\.me|intercom\.help|aftership\.com|helpjuice\.com|helprace\.com|smartling\.com|acquia-sites\.com|proposify\.biz|simplebooklet\.com|getresponse\.com|hatenablog\.com|bigcartel\.com|activecampaign\.com|tictail\.com|strikinglydns\.com|mashery\.com|wordpress\.com|fastly\.net|edgekey\.net|edgesuite\.net|awsglobalaccelerator\.com|elasticbeanstalk\.com|global\.ssl\.fastly\.net|sendgrid\.net|zohohost\.com|freshdesk\.com|teamwork\.com|ngrok\.io|pagewiz\.net|furyns\.com|cname\.mendix\.net'

# Alphabet's own infrastructure. A CNAME here is not a takeover candidate; it
# is Google pointing at Google, and reporting it wastes a report.
INHOUSE='\.google\.com\.$|\.googleusercontent\.com\.$|\.googleapis\.com\.$|ghs\.google\.com|ghs-vip|googlehosted\.com|\.gstatic\.com\.$|\.appspot\.com\.$|\.withgoogle\.com\.$|\.google\.$'

dnsinfo() {   # dnsinfo <host> -> "status<TAB>chain<TAB>cname<TAB>addrs"
  local h="$1" st chain cn addrs
  st="$(dig +time=3 +tries=2 +noall +comments "$h" A 2>/dev/null \
        | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
  [ -n "$st" ] || st="NORESOLVER"
  chain="$(dig +time=3 +tries=2 +short "$h" A 2>/dev/null | paste -sd',' -)"
  cn="$(dig +time=3 +tries=2 +short "$h" CNAME 2>/dev/null | paste -sd',' -)"
  addrs="$(printf '%s\n' "${chain//,/$'\n'}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | paste -sd',' -)"
  printf '%s\t%s\t%s\t%s' "$st" "${chain:--}" "${cn:--}" "${addrs:--}"
}

verdict() {   # verdict <status> <chain> <cname> <addrs> -> one word + why
  local st="$1" chain="$2" cn="$3" addrs="$4" target
  target="$cn"; [ "$target" = "-" ] && target="$chain"
  case "$st" in
    NXDOMAIN)   echo "NXDOMAIN  the name does not exist — nothing to take"; return ;;
    NORESOLVER) echo "NO-DNS    no answer from the resolver — rerun, do not conclude"; return ;;
  esac
  if [ "$cn" != "-" ] && printf '%s' "$cn" | grep -qE "$INHOUSE"; then
    echo "IN-HOUSE  CNAME into Alphabet's own infrastructure"; return
  fi
  if [ "$cn" != "-" ] && printf '%s' "$cn" | grep -qE "$CLAIMABLE"; then
    if [ "$addrs" = "-" ]; then
      echo "CHECK     CNAME -> $cn, resolves to nothing — the shape worth proving"
    else
      echo "CHECK     CNAME -> $cn, still resolves ($addrs) — probably in use"
    fi
    return
  fi
  if [ "$cn" != "-" ]; then
    if [ "$addrs" = "-" ]; then
      echo "DANGLING  CNAME -> $cn resolves to nothing, provider not in the list"
    else
      echo "CNAME     -> $cn ($addrs) — third party, not a claimable service"
    fi
    return
  fi
  if [ "$addrs" != "-" ]; then
    echo "HAS-IP    $addrs answers DNS but not HTTP — a closed port, not a bug"; return
  fi
  echo "NO-RECORD the name resolves to no address and has no CNAME"
}

selftest() {
  local fail=0 v
  v="$(verdict NXDOMAIN - - -)";                        case "$v" in NXDOMAIN*) ;; *) echo "!! selftest: NXDOMAIN -> $v"; fail=1 ;; esac
  v="$(verdict NOERROR ghs.google.com. ghs.google.com. -)"
                                                        case "$v" in IN-HOUSE*) ;; *) echo "!! selftest: in-house -> $v"; fail=1 ;; esac
  v="$(verdict NOERROR x.s3.amazonaws.com. x.s3.amazonaws.com. -)"
                                                        case "$v" in CHECK*) ;; *) echo "!! selftest: claimable+unresolved -> $v"; fail=1 ;; esac
  v="$(verdict NOERROR 1.2.3.4 x.herokuapp.com. 1.2.3.4)"
                                                        case "$v" in CHECK*still\ resolves*) ;; *) echo "!! selftest: claimable+resolving -> $v"; fail=1 ;; esac
  v="$(verdict NOERROR 1.2.3.4 - 1.2.3.4)";             case "$v" in HAS-IP*) ;; *) echo "!! selftest: has-ip -> $v"; fail=1 ;; esac
  v="$(verdict NOERROR x.example.net. x.example.net. -)"
                                                        case "$v" in DANGLING*) ;; *) echo "!! selftest: dangling unknown provider -> $v"; fail=1 ;; esac
  v="$(verdict NORESOLVER - - -)";                      case "$v" in NO-DNS*) ;; *) echo "!! selftest: no resolver -> $v"; fail=1 ;; esac
  # A resolver failure must never read as NXDOMAIN. That mistake turns "the Pi
  # lost DNS" into "twenty takeover candidates".
  [ "$fail" -eq 0 ] && echo "POSITIVE  the seven verdicts are distinguished, and a resolver failure is not NXDOMAIN"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

command -v dig >/dev/null || { echo "!! dig not found — apt install dnsutils"; exit 1; }
[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }
LIST="${1:-$(ls -1t "$OUT"/live-*.tsv 2>/dev/null | head -1)}"
[ -n "${LIST:-}" ] && [ -f "$LIST" ] || { echo "!! no live table; run acq-live.sh first"; exit 1; }

{
echo "# what the DEAD hosts actually are"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from : $LIST"
echo

echo "== CONTROL =="
selftest || exit 2
# A resolver that cannot answer for a name everybody can resolve makes every
# verdict below meaningless, so it is checked before any of them.
if [ "$(dig +time=3 +short google.com A 2>/dev/null | grep -c .)" -eq 0 ]; then
  echo "!! BROKEN: the resolver did not answer for google.com — fix DNS first"; exit 2
fi
echo "POSITIVE  the resolver answers"
echo

mapfile -t DEAD < <(awk -F'\t' 'NR>1 && $3 ~ /^(DEAD|ERR|000)$/ {print $1"\t"$2}' "$LIST")
echo "== ${#DEAD[@]} host(s) the live sweep could not reach =="
echo

printf 'host\ttier\tdns\tcname\taddrs\tverdict\n' > "$TSV"
ncheck=0; ndangle=0; nskip=0
for row in "${DEAD[@]}"; do
  h="${row%%$'\t'*}"; tier="${row#*$'\t'}"
  "$SCOPE" "$h" >/dev/null 2>&1 || { nskip=$((nskip+1)); continue; }
  IFS=$'\t' read -r st chain cn addrs <<<"$(dnsinfo "$h")"
  v="$(verdict "$st" "$chain" "$cn" "$addrs")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$tier" "$st" "$cn" "$addrs" "${v%% *}" >> "$TSV"
  case "$v" in
    CHECK*)    ncheck=$((ncheck+1));  printf '  %-45s %-6s %s\n' "$h" "$tier" "$v" ;;
    DANGLING*) ndangle=$((ndangle+1)); printf '  %-45s %-6s %s\n' "$h" "$tier" "$v" ;;
    NO-DNS*)                           printf '  %-45s %-6s %s\n' "$h" "$tier" "$v" ;;
  esac
done

echo
echo "== summary =="
awk -F'\t' 'NR>1 {c[$6]++} END {for (k in c) printf "%6d  %s\n", c[k], k}' "$TSV" | sort -rn
echo
echo "worth proving : $ncheck"
echo "dangling, unknown provider: $ndangle"
echo "out of scope  : $nskip"
echo "table: $TSV"

cat <<'NOTE'

== reading it ==
CHECK is a precondition. It means: this name points at a service where
hostnames are claimed, and nothing is answering. It does NOT mean the host is
takeable, and a report saying so gets closed — § 3 names this exact mistake
and the Wiz attempt is the proof.

To turn one into a finding, in this order:
  1. Can the hostname actually be claimed on that provider? Modern Vercel,
     Netlify and Firebase refuse a domain still bound to another account.
     Try it. If the provider refuses, there is no finding and you stop.
  2. Claim it and serve a benign canary at a path only you know.
  3. Fetch that path over the target hostname and keep the output.
  4. Only then does § 3's other requirement apply: show real user traffic, a
     shared cookie domain, or an OAuth redirect_uri allowlist entry. A host
     nobody visits and nothing trusts is still informational after takeover.

DANGLING with an unknown provider is the more interesting column to read by
hand — the claimable list is not complete, and a CNAME into a service nobody
has written a fingerprint for is where an undiscovered one lives.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
