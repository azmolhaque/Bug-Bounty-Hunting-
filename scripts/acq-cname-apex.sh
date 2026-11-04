#!/usr/bin/env bash
# acq-cname-apex.sh — who owns the domain a dangling CNAME points at.
#
# acq-dead-dns.sh found three TIER0 names pointing at a zone that answers
# nothing:
#
#   api.pring.jp        -> api.aws-zaipon.com
#   dev-api.pring.jp    -> dev-api.aws-zaipon.com
#   future-api.pring.jp -> future-api.aws-zaipon.com
#
# "Resolves to nothing" has three causes and only one of them is a finding:
#
#   the apex is NOT REGISTERED      anyone can register aws-zaipon.com and then
#                                   serve whatever they like on three TIER0
#                                   hostnames. This is a domain takeover, which
#                                   is strictly worse than the subdomain kind,
#                                   and it is provable: register, serve a
#                                   canary, fetch it over the target name.
#   REGISTERED, zone has no NS      somebody holds the name and has not
#                                   delegated it. Not ours to take.
#   REGISTERED, zone exists, host
#   is NXDOMAIN inside it           the owner simply deleted the record. Not
#                                   ours to take either.
#
# The discriminator is RDAP, not whois: RDAP answers 404 for a name nobody has
# registered and 200 with the registrar for one somebody has, as data rather
# than as a paragraph of English that varies per registry. whois is kept as a
# second opinion because a registry can lag.
#
# This script does not register anything. It tells you whether registering is
# the next step, and § 3 is explicit that until the claim is actually made and
# a canary served, there is no finding to report.
#
# Usage:
#   ./scripts/acq-cname-apex.sh aws-zaipon.com
#   ./scripts/acq-cname-apex.sh --from-table ~/acq/deaddns-20261028-0710-150004.tsv
#   ./scripts/acq-cname-apex.sh --selftest
set -uo pipefail

OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
LOG="$OUT/cnameapex-$STAMP.txt"
EVID="$OUT/cnameapex-$STAMP.evidence"

apex() {   # apex <fqdn> -> registrable-looking apex, best effort
  local h="${1%.}"
  case "$h" in
    *.co.uk|*.co.jp|*.com.au|*.co.nz|*.com.br|*.co.in|*.com.cn|*.co.za|*.ne.jp|*.or.jp|*.ac.uk|*.gov.uk)
      echo "$h" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' ;;
    *) echo "$h" | awk -F. '{print $(NF-1)"."$NF}' ;;
  esac
}

rdap_url() {   # rdap_url <apex> -> an RDAP endpoint for its TLD, or ""
  case "${1##*.}" in
    com|net) echo "https://rdap.verisign.com/${1##*.}/v1/domain/$1" ;;
    org)     echo "https://rdap.publicinterestregistry.org/rdap/domain/$1" ;;
    jp)      echo "" ;;   # JPRS does not serve public RDAP; whois only
    io)      echo "https://rdap.identitydigital.services/rdap/domain/$1" ;;
    *)       echo "https://rdap.org/domain/$1" ;;
  esac
}

selftest() {
  local fail=0 v
  v="$(apex sub.deep.example.com)";  [ "$v" = "example.com" ]    || { echo "!! selftest: apex of a .com -> $v"; fail=1; }
  v="$(apex a.b.example.co.jp)";     [ "$v" = "example.co.jp" ]  || { echo "!! selftest: apex of a .co.jp -> $v"; fail=1; }
  v="$(apex api.aws-zaipon.com.)";   [ "$v" = "aws-zaipon.com" ] || { echo "!! selftest: trailing dot -> $v"; fail=1; }
  v="$(rdap_url aws-zaipon.com)"
  case "$v" in https://rdap.verisign.com/com/v1/domain/aws-zaipon.com) ;; *) echo "!! selftest: rdap url -> $v"; fail=1 ;; esac
  [ -n "$(rdap_url x.jp)" ] && { echo "!! selftest: .jp should have no RDAP endpoint"; fail=1; }
  [ "$fail" -eq 0 ] && echo "POSITIVE  the apex is extracted correctly and .jp is routed to whois"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi
command -v dig >/dev/null || { echo "!! dig not found — apt install dnsutils"; exit 1; }

TARGETS=()
if [ "${1:-}" = "--from-table" ]; then
  [ -f "${2:-}" ] || { echo "!! usage: --from-table <deaddns tsv>"; exit 1; }
  mapfile -t TARGETS < <(awk -F'\t' 'NR>1 && ($6=="DANGLING" || $6=="CHECK") && $4!="-" {print $4}' "$2" \
                         | tr ',' '\n' | sed 's/\.$//' | sort -u)
else
  TARGETS=("$@")
fi
[ ${#TARGETS[@]} -gt 0 ] || { echo "!! nothing to look up"; exit 1; }

{
echo "# who owns the apex behind a dangling CNAME"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from : $(curl -sS -m 10 https://ifconfig.me 2>/dev/null || echo 'ip lookup failed')"
echo

echo "== CONTROL =="
selftest || exit 2
# A registered domain must read as registered, or every answer below is noise.
ctl="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$(rdap_url google.com)" 2>/dev/null)"
if [ "$ctl" != "200" ]; then
  echo "!! BROKEN: RDAP returned $ctl for google.com — the endpoint or the network is the problem,"
  echo "   not the targets. Do not read a 404 below as 'unregistered' until this says 200."
  exit 2
fi
echo "POSITIVE  RDAP answers 200 for a domain that is certainly registered"
# And a name nobody has taken must read as free, so a registry that answers 200
# for everything cannot quietly mark every target registered.
neg="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
       "$(rdap_url zzz-this-name-is-not-registered-9f3a1c.com)" 2>/dev/null)"
if [ "$neg" = "200" ]; then
  echo "!! BROKEN: RDAP also returned 200 for a made-up name — it cannot tell free from taken"; exit 2
fi
echo "POSITIVE  RDAP answers $neg for a made-up name, so 404 means free"
echo

: > "$EVID"
for t in "${TARGETS[@]}"; do
  ap="$(apex "$t")"
  echo "== $t   (apex: $ap)"
  {
    echo "### $t / $ap   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$EVID"

  # Does the child name exist at all?
  cst="$(dig +time=3 +tries=2 +noall +comments "$t" A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
  echo "   child  $t : ${cst:-no answer}"

  ns="$(dig +time=3 +tries=2 +short "$ap" NS 2>/dev/null | paste -sd',' -)"
  soa="$(dig +time=3 +tries=2 +short "$ap" SOA 2>/dev/null | head -1)"
  ast="$(dig +time=3 +tries=2 +noall +comments "$ap" NS 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
  echo "   apex   $ap : ${ast:-no answer}   NS=${ns:--}   SOA=${soa:--}"

  # SERVFAIL is not "no nameservers", and reading it that way printed exactly
  # the wrong sentence for aws-zaipon.com: "not delegated (no NS)" on a domain
  # RDAP showed delegated to Route 53. An empty `dig NS` plus SERVFAIL means
  # the resolver could not get an answer OUT of the delegated servers, which is
  # a different and far more interesting state than having none.
  #
  # So ask the parent zone who the delegated servers are, and then ask those
  # servers directly. The parent always answers; the delegated servers are the
  # ones that may not.
  pns=""; nsalive=0; nsrefused=0
  tld="${ap##*.}"
  parent="$(dig +time=3 +tries=2 +short "$tld." NS 2>/dev/null | head -1)"
  if [ -n "$parent" ]; then
    pns="$(dig +time=5 +tries=2 +norecurse "@$parent" "$ap" NS 2>/dev/null \
           | awk '$4=="NS" {print $5}' | sed 's/\.$//' | sort -u | paste -sd',' -)"
  fi
  echo "   parent $tld says NS = ${pns:--}"
  if [ -n "$pns" ]; then
    for n in ${pns//,/ }; do
      nst="$(dig +time=5 +tries=1 +noall +comments "@$n" "$ap" SOA 2>/dev/null \
             | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
      nsoa="$(dig +time=5 +tries=1 +short "@$n" "$ap" SOA 2>/dev/null | head -1)"
      if [ -n "$nsoa" ]; then
        nsalive=$((nsalive+1)); echo "     $n : ${nst:-?}  SOA present"
      else
        nsrefused=$((nsrefused+1)); echo "     $n : ${nst:-no answer}  no SOA"
      fi
      printf '%s NS %s -> %s / %s\n' "$ap" "$n" "${nst:-?}" "${nsoa:--}" >> "$EVID"
    done
  fi

  url="$(rdap_url "$ap")"
  if [ -n "$url" ]; then
    rst="$(curl -sS -m 20 -o "$OUT/.rdap.$$" -w '%{http_code}' "$url" 2>/dev/null)"
    echo "   rdap   $rst  $url"
    head -c 4000 "$OUT/.rdap.$$" >> "$EVID"; echo >> "$EVID"
    # Parsed, not grepped. The sed version took the first "ldhName" in the
    # document, which belonged to a nameserver, and printed a Route 53 hostname
    # where the domain name should have been.
    rdapsum="$(python3 -I - "$OUT/.rdap.$$" <<'PY'
import json, sys
try: d = json.load(open(sys.argv[1]))
except Exception as e: print("unparseable: %s" % e); raise SystemExit
name = d.get("ldhName", "?")
status = ",".join(d.get("status", [])) or "-"
ns = ",".join(n.get("ldhName", "?") for n in d.get("nameservers", []) or []) or "-"
rar = "-"
for e in d.get("entities", []) or []:
    if "registrar" in (e.get("roles") or []):
        for v in (e.get("vcardArray") or [None, []])[1]:
            if v and v[0] == "fn": rar = v[3]
print("domain=%s status=%s" % (name, status))
print("nameservers=%s" % ns)
print("registrar=%s" % rar)
PY
)"
    printf '%s\n' "$rdapsum" | sed 's/^/          /'
    rm -f "$OUT/.rdap.$$"
  else
    rst="n/a"
    echo "   rdap   no public RDAP for .${ap##*.} — whois only"
  fi

  if command -v whois >/dev/null; then
    w="$(whois "$ap" 2>/dev/null | head -40)"
    printf '%s\n' "$w" >> "$EVID"
    wfree=0
    printf '%s' "$w" | grep -qiE 'no match|not found|no entries found|no data found|status: *free|available for registration' && wfree=1
    echo "   whois  $( [ "$wfree" = 1 ] && echo 'says NO MATCH' || echo 'has a record' )"
  else
    wfree=-1
    echo "   whois  not installed — apt install whois for a second opinion"
  fi

  # The verdict. RDAP decides when it answered; whois decides for .jp and
  # friends. Disagreement is reported as disagreement, never resolved silently.
  if [ "$rst" = "404" ] && [ "$wfree" = 1 ]; then
    echo "   >>> NOT REGISTERED — RDAP 404 and whois no-match agree."
    echo "       Registering this apex gives you $t and every sibling that"
    echo "       points at it. This is the one case worth the next step."
  elif [ "$rst" = "404" ] && [ "$wfree" = 0 ]; then
    echo "   !!! DISAGREEMENT — RDAP says free, whois has a record. Do not act."
  elif [ "$rst" = "200" ] || [ "$wfree" = 0 ]; then
    if [ -z "$pns" ]; then
      echo "   --- REGISTERED, and the parent zone publishes no delegation."
      echo "       The name is theirs and points nowhere. Nothing to take."
    elif [ "$nsalive" -gt 0 ]; then
      echo "   --- REGISTERED and the zone is live ($nsalive of its servers hold"
      echo "       an SOA). The owner simply has no record for $t. Theirs."
    else
      echo "   >>> REGISTERED, DELEGATED, AND THE ZONE IS GONE."
      echo "       The parent publishes $pns"
      echo "       and not one of them holds an SOA for $ap. The delegation"
      echo "       outlived the zone — this is the precondition for taking the"
      echo "       zone at the DNS provider rather than at the registrar."
      echo "       STILL A PRECONDITION. See the reading guide before anything."
    fi
  else
    echo "   ??? UNDECIDED — rdap=$rst whois=$wfree. Rerun; do not conclude."
  fi
  echo
  sleep 1
done

cat <<'NOTE'
== reading it ==
Two verdicts are worth anything, and both are preconditions rather than
findings. § 3 rejects a takeover claimed on a precondition, and the Wiz attempt
is this repo's proof of that.

REGISTERED, DELEGATED, AND THE ZONE IS GONE means the parent zone still points
at a set of provider nameservers that no longer serve the domain. Somebody
holds the registration, so it cannot be bought; the question is whether the
zone can be recreated at that provider and land on the same nameserver set.

Be honest about that question before spending anything on it. On Route 53 the
published technique is to create and delete hosted zones until the assigned
nameserver set matches the delegated one, which takes a large and unbounded
number of attempts, costs per zone, and leans on a provider that is not the
party being tested. § 4 is the rule that applies: if the next link cannot be
tested now, this is a HYPOTHESIS and not a lead, and it gets logged as one.
Reporting the dangling delegation on its own is the Wiz mistake with different
nameservers.

What IS worth doing first, and costs nothing:
  - Is the target hostname used by anything? A TIER0 API name that a live app
    resolves is worth an hour; a legacy name nothing references is informational
    even after a successful takeover, which § 3 says in as many words.
  - Does the same apex sit behind other hostnames, in this program or others?
  - Is the apex itself registered to the target or to a third party? A third
    party holding the delegation target of a TIER0 name is worth saying out
    loud even without a takeover, because the owner can serve that hostname.

If a target comes back NOT REGISTERED, the order is:
  1. Decide whether to spend the registration fee. It is yours to decide, and
     it is the only way to satisfy § 3 — the claim has to be made, not assumed.
  2. Register the apex. Change nothing else.
  3. Serve a benign canary at a path only you know, over plain HTTP first.
  4. Fetch that path over the TARGET hostname — api.pring.jp, not the apex —
     and keep the full request and response. That fetch is the evidence.
  5. Do not accept logins, do not collect any traffic, do not serve anything
     but the canary. § 7 is not optional and real users may hit the name.
  6. Report with the canary fetch, the RDAP 404 from before registration, and
     the CNAME. Say what the hostname is used for only if you can show it.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report  : $LOG"
echo "evidence: $EVID"
