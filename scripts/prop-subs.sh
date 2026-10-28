#!/usr/bin/env bash
# prop-subs.sh — find the direct subdomains of a domain whose tier propagates.
#
# Why this exists. 31 domains in the acquisitions tier file carry
# `propagate_tier_to_direct_subdomains: true`, which puts every DIRECT
# subdomain in scope whether Google listed it or not. Those names are not in
# the protobuf, so the only way to learn them is certificate transparency.
# Without this step the generated scope file grants a surface we never look at,
# which is the same quiet-filter failure the repo has already been bitten by
# twice.
#
# It became urgent on 2026-10-28: Google added intrinsic.ai (TIER1),
# intrinsic.equipment (TIER1) and intrinsic.dev (TIER2) that day, all three
# with the flag. A whole estate arrived in scope at once, and nobody's cached
# tooling knows about it yet.
#
# What it does NOT do: touch the target. Every source here is a third-party
# certificate log. The names it prints are candidates for acq-live.sh, and
# scope-check decides which of them may be touched — never this script.
#
# Usage:
#   ./scripts/prop-subs.sh                      # every propagating domain in the protobuf
#   ./scripts/prop-subs.sh intrinsic.ai         # just these
#   SCOPE_FILE=$PWD/config/scope-acquisitions.yaml ./scripts/prop-subs.sh intrinsic.ai
#
# Then:
#   HOSTS_FILE=~/acq/prop-subs-<stamp>-hosts.txt ./scripts/acq-live.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PB="${PB:-$ROOT/config/acquisitions_domains_tiers.asciipb}"
SCOPE="$HERE/scope-check.sh"
: "${SCOPE_FILE:=$ROOT/config/scope-acquisitions.yaml}"
export SCOPE_FILE
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
HOSTS="$OUT/prop-subs-$STAMP-hosts.txt"
LOG="$OUT/prop-subs-$STAMP.log"
DELAY="${DELAY:-2}"      # between source fetches; these are other people's logs

command -v curl    >/dev/null || { echo "!! curl missing"; exit 1; }
command -v python3 >/dev/null || { echo "!! python3 missing — JSON is not parsed with sed here"; exit 1; }
[ -x "$SCOPE" ]              || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }
[ -f "$SCOPE_FILE" ]         || { echo "!! no scope file at $SCOPE_FILE"; exit 1; }

# ---- sources -----------------------------------------------------------------
# Each prints one dns name per line, or exits non-zero. A source that fails is
# reported as a failure, never as an empty result: "nothing here" is the most
# believable lie an instrument can tell.

src_crtsh() {   # src_crtsh <domain>
  local d="$1" body code
  body="$(mktemp)"
  code="$(curl -sS -m 60 -o "$body" -w '%{http_code}' \
          -A 'bug-bounty research (azmolhaque95@gmail.com)' \
          "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null)"
  if [ "$code" != "200" ]; then rm -f "$body"; echo "!!HTTP=$code"; return 1; fi
  python3 -c '
import json,sys
try:
    rows=json.load(open(sys.argv[1]))
except Exception as e:
    print("!!PARSE="+type(e).__name__); sys.exit(1)
out=set()
for r in rows:
    for n in str(r.get("name_value","")).split("\n"):
        n=n.strip().lower().lstrip("*.")
        if n: out.add(n)
    cn=str(r.get("common_name","") or "").strip().lower().lstrip("*.")
    if cn: out.add(cn)
print("\n".join(sorted(out)))
' "$body"
  local rc=$?; rm -f "$body"; return $rc
}

src_certspotter() {   # src_certspotter <domain>
  local d="$1" body code
  body="$(mktemp)"
  code="$(curl -sS -m 60 -o "$body" -w '%{http_code}' \
          -A 'bug-bounty research (azmolhaque95@gmail.com)' \
          "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names" 2>/dev/null)"
  if [ "$code" != "200" ]; then rm -f "$body"; echo "!!HTTP=$code"; return 1; fi
  python3 -c '
import json,sys
try:
    rows=json.load(open(sys.argv[1]))
except Exception as e:
    print("!!PARSE="+type(e).__name__); sys.exit(1)
out=set()
for r in rows:
    for n in r.get("dns_names",[]) or []:
        n=str(n).strip().lower().lstrip("*.")
        if n: out.add(n)
print("\n".join(sorted(out)))
' "$body"
  local rc=$?; rm -f "$body"; return $rc
}

SOURCES="src_crtsh src_certspotter"

# ---- the +. rule -------------------------------------------------------------
# "propagate to DIRECT subdomains" is exactly one label below the apex. Written
# as a filter here and as the "+." pattern in scope-check, and the two have to
# agree: a.b.intrinsic.ai is more than Google granted, and CLAUDE.md 0 says the
# doubtful case is out.
# SUBS picks which rule applies, and the two tier files need different ones.
#
#   direct  one label below the apex. The acquisitions flag says "direct
#           subdomains" and nothing more, and a.b.cameyo.com is more than
#           Google granted.
#   any     any depth. The Google file inherits sensitivity down the tree, so
#           deep.nested.foo.google.com is in scope at google.com's tier.
#
# scope-check still gates every name either way; this only decides what is
# worth asking it about.
SUBS="${SUBS:-direct}"
case "$SUBS" in direct|any) ;; *) echo "!! SUBS must be 'direct' or 'any'"; exit 1 ;; esac

keep_subs() {   # keep_subs <apex>   (reads names on stdin)
  if [ "$SUBS" = "any" ]; then any_depth "$1"; else direct_only "$1"; fi
}

any_depth() {   # any_depth <apex>   (reads names on stdin)
  local apex="$1"
  awk -v apex="$apex" '
    { n=tolower($0); sub(/\.$/,"",n) }
    n == apex { print n; next }
    {
      suf = "." apex
      if (index(n, suf) == length(n) - length(suf) + 1 && length(n) > length(suf)) print n
    }
  ' | sort -u
}

direct_only() {   # direct_only <apex>   (reads names on stdin)
  local apex="$1"
  awk -v apex="$apex" '
    { n=tolower($0); sub(/\.$/,"",n) }
    n == apex { print n; next }
    {
      suf = "." apex
      if (index(n, suf) != length(n) - length(suf) + 1) next
      head = substr(n, 1, length(n) - length(suf))
      if (head == "" || index(head, ".") > 0) next
      print n
    }
  ' | sort -u
}

propagating_domains() {
  awk '
    /^domain: *\{/ { f=""; t=""; p=0 }
    /fqdn:/        { f=$2; gsub(/"/,"",f) }
    /tier:/        { t=$2 }
    /propagate_tier_to_direct_subdomains: *true/ { p=1 }
    /^\}/          { if (f!="" && t!="" && t!="TIER4" && p) print f }
  ' "$PB" | sort -u
}

{
echo "# direct-subdomain enumeration for propagating domains"
echo "# when      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# scope file: $SCOPE_FILE"
echo "# sources   : $SOURCES"
echo

# ---- control 1: a source that answers ----
# cameyo.com is the oldest propagating domain we know and has public certs for
# subdomains. If this comes back empty the logs are unreachable or the parser
# is broken, and every empty result below would be a statement about this
# machine rather than about the estate.
ctl_ok=0
for s in $SOURCES; do
  # grep -v '^!!' first: a failing source prints "!!HTTP=403", and counting
  # that line would report the control as passing on the strength of an error
  # message.
  n="$("$s" cameyo.com 2>/dev/null | grep -v '^!!' | keep_subs cameyo.com | grep -c . || true)"
  case "$n" in
    ''|0|*[!0-9]*) echo "   note: $s returned $n direct names for the control domain" ;;
    *) echo "POSITIVE  $s -> $n direct subdomain(s) of cameyo.com"; ctl_ok=$((ctl_ok+1)) ;;
  esac
  sleep "$DELAY"
done
[ "$ctl_ok" -gt 0 ] || { echo "!! BROKEN: no source returned a single known subdomain."
                         echo "!!         Fix connectivity or the parser before trusting anything below."; exit 2; }

# ---- control 2: a domain that must yield nothing ----
# A source that answers for every name (or a parser that invents names) would
# make the whole estate look populated.
canary="no-such-domain-$RANDOM$RANDOM.com"
bad=0
for s in $SOURCES; do
  n="$("$s" "$canary" 2>/dev/null | grep -v '^!!' | keep_subs "$canary" | grep -c . || true)"
  [ "${n:-0}" -eq 0 ] || { echo "!! BROKEN: $s returned $n name(s) for $canary"; bad=1; }
  sleep "$DELAY"
done
[ "$bad" -eq 0 ] && echo "NEGATIVE  a domain that does not exist yields no names"
[ "$bad" -eq 0 ] || exit 2

# ---- control 3: the one-label filter ----
# Fed by hand, because a log that happens to hold no nested names would let a
# broken filter pass. These five fixtures are what the +. rule means.
fixture() { printf '%s\n' x.intrinsic.ai a.b.intrinsic.ai intrinsic.ai '*.intrinsic.ai' \
            deep.nested.intrinsic.ai notintrinsic.ai evil-intrinsic.ai \
            intrinsic.ai.attacker-9f3a.com | sed 's/^\*\.//'; }
# Both rules are checked every run, not just the one in use: a mode that is
# silently wrong is only discovered when somebody reads a host list and asks
# why a name is in it.
got_d="$(fixture | direct_only intrinsic.ai | paste -sd',')"
want_d='intrinsic.ai,x.intrinsic.ai'
got_a="$(fixture | any_depth intrinsic.ai | paste -sd',')"
want_a='a.b.intrinsic.ai,deep.nested.intrinsic.ai,intrinsic.ai,x.intrinsic.ai'
if [ "$got_d" = "$want_d" ] && [ "$got_a" = "$want_a" ]; then
  echo "POSITIVE  direct keeps one label ($got_d)"
  echo "POSITIVE  any keeps every depth and still rejects evil-intrinsic.ai and intrinsic.ai.attacker-9f3a.com"
  echo "   running with SUBS=$SUBS"
else
  [ "$got_d" = "$want_d" ] || echo "!! BROKEN: direct_only returned '$got_d', wanted '$want_d'"
  [ "$got_a" = "$want_a" ] || echo "!! BROKEN: any_depth returned '$got_a', wanted '$want_a'"
  exit 2
fi
echo

# ---- the sweep ----
if [ "$#" -gt 0 ]; then
  DOMAINS="$*"
  echo "== $# domain(s) given on the command line =="
else
  DOMAINS="$(propagating_domains | paste -sd' ')"
  echo "== $(printf '%s\n' $DOMAINS | grep -c .) propagating domain(s) from $(basename "$PB") =="
fi
echo

: > "$HOSTS"
for d in $DOMAINS; do
  all="$(mktemp)"
  fails=0
  for s in $SOURCES; do
    out="$("$s" "$d" 2>/dev/null)"
    if [ $? -ne 0 ] || printf '%s' "$out" | grep -q '^!!'; then
      echo "   !! $s failed for $d: $(printf '%s' "$out" | head -1)"
      fails=$((fails+1))
    else
      printf '%s\n' "$out" >> "$all"
    fi
    sleep "$DELAY"
  done

  direct="$(keep_subs "$d" < "$all")"
  total="$(sort -u "$all" | grep -c . || true)"

  # The apex is in scope under its own name, whether or not a certificate log
  # has heard of it. intrinsic.dev returned no CT entries at all on the first
  # run, so the apex fell out of the host list and was never probed — the one
  # name we already know must not depend on a third party also knowing it.
  # Counted here rather than before the apex is added. Counting first printed
  # "8 name(s) seen, 9 direct" for bvi.dev.debugproject.com — more names kept
  # than were ever read, which cannot be true. The cause was harmless and the
  # effect is not: a table that does not agree with itself stops being read.
  apex_added=0
  case $'\n'"$direct"$'\n' in
    *$'\n'"$d"$'\n'*) : ;;
    *) apex_added=1 ;;
  esac
  direct="$(printf '%s\n%s\n' "$d" "$direct" | grep -v '^[[:space:]]*$' | sort -u)"
  total=$(( total + apex_added ))
  rm -f "$all"

  if [ "$fails" -eq $(printf '%s\n' $SOURCES | grep -c .) ]; then
    echo "SOURCE-DOWN  $d — every source failed; this is NOT 'no subdomains'"
    continue
  fi

  n_direct="$(printf '%s\n' "$direct" | grep -c . || true)"
  in=0; out=0
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    if "$SCOPE" "$h" >/dev/null 2>&1; then
      echo "$h" >> "$HOSTS"; in=$((in+1))
    else
      out=$((out+1))
    fi
  done <<< "$direct"

  printf '%-30s %4d name(s) known, %3d direct, %3d in scope, %3d rejected by scope-check%s\n' \
         "$d" "${total:-0}" "${n_direct:-0}" "$in" "$out" \
         "$([ "$apex_added" -eq 1 ] && printf '  (apex added; no certificate names it)')"
done

sort -u -o "$HOSTS" "$HOSTS"
echo
echo "== $(grep -c . "$HOSTS" || true) host(s) in scope and ready to probe =="
grep -c . "$HOSTS" >/dev/null && head -40 "$HOSTS"

cat <<NOTE

== what to do with this ==
These names came out of certificate logs, so a name here may be long dead, may
be internal-only, or may never have been served. The next step is one request
each:

  HOSTS_FILE=$HOSTS ./scripts/acq-live.sh

and then acq-fingerprint.sh over whatever answered. A name in a log is not a
host, a live host is not a finding, and a login page is not a finding either —
the question that has ever paid here is whether you can get in, and once in,
whether something is yours that should not be.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "hosts : $HOSTS"
echo "log   : $LOG"
