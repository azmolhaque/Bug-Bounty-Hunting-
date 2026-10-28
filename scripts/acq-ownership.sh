#!/usr/bin/env bash
# acq-ownership.sh — does the target still own the domains its scope file lists?
#
# Written the moment picasa-software.com answered. It is TIER3 in Google's own
# external_domains_google.asciipb, scope-check calls it IN-SCOPE, and it is
# registered through Wix with a creation date of 2026-10-10 — eighteen days
# before this ran. Picasa was discontinued in 2016, Google let the name go, a
# stranger bought it and pointed it at their GitHub Pages with a "this domain
# is for sale" page on it.
#
# So a fingerprint sweep would have put thirty probes into a private
# individual's website while every control in this repo printed POSITIVE. That
# is the one mistake § 0 calls unrecoverable, and no instrument here was
# looking for it: every scope check so far has asked "is this name on the
# list", never "does the list still describe reality".
#
# The signal is the registration's CREATION date, not its updated date. A
# renewal moves `Updated`; only a drop-and-re-register moves `Created`. So a
# brand the target has held for twenty years reading as created last month
# means it changed hands, whatever the scope file says.
#
# This produces an exclusion list, not a finding. A lapsed domain is the
# target's asset-management problem, and reporting it as a vulnerability is
# the kind of submission § 2 exists to prevent.
#
# Usage:
#   ./scripts/acq-ownership.sh config/scope-google-tiers.yaml
#   ./scripts/acq-ownership.sh --selftest
set -uo pipefail

OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
LOG="$OUT/ownership-$STAMP.txt"
TSV="$OUT/ownership-$STAMP.tsv"
DELAY="${DELAY:-1.5}"
YEARS="${YEARS:-3}"

# Registrars that sell to companies defending a brand. Their presence is not
# proof of anything on its own — it is the creation date that decides — but it
# raises confidence when the date is old.
CORPORATE_RE='MarkMonitor|CSC Corporate|Corporation Service Company|COM LAUDE|Nom-iq|Safenames|Ascio|EuroDNS|Brandsight|IP Twins|Authentic Web|Gandi.*[Cc]orporate|Google LLC'
# Registrars that sell to anybody with a card. Again not proof — plenty of
# small acquisitions use them legitimately — but with a recent creation date
# it is the shape picasa-software.com had.
CONSUMER_RE='Wix|GoDaddy|Namecheap|NameSilo|Dynadot|Porkbun|Tucows|Hostinger|Name\.com|Squarespace|Epik|Sav\.com|Spaceship|Gname|PDR Ltd|Realtime Register|Key-Systems|InterNetX|Hostgator|Bluehost|IONOS|OVH'

# TLDs Google operates itself. Every name under one of these belongs to them
# by definition, and there is no registrar to ask: the first run put `google`,
# `goog`, `gle` and `youtube` in the UNREGISTERED column because RDAP has
# nothing to say about a bare TLD label.
BRAND_TLD_RE='^(google|goog|gle|youtube|android|chrome|gmail|nexus|play|dclk|fly|here|ing|meme|prod|rsvp|soy|zip|dev|app|page|new|how|channel|boo|day|eat|esq|foo|mov|phd|search)$'

apex() {   # apex <fqdn>
  python3 -I -c '
import sys
h=sys.argv[1].rstrip(".").lstrip("+.")
multi=("co.uk","co.jp","com.au","co.nz","com.br","co.in","com.cn","co.za","ne.jp","or.jp",
       "ac.uk","gov.uk","com.ru","net.ru","org.ru","com.mx","com.tr","co.kr","com.sg","com.hk")
p=h.split(".")
print(".".join(p[-3:]) if len(p)>=3 and ".".join(p[-2:]) in multi else ".".join(p[-2:]) if len(p)>=2 else h)
' "$1"
}

rdap_url() {
  case "${1##*.}" in
    com|net) echo "https://rdap.verisign.com/${1##*.}/v1/domain/$1" ;;
    org)     echo "https://rdap.publicinterestregistry.org/rdap/domain/$1" ;;
    jp)      echo "" ;;
    *)       echo "https://rdap.org/domain/$1" ;;
  esac
}

# parse <file> -> "registrar<TAB>created"
parse() {
  python3 -I - "$1" <<'PY'
import json, sys
try: d = json.load(open(sys.argv[1]))
except Exception: print("\t"); raise SystemExit
rar = ""
for e in d.get("entities") or []:
    if "registrar" in (e.get("roles") or []):
        for v in (e.get("vcardArray") or [None, []])[1]:
            if v and v[0] == "fn": rar = v[3]
created = ""
for ev in d.get("events") or []:
    if ev.get("eventAction") == "registration": created = (ev.get("eventDate") or "")[:10]
print("%s\t%s" % (rar, created))
PY
}

classify() {   # classify <registrar> <created-YYYY-MM-DD> -> word + why
  local rar="$1" created="$2" age
  if [ -z "$created" ]; then
    if printf '%s' "$rar" | grep -qE "$CORPORATE_RE"; then
      echo "OK        no creation date, but a corporate registrar ($rar)"; return
    fi
    echo "UNKNOWN   no creation date in RDAP — check by hand"; return
  fi
  age=$(( ( $(date -u +%s) - $(date -u -d "$created" +%s 2>/dev/null || echo 0) ) / 31557600 ))
  if [ "$age" -lt "$YEARS" ]; then
    if printf '%s' "$rar" | grep -qE "$CONSUMER_RE"; then
      echo "NOT-THEIRS  created $created ($age y) at a consumer registrar ($rar)"; return
    fi
    echo "RECENT    created $created ($age y) — too new for an old brand; check ($rar)"; return
  fi
  if printf '%s' "$rar" | grep -qE "$CORPORATE_RE"; then
    echo "OK        created $created, corporate registrar ($rar)"; return
  fi
  echo "OK?       created $created ($age y), registrar $rar — old enough, unusual registrar"
}

selftest() {
  local fail=0 v
  v="$(apex sub.deep.example.com)";   [ "$v" = example.com ]    || { echo "!! selftest: apex .com -> $v"; fail=1; }
  v="$(apex a.b.example.co.jp)";      [ "$v" = example.co.jp ]  || { echo "!! selftest: apex .co.jp -> $v"; fail=1; }
  # The two real cases this script exists for, as fixtures.
  v="$(classify 'MarkMonitor Inc.' 1997-09-15)"
  case "$v" in OK*corporate*) ;; *) echo "!! selftest: an old corporate registration -> $v"; fail=1 ;; esac
  v="$(classify 'Wix.com Ltd.' "$(date -u -d '18 days ago' +%Y-%m-%d)")"
  case "$v" in NOT-THEIRS*) ;; *) echo "!! selftest: picasa-software.com's shape -> $v"; fail=1 ;; esac
  # A new domain at a corporate registrar is suspicious but not a verdict.
  v="$(classify 'MarkMonitor Inc.' "$(date -u -d '30 days ago' +%Y-%m-%d)")"
  case "$v" in RECENT*) ;; *) echo "!! selftest: new + corporate -> $v"; fail=1 ;; esac
  # An old domain at a consumer registrar is fine; small acquisitions do this.
  v="$(classify 'GoDaddy.com, LLC' 2005-03-01)"
  case "$v" in OK*) ;; *) echo "!! selftest: old + consumer -> $v"; fail=1 ;; esac
  v="$(apex sub.example.com.ru)";  [ "$v" = example.com.ru ] || { echo "!! selftest: com.ru suffix -> $v"; fail=1; }
  printf '%s' "google" | grep -qE "$BRAND_TLD_RE" || { echo "!! selftest: google is a brand TLD"; fail=1; }
  printf '%s' "com"    | grep -qE "$BRAND_TLD_RE" && { echo "!! selftest: com must not read as a brand TLD"; fail=1; }
  [ "$fail" -eq 0 ] && echo "POSITIVE  an old corporate registration passes, a fortnight-old Wix one does not, and a brand TLD is not an unregistered domain"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

SCOPE="${1:-}"
[ -n "$SCOPE" ] && [ -f "$SCOPE" ] || { echo "!! usage: $0 <scope yaml>"; exit 1; }
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

{
echo "# does the target still own what its scope file lists"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from : $SCOPE   (creation date younger than $YEARS years is the flag)"
echo

echo "== CONTROL =="
selftest || exit 2
st="$(curl -sS -L --max-redirs 5 -m 25 -o "$tmp" -w '%{http_code}' "$(rdap_url google.com)" 2>/dev/null)"
[ "$st" = "200" ] || { echo "!! BROKEN: RDAP returned $st for google.com"; exit 2; }
IFS=$'\t' read -r r c <<<"$(parse "$tmp")"
case "$(classify "$r" "$c")" in OK*) echo "POSITIVE  google.com reads as the owner's ($r, $c)" ;;
  *) echo "!! BROKEN: google.com did not read as owned — $(classify "$r" "$c")"; exit 2 ;; esac
# A TLD that goes through rdap.org rather than a registry endpoint we name
# directly. Without -L this returned the redirect instead of the answer, and
# abc.xyz — Alphabet's own, registered since 2015 — would have read as
# UNREGISTERED. The control exists because that happened.
st="$(curl -sS -L --max-redirs 5 -m 25 -o "$tmp" -w '%{http_code}' "$(rdap_url abc.xyz)" 2>/dev/null)"
if [ "$st" != "200" ]; then
  echo "!! BROKEN: RDAP returned $st for abc.xyz, a registered name on a TLD routed via rdap.org."
  echo "!!         Every non com/net/org verdict below would be about the redirect, not the domain."
  exit 2
fi
echo "POSITIVE  a registered name on an rdap.org-routed TLD answers 200"
echo

mapfile -t APEXES < <(awk '/^in_scope:/{f=1;next} /^out_of_scope:/{f=0} f' "$SCOPE" \
  | sed -n 's/^[[:space:]]*-[[:space:]]*"\([^"]*\)".*/\1/p' | sed 's/^+\.//' \
  | while read -r h; do apex "$h"; done | sort -u)

echo "== ${#APEXES[@]} apex(es) =="
printf 'apex\tverdict\tregistrar\tcreated\n' > "$TSV"
nflag=0
for a in "${APEXES[@]}"; do
  case "$a" in
    *.*) ;;
    *) printf '%s\t%s\t\t\n' "$a" "BARE-TLD" >> "$TSV"
       echo "  $a : BARE-TLD — a top-level domain, not a registration; skipped"
       continue ;;
  esac
  if printf '%s' "${a##*.}" | grep -qE "$BRAND_TLD_RE"; then
    printf '%s\t%s\t\t\n' "$a" "OK-BRAND-TLD" >> "$TSV"
    continue
  fi
  u="$(rdap_url "$a")"
  if [ -z "$u" ]; then
    printf '%s\t%s\t\t\n' "$a" "NO-RDAP" >> "$TSV"; sleep "$DELAY"; continue
  fi
  # -L, because rdap.org works by redirecting to the registry's own RDAP
  # server. Without it every TLD outside com/net/org was read from the
  # redirect itself rather than the answer, and a name that is plainly
  # registered could land in the UNREGISTERED column.
  st="$(curl -sS -L --max-redirs 5 -m 25 -o "$tmp" -w '%{http_code}' "$u" 2>/dev/null)"
  if [ "$st" = "404" ]; then
    # UNREGISTERED is the most consequential verdict here — it is the one that
    # would send us to buy a name — so it gets a second opinion from a
    # different protocol before it is written down, and a disagreement is
    # printed as a disagreement rather than resolved silently.
    wfree=-1
    if command -v whois >/dev/null; then
      if whois "$a" 2>/dev/null | head -40 \
         | grep -qiE 'no match|not found|no entries found|no data found|status: *free|available for registration'
      then wfree=1; else wfree=0; fi
    fi
    if [ "$wfree" = 0 ]; then
      printf '%s\t%s\t\t\n' "$a" "DISAGREE" >> "$TSV"
      echo "  $a : DISAGREE — RDAP 404 but whois has a record. Do not act on this."
    else
      printf '%s\t%s\t\t\n' "$a" "UNREGISTERED" >> "$TSV"
      echo "  $a : UNREGISTERED — RDAP 404$([ "$wfree" = 1 ] && echo ' and whois agrees')"
    fi
    nflag=$((nflag+1)); sleep "$DELAY"; continue
  fi
  if [ "$st" != "200" ]; then
    printf '%s\t%s\t\t\n' "$a" "RDAP-$st" >> "$TSV"; sleep "$DELAY"; continue
  fi
  IFS=$'\t' read -r r c <<<"$(parse "$tmp")"
  v="$(classify "$r" "$c")"
  printf '%s\t%s\t%s\t%s\n' "$a" "${v%% *}" "$r" "$c" >> "$TSV"
  case "$v" in
    NOT-THEIRS*|RECENT*|UNKNOWN*) nflag=$((nflag+1)); printf '  %-34s %s\n' "$a" "$v" ;;
  esac
  sleep "$DELAY"
done

echo
echo "== summary =="
awk -F'\t' 'NR>1 {c[$2]++} END {for (k in c) printf "%5d  %s\n", c[k], k}' "$TSV" | sort -rn
echo "flagged: $nflag"
echo "table  : $TSV"

cat <<'NOTE'

== reading it ==
NOT-THEIRS and UNREGISTERED are the ones that matter, and neither is a finding.
A lapsed domain is the target's asset-management problem; reporting it as a
vulnerability is the submission § 2 exists to prevent.

What they are is an EXCLUSION LIST. Any host under a flagged apex must be left
alone — it belongs to somebody who never agreed to be tested, and § 0 calls
that the one unrecoverable mistake. Add them to out_of_scope by hand after
reading each one; do not let a script edit a scope file.

RECENT at a corporate registrar usually means the target really did register
it lately. Check it rather than excluding it.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
