#!/usr/bin/env bash
# acq-s3-claim.sh — is the bucket behind an S3 CNAME still there?
#
# acq-dead-dns.sh found three TIER3 names pointing at the bare S3 endpoint:
#
#   repos.nestlabs.com           -> s3.amazonaws.com
#   server-logs.nestlabs.com     -> s3.amazonaws.com
#   thirdparty.ops.nestlabs.com  -> s3.amazonaws.com
#
# A CNAME to the bare endpoint means S3 routes by Host header, so the bucket
# name IS the hostname. Bucket names are global and first-come. If the bucket
# was deleted, anyone can create one with that name and serve content on a
# nestlabs.com hostname.
#
# This is the one takeover class in this estate where § 3's demand is cheap to
# satisfy. Creating a bucket is free and instant, so "claim it and serve a
# canary" is a few minutes of work rather than the unbounded Route 53 grind
# that made aws-zaipon.com a hypothesis.
#
# The whole job is telling four S3 answers apart:
#
#   NoSuchBucket       gone. The name is free and this is worth the next step.
#   AccessDenied       the bucket exists and is private. Not yours.
#   PermanentRedirect  it exists in another region. Not yours.
#   ListBucketResult   it exists AND lists publicly — read what is in it before
#                      anything else, because someone else's data in a world-
#                      readable bucket is a finding on its own.
#
# And one non-answer: a plain HTML 404 from a CDN or a proxy is NOT NoSuchBucket.
# Treating them as the same turns every 404 on the internet into a takeover,
# which is the mistake this repo has now made three times in other sweeps.
#
# Nothing here creates, writes or deletes anything. Every request is a GET.
#
# Usage:
#   ./scripts/acq-s3-claim.sh repos.nestlabs.com server-logs.nestlabs.com
#   ./scripts/acq-s3-claim.sh --from-table ~/acq/deaddns-20261028-0723-156150.tsv
#   ./scripts/acq-s3-claim.sh --selftest
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
LOG="$OUT/s3claim-$STAMP.txt"
EVID="$OUT/s3claim-$STAMP.evidence"
UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

body=$(mktemp); trap 'rm -f "$body"' EXIT

# S3 says which of these it is, in an XML <Code> element. Matching the code
# element and not loose words is what keeps an HTML page saying "access denied"
# out of the results.
s3code() {   # s3code <file> -> the S3 error/listing code, or "-"
  local c
  c="$(sed -n 's/.*<Code>\([A-Za-z]*\)<\/Code>.*/\1/p' "$1" | head -1)"
  if [ -z "$c" ] && [ "$(grep -c '<ListBucketResult' "$1" 2>/dev/null)" -gt 0 ]; then
    c="ListBucketResult"
  fi
  printf '%s' "${c:--}"
}

verdict() {   # verdict <code> -> word + sentence
  case "$1" in
    NoSuchBucket)      echo "GONE       the bucket does not exist — the name is free" ;;
    NoSuchKey)         echo "EXISTS     the bucket is there, that key is not" ;;
    AccessDenied)      echo "EXISTS     the bucket is there and private" ;;
    AllAccessDisabled) echo "EXISTS     the bucket is there and disabled by AWS" ;;
    PermanentRedirect) echo "EXISTS     the bucket is there, in another region" ;;
    InvalidBucketName) echo "INVALID    S3 will not accept this name at all" ;;
    ListBucketResult)  echo "PUBLIC     the bucket is there and lists to anyone" ;;
    -)                 echo "NOT-S3     no S3 code in the response — read it by hand" ;;
    *)                 echo "OTHER      S3 said $1" ;;
  esac
}

selftest() {
  local fail=0 t c v; t=$(mktemp)
  printf '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><BucketName>x</BucketName></Error>\n' > "$t"
  c="$(s3code "$t")"; v="$(verdict "$c")"
  case "$v" in GONE*) ;; *) echo "!! selftest: NoSuchBucket -> $v"; fail=1 ;; esac
  printf '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>\n' > "$t"
  case "$(verdict "$(s3code "$t")")" in EXISTS*) ;; *) echo "!! selftest: AccessDenied misread"; fail=1 ;; esac
  printf '<?xml version="1.0"?><Error><Code>PermanentRedirect</Code></Error>\n' > "$t"
  case "$(verdict "$(s3code "$t")")" in EXISTS*) ;; *) echo "!! selftest: PermanentRedirect misread"; fail=1 ;; esac
  printf '<?xml version="1.0"?><ListBucketResult><Name>x</Name><Contents><Key>a</Key></Contents></ListBucketResult>\n' > "$t"
  case "$(verdict "$(s3code "$t")")" in PUBLIC*) ;; *) echo "!! selftest: a public listing misread"; fail=1 ;; esac
  # The negatives. None of these may read as GONE.
  for neg in \
    '<html><head><title>404 Not Found</title></head><body>The requested URL was not found. NoSuchBucket</body></html>' \
    '<html><title>403 Forbidden</title><body>access denied</body></html>' \
    '{"error":"not found"}' \
    ''
  do
    printf '%s\n' "$neg" > "$t"
    v="$(verdict "$(s3code "$t")")"
    case "$v" in
      GONE*) echo "!! selftest: a non-S3 page read as GONE: ${neg:0:40}"; fail=1 ;;
    esac
  done
  # The first negative is the one that matters: an HTML 404 that happens to
  # contain the word NoSuchBucket in prose. s3code matches the <Code> element,
  # so prose cannot reach it.
  rm -f "$t"
  [ "$fail" -eq 0 ] && echo "POSITIVE  the four S3 codes are told apart, and an HTML 404 saying NoSuchBucket is not GONE"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }

HOSTS=()
if [ "${1:-}" = "--from-table" ]; then
  [ -f "${2:-}" ] || { echo "!! usage: --from-table <deaddns tsv>"; exit 1; }
  mapfile -t HOSTS < <(awk -F'\t' 'NR>1 && $4 ~ /s3[.-].*amazonaws\.com|s3\.amazonaws\.com/ {print $1}' "$2" | sort -u)
else
  HOSTS=("$@")
fi
[ ${#HOSTS[@]} -gt 0 ] || { echo "!! no hosts given"; exit 1; }

fetch() {   # fetch <url> -> status; body in $body
  : > "$body"
  curl -sS -k -m 15 -A "$UA" -o "$body" -w '%{http_code}' "$1" 2>/dev/null
}

{
echo "# is the bucket behind an S3 CNAME still there"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from : $(curl -sS -m 10 https://ifconfig.me 2>/dev/null || echo 'ip lookup failed')"
echo

echo "== CONTROL =="
selftest || exit 2
# A name nobody has taken must come back NoSuchBucket, or a GONE below means
# nothing. A name that certainly exists must not.
st="$(fetch "https://s3.amazonaws.com/zzz-no-such-bucket-9f3a1c-test")"
c="$(s3code "$body")"
[ "$c" = "NoSuchBucket" ] || { echo "!! BROKEN: a made-up bucket returned '$c' ($st), not NoSuchBucket"; exit 2; }
echo "POSITIVE  a made-up bucket name returns NoSuchBucket"
st="$(fetch "https://s3.amazonaws.com/aws-roadmap")"
c="$(s3code "$body")"
[ "$c" = "NoSuchBucket" ] && { echo "!! BROKEN: an existing bucket also returned NoSuchBucket"; exit 2; }
echo "POSITIVE  an existing bucket returns $c, not NoSuchBucket"
echo

: > "$EVID"
ngone=0; npublic=0; nexists=0; nskip=0
for h in "${HOSTS[@]}"; do
  "$SCOPE" "$h" >/dev/null 2>&1 || { nskip=$((nskip+1)); echo "skip $h — not IN-SCOPE"; continue; }
  echo "== $h"
  echo "### $h   $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVID"

  # Three ways to ask about the same bucket. They can disagree, and a
  # disagreement is information: path style answers for any region, the
  # virtual-host style can 301 to the right one, and the target hostname goes
  # through whatever the CNAME chain actually resolves to today.
  for u in "http://$h/" "https://s3.amazonaws.com/$h" "https://$h.s3.amazonaws.com/"; do
    st="$(fetch "$u")"
    c="$(s3code "$body")"
    v="$(verdict "$c")"
    printf '   %-44s %s  %-18s %s\n' "${u:0:44}" "$st" "$c" "${v#* }"
    { echo "--- GET $u -> $st"; head -c 1200 "$body"; echo; } >> "$EVID"
    case "$v" in
      GONE*)   ngone=$((ngone+1)) ;;
      PUBLIC*) npublic=$((npublic+1)) ;;
      EXISTS*) nexists=$((nexists+1)) ;;
    esac
    sleep 0.5
  done
  echo
done

echo "== summary =="
echo "answers saying the bucket is gone  : $ngone"
echo "answers saying it exists           : $nexists"
echo "answers that listed publicly       : $npublic"
echo "out of scope                       : $nskip"
echo "evidence: $EVID"

cat <<'NOTE'

== reading it ==
PUBLIC first, if it happened. A world-readable bucket on a target hostname is a
finding the moment it holds somebody else's data, and it needs no takeover at
all. Read the listing, and if there is real content, stop and write it up.

GONE on the path-style URL (s3.amazonaws.com/<name>) is the one that counts:
it is S3 itself saying no bucket holds that name. Then, and only then:

  1. Create a bucket with exactly that name in your own AWS account. It is
     free, and if the name is taken the API says so — which is the proof the
     Wiz report was missing.
  2. Put one object at a path only you know. Nothing else. No index document
     that a real visitor would be served, if you can avoid it.
  3. Fetch that path over the TARGET hostname — http://repos.nestlabs.com/... —
     and keep the request and the full response. That fetch is the evidence.
  4. Then answer § 3's other half, which closes most takeover reports: who
     reaches this hostname? Look for it in package manifests, build configs,
     firmware update URLs, old documentation, archived pages. A name nothing
     references is informational even with the bucket in your hand.
  5. Delete the bucket when the report is filed, and say in the report that
     you did.

GONE on only the virtual-host URL while the path-style says otherwise usually
means a region redirect, not a free name. Trust the path-style answer.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report  : $LOG"
echo "evidence: $EVID"
