#!/usr/bin/env bash
# acq-iap-gap.sh — does any path get past Identity-Aware Proxy?
#
# Four TIER0 hosts are named argocd-gke-app-{eu,us}-{prod,test}.photomath.net
# and all four answer 200 with "Sign in - Google Accounts" from server GSE.
# That is IAP in front of an ArgoCD. The fingerprint sweep cannot see any of
# it: every path it asks for returns Google's login page, so its zero means
# "IAP answered" and not "no ArgoCD here". That is the third time a sweep in
# this repo has reported the instrument's own shape as a measured absence.
#
# So the question changes. Not "what software is this" — the hostname already
# said — but: **is every path actually behind the proxy?** IAP is attached per
# backend service. A health endpoint on a second backend, a path handled by the
# load balancer, an API route added after the IAP binding, all answer without
# it. One path that does not return Google's login page is an authentication
# bypass, and § 2 criterion 1 names that outright.
#
# Everything here is a GET. Nothing is written, nothing is brute-forced, and
# the list is a dozen paths per host.
#
# Usage:
#   ./scripts/acq-iap-gap.sh                      # auto: IAP hosts in the newest live table
#   ./scripts/acq-iap-gap.sh argocd-gke-app-eu-prod.photomath.net
#   ./scripts/acq-iap-gap.sh --selftest
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)-$$"
LOG="$OUT/iapgap-$STAMP.txt"
DELAY="${DELAY:-0.5}"
UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

# Paths that, on an ArgoCD, answer without a session — so if the proxy is not
# in the way, each one says so in its own words rather than Google's.
PATHS=(
  /
  /healthz
  /readyz
  /livez
  /_ah/health
  /metrics
  /robots.txt
  /favicon.ico
  /api/version
  /api/v1/applications
  /api/webhook
  /api/dex/healthz
  /api/dex/.well-known/openid-configuration
  /swagger.json
)

body=$(mktemp); hdr=$(mktemp)
trap 'rm -f "$body" "$hdr"' EXIT

# IAP's answer, in any of the forms it takes: the login page itself, a redirect
# to it, or IAP's own error surface.
IAP_RE='accounts\.google\.com|Sign in - Google Accounts|/_gcp_iap/|iap\.googleapis\.com|Invalid IAP credentials'

classify() {   # classify <status> <headerfile> <bodyfile> -> IAP | BACKEND
  local st="$1"
  if grep -qiE "^location:.*($IAP_RE)" "$2" 2>/dev/null; then echo IAP; return; fi
  if [ "$(grep -cE "$IAP_RE" "$3" 2>/dev/null)" -gt 0 ]; then echo IAP; return; fi
  echo BACKEND
}

selftest() {
  local fail=0 v
  : > "$hdr"
  printf '<html><head><title>Sign in - Google Accounts</title></head><body><form action="https://accounts.google.com/signin"></form></body></html>\n' > "$body"
  v="$(classify 200 "$hdr" "$body")"; [ "$v" = IAP ] || { echo "!! selftest: the IAP login page read as $v"; fail=1; }

  printf 'HTTP/2 302\nlocation: https://accounts.google.com/o/oauth2/v2/auth?client_id=x\n' > "$hdr"
  : > "$body"
  v="$(classify 302 "$hdr" "$body")"; [ "$v" = IAP ] || { echo "!! selftest: a 302 to accounts.google.com read as $v"; fail=1; }

  # ArgoCD's own answers. Each one means the request reached the backend.
  : > "$hdr"
  printf 'Method Not Allowed\n' > "$body"
  v="$(classify 405 "$hdr" "$body")"; [ "$v" = BACKEND ] || { echo "!! selftest: ArgoCD 405 read as $v"; fail=1; }

  printf '{"error":"no session information","code":16}\n' > "$body"
  v="$(classify 401 "$hdr" "$body")"; [ "$v" = BACKEND ] || { echo "!! selftest: ArgoCD auth error read as $v"; fail=1; }

  printf '{"Version":"v2.9.3","KustomizeVersion":"v5.2.1"}\n' > "$body"
  v="$(classify 200 "$hdr" "$body")"; [ "$v" = BACKEND ] || { echo "!! selftest: ArgoCD version JSON read as $v"; fail=1; }

  # An empty body with no headers must not read as a bypass. A timeout, a reset
  # connection and a 000 all produce exactly this, and calling it BACKEND would
  # turn every network hiccup into an authentication bypass.
  : > "$body"
  v="$(classify 000 "$hdr" "$body")"
  [ "$v" = BACKEND ] && echo "   note: an empty response reads as BACKEND — the loop drops status 000 before classifying"

  [ "$fail" -eq 0 ] && echo "POSITIVE  Google's login page and a redirect to it read as IAP; ArgoCD's own replies read as BACKEND"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }

HOSTS=("$@")
if [ ${#HOSTS[@]} -eq 0 ]; then
  LIST="$(ls -1t "$OUT"/live-*.tsv 2>/dev/null | head -1)"
  [ -n "$LIST" ] && [ -f "$LIST" ] || { echo "!! no hosts given and no live table"; exit 1; }
  mapfile -t HOSTS < <(awk -F'\t' 'NR>1 && $0 ~ /Sign in - Google Accounts/ {print $1}' "$LIST" | sort -u)
  echo "# hosts taken from $LIST by their IAP login title"
fi

{
echo "# IAP gap probe — does any path reach the backend"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# paths: ${#PATHS[@]} per host, ${DELAY}s apart, GET only"
echo

echo "== CONTROL =="
selftest || exit 2
echo

echo "== ${#HOSTS[@]} host(s) =="
nhost=0; ngap=0; nskip=0
for h in "${HOSTS[@]}"; do
  "$SCOPE" "$h" >/dev/null 2>&1 || { nskip=$((nskip+1)); echo "  skip $h — not IN-SCOPE"; continue; }
  nhost=$((nhost+1))
  echo
  echo "== $h"
  first=""
  for p in "${PATHS[@]}"; do
    : > "$body"; : > "$hdr"
    st="$(curl -sS -k -m 15 -A "$UA" -D "$hdr" -o "$body" -w '%{http_code}' "https://$h$p" 2>/dev/null || echo 000)"
    if [ "$st" = "000" ]; then
      printf '  %-46s  ---  no answer\n' "$p"; sleep "$DELAY"; continue
    fi
    cls="$(classify "$st" "$hdr" "$body")"
    sz="$(wc -c < "$body")"
    # The control: whatever / returns is this host's baseline. If / is not IAP
    # the premise is wrong for this host and every "gap" below is meaningless.
    if [ "$p" = "/" ]; then
      first="$cls"
      printf '  %-46s  %s  %s  %s bytes   <- baseline\n' "$p" "$st" "$cls" "$sz"
      if [ "$cls" != "IAP" ]; then
        echo "     !! / does not return Google's login page, so this host is not behind IAP."
        echo "        Nothing below is a bypass. Fingerprint it normally instead."
      fi
      sleep "$DELAY"; continue
    fi
    if [ "$cls" = "BACKEND" ] && [ "$first" = "IAP" ]; then
      ngap=$((ngap+1))
      printf '  %-46s  %s  %s  %s bytes   <<< PAST THE PROXY\n' "$p" "$st" "$cls" "$sz"
      echo "        $(head -c 300 "$body" | tr -d '\0' | tr '\n' ' ')"
    else
      printf '  %-46s  %s  %s  %s bytes\n' "$p" "$st" "$cls" "$sz"
    fi
    sleep "$DELAY"
  done
done

echo
echo "== summary =="
echo "hosts probed        : $nhost"
echo "out of scope        : $nskip"
echo "paths past the proxy: $ngap"

cat <<'NOTE'

== reading it ==
Zero past the proxy is the expected answer and a clean one: IAP is attached to
the backend service, not to a path, so it normally covers everything. Write it
down and move on — the hostname told us ArgoCD is there, and IAP is why it is
not our problem.

A path that did get past is not yet a finding either. What it returned decides:

  Google's login page            IAP. Not a gap, whatever the status code.
  ArgoCD's "no session
  information"                   the request reached ArgoCD and ArgoCD said no.
                                 The proxy was bypassed and the app's own auth
                                 held. Worth reporting as an auth-bypass of the
                                 IAP binding ONLY if a protected path answers.
  /api/v1/applications with
  "items" in it                  somebody else's deployment inventory came back
                                 without a credential. That is the finding.
                                 Stop, keep the bytes, write it up.
  /metrics, /healthz             an exposed internal endpoint. § 3 drops this on
                                 its own — do not report uptime and hostnames.

Keep the whole response for anything in the third row, and note the external IP
and UTC time per § 9's evidence checklist before touching it again.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
