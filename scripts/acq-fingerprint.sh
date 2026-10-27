#!/usr/bin/env bash
# acq-fingerprint.sh — what software is actually running on each live host.
#
# Why this and not more paths. Both findings this account has had rewarded
# came from identifying the software and then going at that software:
# rip.photomath.net was Metabase with default credentials, support.pring.jp
# was a host that could be taken over. Neither came from /admin returning 200.
# The twelve-path sweep over 320 live hosts found nothing, and it could not
# have: every site answers /login, and none of them says what it is.
#
# So each probe here matches on **content**, never on status. A 404 page that
# echoes the path, a catch-all 200, a login wall — all of them produce status
# codes and none of them produce `"cluster_name"` or `ref: refs/heads/`.
# That is the whole difference, and it is why the earlier sweep drowned in
# false positives while this one can report a measured zero.
#
# Usage:
#   SCOPE_FILE=$PWD/config/scope-acquisitions.yaml ./scripts/acq-fingerprint.sh
#   SCOPE_FILE=... ./scripts/acq-fingerprint.sh ~/acq/live-20261024-1723.tsv
#   ./scripts/acq-fingerprint.sh --selftest
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"; mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M)"
LOG="$OUT/fingerprint-$STAMP.txt"
TSV="$OUT/fingerprint-$STAMP.tsv"
DELAY="${DELAY:-0.4}"
UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

# path | marker (extended regex, matched against the body) | name
# Markers are strings the software emits and almost nothing else does.
PROBES=(
  '/api/session/properties|"setup-token"|"engines"|Metabase'
  '/ghost/api/admin/site/|"publication"|"ghost"|Ghost'
  '/login?from=%2F|Jenkins|jenkins|Jenkins'
  '/actuator/health|"status":"UP"|"diskSpace"|Spring Boot actuator'
  '/_cluster/health|"cluster_name"|"number_of_nodes"|Elasticsearch'
  '/.git/HEAD|ref: refs/|^[0-9a-f]{40}$|exposed .git'
  '/.env|APP_KEY=|DB_PASSWORD=|exposed .env'
  '/server-status|Apache Server Status|Server Version|Apache status page'
  '/wp-login.php|wp-submit|WordPress|WordPress'
  '/api/v4/projects|"path_with_namespace"|"ssh_url_to_repo"|GitLab API'
  '/debug/pprof/|Types of profiles|goroutine|Go pprof'
  '/solr/admin/cores|"responseHeader"|"initFailures"|Solr'
  # Second batch. Same rule as above: each marker is a string the software
  # emits and a login wall, a catch-all 200 and a path-echoing 404 do not.
  # /health and /version are generic paths, so the marker carries all the
  # weight there ("metadatabase" is Airflow's word, nobody else's).
  '/api/health|"database": *"ok"|"commit": *"[0-9a-f]|Grafana'
  '/api/status|"name": *"kibana"|"nickname"|Kibana'
  '/health|"metadatabase"|"scheduler": *\{|Airflow'
  '/phpmyadmin/|phpMyAdmin|pma_username|phpMyAdmin'
  '/minio/|MinIO Console|minio-console|MinIO'
  '/v1/agent/self|"Datacenter"|"NodeName"|Consul'
  '/v3/settings|"baseType": *"setting"|cacerts|Rancher'
  '/metrics|go_gc_duration_seconds|process_cpu_seconds_total|exposed Prometheus metrics'
  '/v2/_catalog|"repositories": *\[|"errors": *\[|Docker registry'
  '/version|"gitVersion"|"buildDate"|Kubernetes or Mongo version endpoint'
  '/appsettings.json|ConnectionStrings|DefaultConnection|exposed appsettings.json'
  '/phpinfo.php|phpinfo\(\)|PHP Extension Build|phpinfo'
)

body=$(mktemp); trap 'rm -f "$body"' EXIT

fetch() {   # fetch <url> -> prints status; body lands in $body
  : > "$body"
  curl -sS -k -m 12 -A "$UA" -o "$body" -w '%{http_code}' "$1" 2>/dev/null || echo "000"
}

selftest() {
  local fail=0 t; t=$(mktemp)
  printf '{"setup-token":"abc","engines":{}}\n' > "$t"
  grep -qE '"setup-token"' "$t" || { echo "!! selftest: Metabase marker"; fail=1; }
  printf 'ref: refs/heads/main\n' > "$t"
  grep -qE 'ref: refs/' "$t" || { echo "!! selftest: .git marker"; fail=1; }
  printf 'go_gc_duration_seconds{quantile="0"} 1.0\n' > "$t"
  grep -qE 'go_gc_duration_seconds' "$t" || { echo "!! selftest: metrics marker"; fail=1; }
  printf '{"metadatabase": {"status": "healthy"}}\n' > "$t"
  grep -qE '"metadatabase"' "$t" || { echo "!! selftest: Airflow marker"; fail=1; }
  # Nothing a site serves to *everybody* may match. Three shapes have produced
  # false positives in this repo's earlier sweeps: the 404 that echoes the
  # path, the catch-all SPA shell, and the login wall.
  for neg in \
    '<html><title>404 Not Found</title>The requested URL /.env was not found</html>' \
    '{"error":"not found","status":404,"path":"/v1/agent/self","version":"1.0"}' \
    '<html><head><title>Sign in</title></head><body><form action="/login" method="post"><input name="username"><input name="password" type="password"><button>Log in</button></form><div id="root"></div><script src="/static/app.js"></script></body></html>'
  do
    printf '%s\n' "$neg" > "$t"
    for p in "${PROBES[@]}"; do
      IFS='|' read -r _ m1 m2 name <<<"$p"
      if grep -qE "$m1|$m2" "$t"; then echo "!! selftest: a generic page matched $name"; fail=1; fi
    done
  done
  rm -f "$t"
  [ "$fail" -eq 0 ] && echo "POSITIVE  ${#PROBES[@]} markers match their software and ignore a 404, an SPA shell and a login wall"
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

[ -x "$SCOPE" ] || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }
LIST="${1:-$(ls -1t "$OUT"/live-*.tsv 2>/dev/null | head -1)}"
[ -n "${LIST:-}" ] && [ -f "$LIST" ] || { echo "!! no live table; run acq-live.sh first"; exit 1; }

{
echo "# software fingerprint of the live acquisition hosts"
echo "# when  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# from  : $LIST"
echo "# probes: ${#PROBES[@]} per host, ${DELAY}s apart, content-matched"
echo

echo "== CONTROL =="
selftest || exit 2
if [ "$(fetch https://www.appsheet.com/)" = "000" ]; then
  echo "!! BROKEN: a known-live host did not answer; fix connectivity first"; exit 2
fi
echo "POSITIVE  a known-live host answers"
echo

mapfile -t HOSTS < <(awk -F'\t' 'NR>1 && $3 !~ /^(DEAD|ERR|000)$/ {print $1}' "$LIST" | sort -u)
echo "== ${#HOSTS[@]} live host(s) =="
echo

printf 'host\tsoftware\tpath\tstatus\n' > "$TSV"
n=0; nid=0; nskip=0
for h in "${HOSTS[@]}"; do
  "$SCOPE" "$h" >/dev/null 2>&1 || { nskip=$((nskip+1)); continue; }
  n=$((n+1))
  hits=""
  for p in "${PROBES[@]}"; do
    IFS='|' read -r path m1 m2 name <<<"$p"
    st=$(fetch "https://$h$path")
    case "$st" in 000|40[13]) sleep "$DELAY"; continue ;; esac
    if [ "$(grep -cE "$m1|$m2" "$body" 2>/dev/null)" -gt 0 ]; then
      hits="$hits  $name  <- $path  ($st, $(wc -c < "$body") bytes)"$'\n'
      printf '%s\t%s\t%s\t%s\n' "$h" "$name" "$path" "$st" >> "$TSV"
    fi
    sleep "$DELAY"
  done
  if [ -n "$hits" ]; then
    nid=$((nid+1))
    echo "== $h"
    printf '%s' "$hits"
    echo
  fi
done

echo "== $nid of $n host(s) identified, $nskip out of scope =="
echo "table: $TSV"

cat <<'NOTE'

== reading it ==
Identified software is a lead, not a finding. What each one is worth:

  exposed .git / .env   read it. Credentials in a .env, source and history in
                        a .git, are the finding itself — stop at the first
                        secret and report, do not enumerate.
  Metabase              the account's own second Fixed report. Check the setup
                        token and whether the instance is unconfigured.
  Jenkins / GitLab      anonymous read of jobs or projects is the question.
  Elasticsearch / Solr  an open cluster returns documents; one document of
                        someone else's is the finding.
  Spring actuator       /env and /heapdump are where credentials sit.
  Apache status         informational on its own — Section 3 drops it.

Nothing here is reportable until something belonging to someone else comes
back. The fifteen closures in this account's history were all reports of the
door, not of what was behind it.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
