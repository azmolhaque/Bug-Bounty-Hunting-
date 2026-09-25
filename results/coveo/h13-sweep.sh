#!/data/data/com.termux/files/usr/bin/bash
# H13 — Coveo cross-organization sweep
#
# Question: an API key minted in org A must never reach org B, on ANY service.
# The platform API enforces this correctly on /rest/organizations/{id} (verified).
# These are 34 SEPARATE backend services. This sweeps all of them.
#
# READ ONLY. GET requests only. No writes against any organization.
#
# Baseline established 2026-09-25: the denial signature is
#   403 {"message":"Access is denied.","errorCode":"ACCESS_DENIED",...}
# and a NONEXISTENT org returns the same 403 — there is no existence oracle.
# Therefore ANYTHING that is not a 403 is worth a look, including a 404.
#
# usage:
#   export KEYA='<api key minted in ORG A>'
#   export ORGB='bugbountygoribbcsq3h50g'
#   bash h13-sweep.sh specs      # fetch the 34 OpenAPI specs
#   bash h13-sweep.sh paths      # build the testable path list
#   bash h13-sweep.sh sweep      # run it

set -u
OUT="${OUT:-$HOME/h13}"
mkdir -p "$OUT"

APIGROUPS="Activity AnalyticsAdmin AuthorizationServer CatalogManagement CommerceService
Connectivity ContextApiService CustomerServiceApi DocumentLogs Event Extension Field Index
KnowledgeGenerativeAI MLConfig Migration Notification Organization Platform PushApi Reveal
RevealModelGenerator SchemaService SearchApi SearchInterfaceService SearchPagesService
SearchUsageMetrics SecurityCache SocialProof Source SourceLogsApi Tailgate
UsageAnalyticsRead UsageAnalyticsWrite Workspace"

specs() {
  echo "== fetching specs -> $OUT/spec-*.json"
  for g in $APIGROUPS; do
    code=$(curl -s -o "$OUT/spec-$g.json" -w '%{http_code}' --max-time 25 \
      "https://platform.cloud.coveo.com/api-docs/$g?group=public")
    printf '  %-26s [%s] %s bytes\n' "$g" "$code" "$(wc -c < "$OUT/spec-$g.json")"
    sleep 0.3
  done
}

# Keep only paths whose ONLY placeholder is {organizationId}. Paths needing a
# source/model/field ID can't be filled without reading org B first, which is a
# later phase — this phase must stay clean.
paths() {
  : > "$OUT/paths.txt"
  for f in "$OUT"/spec-*.json; do
    g=$(basename "$f" .json); g=${g#spec-}
    grep -o '"/rest/[^"]*"' "$f" 2>/dev/null | tr -d '"' | sort -u | while read -r p; do
      case "$p" in *'{organizationId}'*) ;; *) continue ;; esac
      # reject if any OTHER {placeholder} remains after removing {organizationId}
      rest=${p//\{organizationId\}/}
      case "$rest" in *'{'*) continue ;; esac
      printf '%s\t%s\n' "$g" "$p" >> "$OUT/paths.txt"
    done
  done
  sort -u -o "$OUT/paths.txt" "$OUT/paths.txt"
  echo "== testable paths (organizationId only): $(wc -l < "$OUT/paths.txt")"
  cut -f1 "$OUT/paths.txt" | uniq -c | sort -rn | head -40
}

sweep() {
  : "${KEYA:?export KEYA first}"; : "${ORGB:?export ORGB first}"
  [ -s "$OUT/paths.txt" ] || { echo "!! run 'paths' first"; return 1; }
  : > "$OUT/anomalies.txt"
  n=0; anom=0
  while IFS=$'\t' read -r g p; do
    n=$((n+1))
    url="https://platform.cloud.coveo.com${p//\{organizationId\}/$ORGB}"
    body=$(curl -s -w '\n%{http_code}' --max-time 20 -H "Authorization: Bearer $KEYA" "$url")
    code=${body##*$'\n'}; text=${body%$'\n'*}
    # 403 ACCESS_DENIED is CORRECT. Anything else is the signal.
    if [ "$code" = "403" ] && case "$text" in *ACCESS_DENIED*) true;; *) false;; esac; then
      : # correct denial, silent
    else
      anom=$((anom+1))
      printf '[%s] %-22s %s\n    %s\n' "$code" "$g" "$p" "$(printf '%s' "$text" | head -c 220)" \
        | tee -a "$OUT/anomalies.txt"
    fi
    [ $((n % 50)) -eq 0 ] && echo "   ...$n checked, $anom anomalies"
    sleep 0.35
  done < "$OUT/paths.txt"
  echo
  echo "== swept $n paths against ORG B with ORG A's key"
  echo "== anomalies (anything not 403/ACCESS_DENIED): $anom  -> $OUT/anomalies.txt"
}

case "${1:-}" in
  specs) specs ;;
  paths) paths ;;
  sweep) sweep ;;
  *) echo "usage: bash h13-sweep.sh {specs|paths|sweep}" ;;
esac
