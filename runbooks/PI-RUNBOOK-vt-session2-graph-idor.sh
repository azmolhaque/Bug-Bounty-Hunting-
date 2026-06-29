#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal Graph IDOR/BOLA test (private-object access control)
# Portable: Termux / Linux / Pi.
#
# session1: free account can create graphs; graphs carry a visibility flag. THE
# test: create a PRIVATE graph as account A, then try to read it (and each of its
# sub-resources) UNAUTHENTICATED and as account B. Any 200-with-data on a private
# object from a non-owner/anon context = confirmed IDOR/BOLA.
#
# Phases:
#   A. Learn the graph schema + exact visibility field from a public graph (read).
#   B. Create a PRIVATE graph with key A; confirm it is private; capture id.
#   C. Access-control matrix: GET the graph + relationships (owner/viewers/editors/
#      comments/nodes) as (1) UNAUTH, (2) account B. Flag any leak.
#   D. Cleanup: delete the test graph.
#
# PREP: VT_KEY = account A api key (creator). VT_KEY_B = a SECOND free account's
# key (optional but strengthens the cross-account proof; create another free acct).
#   VT_KEY=<A> VT_KEY_B=<B> OUTDIR=$HOME/vt2 \
#     bash runbooks/PI-RUNBOOK-vt-session2-graph-idor.sh
#
# SAFETY: only OUR OWN objects are created/read/deleted. Keys from env, masked in
# output, never committed. In scope. Free-tier safe pacing.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vt2}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<account A api key>}"
VT_KEY_B="${VT_KEY_B:-}"
PACE="${PACE:-16}"
B="https://www.virustotal.com/api/v3"
UA='vt-research/1.0 (authorized VRP testing)'
echo "============================================================"
echo "VIRUSTOTAL GRAPH IDOR TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "A=${VT_KEY:0:4}…${VT_KEY: -3}  B=${VT_KEY_B:+${VT_KEY_B:0:4}…${VT_KEY_B: -3}}${VT_KEY_B:-<none>}  pace=${PACE}s"
echo "Only our own objects. Keys masked, never committed."
echo "============================================================"; echo ""

# generic request: $1=method $2=path $3=authmode(A|B|NONE) $4=datafile(optional)
req(){
  local method="$1" path="$2" auth="$3" df="${4:-}" tag hdr
  tag=$(printf '%s_%s' "$method" "$path" | tr -c 'A-Za-z0-9' '_')
  case "$auth" in
    A) hdr=(-H "x-apikey: $VT_KEY");;
    B) hdr=(-H "x-apikey: $VT_KEY_B");;
    NONE) hdr=();;
  esac
  local args=(-s -L --max-time 25 -H "User-Agent: $UA" -H 'Accept: application/json' "${hdr[@]}" -X "$method")
  [ -n "$df" ] && args+=(-H 'Content-Type: application/json' --data @"$df")
  curl "${args[@]}" -o "$OUTDIR/$tag.json" -w '%{http_code}' "$B$path" 2>/dev/null
}

echo "═══ A: LEARN GRAPH SCHEMA (public graph, read-only) ═══"
code=$(req GET "/graphs?limit=1" A); sleep "$PACE"
PUBID=$(grep -oE '"id": "g[a-f0-9]+"' "$OUTDIR/GET__graphs_limit_1.json" 2>/dev/null | head -1 | sed -E 's/.*"(g[a-f0-9]+)".*/\1/')
echo "  /graphs list -> HTTP $code ; sample public id: ${PUBID:-none}"
if [ -n "$PUBID" ]; then
  code=$(req GET "/graphs/$PUBID" A); sleep "$PACE"
  echo "  /graphs/$PUBID -> HTTP $code ; attribute keys:"
  python3 -c "import json,sys;d=json.load(open('$OUTDIR/GET__graphs_${PUBID}.json'));a=d.get('data',{}).get('attributes',{});print('   ',sorted(a.keys()))" 2>/dev/null || echo "    (parse failed)"
fi
echo ""

echo "═══ B: CREATE A PRIVATE GRAPH (account A) ═══"
cat > "$OUTDIR/newgraph.json" <<'JSON'
{"data":{"type":"graph","attributes":{"graph_data":{"version":"5.0.0","data":{"nodes":[],"edges":[]}},"name":"acl-test-private","private":true}}}
JSON
code=$(req POST "/graphs" A "$OUTDIR/newgraph.json"); sleep "$PACE"
GID=$(python3 -c "import json;print(json.load(open('$OUTDIR/POST__graphs.json')).get('data',{}).get('id',''))" 2>/dev/null)
PRIV=$(python3 -c "import json;print(json.load(open('$OUTDIR/POST__graphs.json')).get('data',{}).get('attributes',{}).get('private'))" 2>/dev/null)
echo "  POST /graphs -> HTTP $code ; created id=${GID:-FAILED} ; private=${PRIV}"
if [ -z "$GID" ]; then
  echo "  !! creation failed — body:"; head -c 300 "$OUTDIR/POST__graphs.json" | sed 's/^/    /'; echo
  echo "  (adjust schema; check Section A attribute keys for the real visibility field)"; exit 0
fi
# verify owner sees it private
code=$(req GET "/graphs/$GID" A); sleep "$PACE"
echo "  owner GET /graphs/$GID -> HTTP $code (sanity: should be 200 for owner)"
echo ""

echo "═══ C: ACCESS-CONTROL MATRIX on the PRIVATE graph ═══"
echo "  (expect: every non-owner row should be 401/403/404. A 200-with-data = IDOR)"
RELS="/graphs/$GID /graphs/$GID/relationships/owner /graphs/$GID/relationships/viewers /graphs/$GID/relationships/editors /graphs/$GID/relationships/group /graphs/$GID/comments /graphs/$GID/relationships/items"
: > "$OUTDIR/idor-hits.txt"
for P in $RELS; do
  for AUTH in NONE B; do
    [ "$AUTH" = "B" ] && [ -z "$VT_KEY_B" ] && continue
    code=$(req GET "$P" "$AUTH"); sleep "$PACE"
    tag=$(printf 'GET_%s' "$P" | tr -c 'A-Za-z0-9' '_')
    size=$(wc -c < "$OUTDIR/$tag.json" 2>/dev/null)
    haserr=$(grep -c '"error"' "$OUTDIR/$tag.json" 2>/dev/null)
    verdict="ok(denied)"
    if [ "$code" = "200" ] && [ "${haserr:-0}" = "0" ]; then verdict="*** LEAK (200 data) ***"; echo "$AUTH|$P|$code" >> "$OUTDIR/idor-hits.txt"; fi
    printf "  [%s] auth=%-4s %-48s %s (size=%s)\n" "$code" "$AUTH" "$P" "$verdict" "$size"
  done
done
echo ""

echo "═══ D: CLEANUP (delete test graph) ═══"
code=$(req DELETE "/graphs/$GID" A); sleep "$PACE"
echo "  DELETE /graphs/$GID -> HTTP $code"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/idor-hits.txt" ]; then
  echo "  *** POSSIBLE IDOR — non-owner read of a PRIVATE graph resource:"
  sed 's/^/    /' "$OUTDIR/idor-hits.txt"
  echo "  CONFIRM: re-fetch the leaking URL by hand from a clean session; if it shows"
  echo "  the private graph's data to anon/account-B, it's a real BOLA -> we report."
else
  echo "  No leak: VT enforces private-graph ACLs across anon + account B. Clean negative."
  echo "  Next angle: graph COLLABORATOR abuse (can B add itself as viewer/editor of A's"
  echo "  private graph via POST relationships?), or comments/votes object IDOR."
fi
echo ""
echo "Evidence: $OUTDIR (raw json local; do not commit)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
