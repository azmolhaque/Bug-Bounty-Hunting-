#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal Graph IDOR/BOLA test (private-object access control)
# Portable: Termux / Linux / Pi.  (session2, fixed schema + key masking)
#
# Graph attributes (from a real graph): graph_data, private, nodes,
# comments_count, creation/last_modified_date, views_count. NO 'name'. So create
# with graph_data + private only. Then run the access-control matrix: read the
# PRIVATE graph + sub-resources as UNAUTH and as account B. Any 200-with-data on a
# private object from a non-owner = candidate IDOR/BOLA.
#
# PREP: VT_KEY=<account A key>  [VT_KEY_B=<second free account key>]
#   VT_KEY=<A> VT_KEY_B=<B> OUTDIR=$HOME/vt2 \
#     bash runbooks/PI-RUNBOOK-vt-session2-graph-idor.sh 2>&1 | tee $HOME/vt2/vt2.log
#   (mkdir -p $HOME/vt2 first so tee has a dir)
#
# SAFETY: only OUR OWN objects created/read/deleted. Keys from env, MASKED in
# output, never committed. In scope. Free-tier safe pacing.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vt2}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<account A api key>}"
VT_KEY_B="${VT_KEY_B:-}"
PACE="${PACE:-16}"
B="https://www.virustotal.com/api/v3"
UA='vt-research/1.0 (authorized VRP testing)'
mask(){ local k="$1"; [ -n "$k" ] && printf '%s…%s' "${k:0:4}" "${k: -3}" || printf '<none>'; }
echo "============================================================"
echo "VIRUSTOTAL GRAPH IDOR TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "A=$(mask "$VT_KEY")  B=$(mask "$VT_KEY_B")  pace=${PACE}s"
echo "Only our own objects. Keys masked, never committed."
echo "============================================================"; echo ""

req(){ # method path auth(A|B|NONE) datafile?
  local method="$1" path="$2" auth="$3" df="${4:-}" tag hdr=()
  tag=$(printf '%s_%s' "$method" "$path" | tr -c 'A-Za-z0-9' '_')
  case "$auth" in A) hdr=(-H "x-apikey: $VT_KEY");; B) hdr=(-H "x-apikey: $VT_KEY_B");; esac
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
  echo "  /graphs/$PUBID -> HTTP $code ; graph_data shape:"
  python3 - "$OUTDIR/GET__graphs_${PUBID}.json" <<'PY' 2>/dev/null || echo "    (parse failed)"
import json,sys
d=json.load(open(sys.argv[1])); a=d.get('data',{}).get('attributes',{})
gd=a.get('graph_data',{})
print("    attrs:",sorted(a.keys()))
print("    graph_data keys:",sorted(gd.keys()) if isinstance(gd,dict) else type(gd).__name__)
print("    graph_data.version:",gd.get('version') if isinstance(gd,dict) else None)
PY
fi
echo ""

echo "═══ B: CREATE A PRIVATE GRAPH (account A) — try schema variants ═══"
GID=""; PRIV=""
i=0
for BODY in \
  '{"data":{"type":"graph","attributes":{"private":true,"graph_data":{"version":"api-v1","data":{"nodes":[],"edges":[]}}}}}' \
  '{"data":{"type":"graph","attributes":{"private":true,"graph_data":{"version":"5.0.0","data":{"nodes":[],"edges":[]}}}}}' \
  '{"data":{"type":"graph","attributes":{"private":true,"graph_data":{"nodes":[],"edges":[]}}}}' \
  '{"data":{"type":"graph","attributes":{"private":true}}}' ; do
  i=$((i+1)); printf '%s' "$BODY" > "$OUTDIR/newgraph$i.json"
  code=$(req POST "/graphs" A "$OUTDIR/newgraph$i.json"); sleep "$PACE"
  GID=$(python3 -c "import json;print(json.load(open('$OUTDIR/POST__graphs.json')).get('data',{}).get('id',''))" 2>/dev/null)
  if [ -n "$GID" ]; then
    PRIV=$(python3 -c "import json;print(json.load(open('$OUTDIR/POST__graphs.json')).get('data',{}).get('attributes',{}).get('private'))" 2>/dev/null)
    echo "  variant $i -> HTTP $code ; created id=$GID ; private=$PRIV"; break
  else
    echo "  variant $i -> HTTP $code ; $(head -c 120 "$OUTDIR/POST__graphs.json" | tr -d '\n')"
  fi
done
if [ -z "$GID" ]; then echo "  !! all create variants failed — inspect $OUTDIR/POST__graphs.json"; exit 0; fi
code=$(req GET "/graphs/$GID" A); sleep "$PACE"
echo "  owner GET /graphs/$GID -> HTTP $code (sanity: 200 for owner)"
echo ""

echo "═══ C: ACCESS-CONTROL MATRIX on the PRIVATE graph ═══"
echo "  (expect every non-owner row = 401/403/404; a 200-with-data = IDOR)"
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

echo "═══ C2: COLLABORATOR ABUSE — can B add ITSELF as viewer/editor of A's private graph? ═══"
if [ -n "$VT_KEY_B" ]; then
  BUSER=$(python3 -c "import json;print(json.load(open('$OUTDIR/GET__users_? .json')) if False else '')" 2>/dev/null)
  for REL in viewers editors; do
    printf '{"data":[{"type":"user","id":"%s"}]}' "${VT_USER_B:-self}" > "$OUTDIR/addrel.json"
    code=$(req POST "/graphs/$GID/relationships/$REL" B "$OUTDIR/addrel.json"); sleep "$PACE"
    echo "  B POST /graphs/$GID/relationships/$REL -> HTTP $code (200/201 = B granted itself access = IDOR)"
    grep -q '"error"' "$OUTDIR/POST__graphs_${GID}_relationships_${REL}.json" 2>/dev/null && echo "    (denied)" || echo "$REL granted?" >> "$OUTDIR/idor-hits.txt"
  done
else
  echo "  (skipped — set VT_KEY_B and VT_USER_B=<account B username> to test)"
fi
echo ""

echo "═══ D: CLEANUP ═══"
code=$(req DELETE "/graphs/$GID" A); sleep "$PACE"
echo "  DELETE /graphs/$GID -> HTTP $code"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/idor-hits.txt" ]; then
  echo "  *** POSSIBLE IDOR / BROKEN ACL:"
  sed 's/^/    /' "$OUTDIR/idor-hits.txt"
  echo "  CONFIRM by hand from a clean session before claiming."
else
  echo "  Clean negative: VT enforces private-graph ACLs (anon + account B denied)."
  echo "  Next angles: comments/votes object IDOR, or graph 'items' node leak via a"
  echo "  public graph that references private file scans."
fi
echo ""
echo "Evidence: $OUTDIR (raw json local; do not commit)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
