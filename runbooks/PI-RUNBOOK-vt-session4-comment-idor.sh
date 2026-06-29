#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal comment object-authorization (BOLA) test
# Portable: Termux / Linux / Pi.
#
# Prior VT angles closed honestly: private graphs premium-gated; graph feed no
# leak; user real-name is the INTENDED public display name (shown on profile page
# logged-out). Remaining free-tier angle = a WRITE surface: comments. Comments
# carry ids; test whether a NON-OWNER (account B / unauth) can DELETE or EDIT
# account A's comment => broken object-level authorization (BOLA), Medium.
#
# Flow: A posts a benign comment on the canonical EICAR test file (heavily-
# commented, benign), capture comment id; B and unauth try DELETE + PATCH; then A
# deletes it (cleanup, state restored). Any non-owner 200 on delete/edit = BOLA.
#
# PREP: VT_KEY=<A> VT_KEY_B=<B>
#   VT_KEY=<A> VT_KEY_B=<B> OUTDIR=$HOME/vt4 \
#     bash runbooks/PI-RUNBOOK-vt-session4-comment-idor.sh 2>&1 | tee $HOME/vt4/vt4.log
#
# SAFETY: one benign comment, deleted at the end (no lasting content). Keys env-
# only, masked, never committed. In scope.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vt4}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<account A key>}"
: "${VT_KEY_B:?set VT_KEY_B=<account B key> (needed for the cross-account test)}"
PACE="${PACE:-16}"
B="https://www.virustotal.com/api/v3"
UA='vt-research/1.0 (authorized VRP testing)'
# EICAR test file sha256 (the canonical benign AV test artifact)
HASH="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
mask(){ local k="$1"; [ -n "$k" ] && printf '%s…%s' "${k:0:4}" "${k: -3}" || printf '<none>'; }
echo "============================================================"
echo "VT COMMENT BOLA TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "A=$(mask "$VT_KEY")  B=$(mask "$VT_KEY_B")  target=EICAR file comments"
echo "One benign comment, deleted at end. Keys masked, never committed."
echo "============================================================"; echo ""

req(){ # method path auth(A|B|NONE) datafile?
  local method="$1" path="$2" auth="$3" df="${4:-}" tag hdr=()
  tag=$(printf '%s_%s' "$method" "$path" | tr -c 'A-Za-z0-9' '_')
  case "$auth" in A) hdr=(-H "x-apikey: $VT_KEY");; B) hdr=(-H "x-apikey: $VT_KEY_B");; esac
  local args=(-s -L --max-time 25 -H "User-Agent: $UA" -H 'Accept: application/json' "${hdr[@]}" -X "$method")
  [ -n "$df" ] && args+=(-H 'Content-Type: application/json' --data @"$df")
  curl "${args[@]}" -o "$OUTDIR/$tag.json" -w '%{http_code}' "$B$path" 2>/dev/null
}

echo "═══ 1: account A posts a benign comment ═══"
printf '{"data":{"type":"comment","attributes":{"text":"benign research test comment - please ignore #%s"}}}' "$(date -u +%s 2>/dev/null || echo x)" > "$OUTDIR/c.json"
code=$(req POST "/files/$HASH/comments" A "$OUTDIR/c.json"); sleep "$PACE"
CID=$(python3 -c "import json;print(json.load(open('$OUTDIR/POST__files_${HASH}_comments.json')).get('data',{}).get('id',''))" 2>/dev/null)
echo "  POST comment -> HTTP $code ; id=${CID:-FAILED}"
if [ -z "$CID" ]; then echo "  body:"; head -c 200 "$OUTDIR/POST__files_${HASH}_comments.json" | sed 's/^/    /'; echo; echo "  (commenting may be gated; inspect)"; exit 0; fi
echo ""

echo "═══ 2: NON-OWNER tamper attempts on A's comment ($CID) ═══"
echo "  (expect every row 401/403/404; a 200 = BOLA)"
: > "$OUTDIR/bola.txt"
printf '{"data":{"type":"comment","id":"%s","attributes":{"text":"EDITED BY NON-OWNER"}}}' "$CID" > "$OUTDIR/edit.json"
for AUTH in B NONE; do
  # edit attempt
  code=$(req PATCH "/comments/$CID" "$AUTH" "$OUTDIR/edit.json"); sleep "$PACE"
  err=$(grep -c '"error"' "$OUTDIR/PATCH__comments_${CID}.json" 2>/dev/null)
  v="ok(denied)"; { [ "$code" = "200" ] && [ "${err:-0}" = "0" ]; } && { v="*** EDIT LEAK ***"; echo "edit|$AUTH|$code" >> "$OUTDIR/bola.txt"; }
  printf "  PATCH auth=%-4s -> HTTP %s  %s\n" "$AUTH" "$code" "$v"
done
# delete attempts LAST among non-owners (B then NONE), but keep one to confirm owner-delete cleanup
for AUTH in B NONE; do
  code=$(req DELETE "/comments/$CID" "$AUTH"); sleep "$PACE"
  # a 200 here means the non-owner deleted A's comment
  if [ "$code" = "200" ]; then echo "  DELETE auth=$AUTH -> HTTP 200  *** DELETE LEAK (non-owner removed A's comment) ***"; echo "delete|$AUTH|$code" >> "$OUTDIR/bola.txt"
  else printf "  DELETE auth=%-4s -> HTTP %s  ok(denied)\n" "$AUTH" "$code"; fi
done
echo ""

echo "═══ 3: cleanup (owner A deletes the comment) ═══"
code=$(req DELETE "/comments/$CID" A); sleep "$PACE"
echo "  owner DELETE -> HTTP $code (204/200 = removed; 404 = a non-owner already deleted it = BOLA confirmed)"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/bola.txt" ]; then
  echo "  *** COMMENT BOLA — non-owner modified/deleted A's comment:"
  sed 's/^/    /' "$OUTDIR/bola.txt"
  echo "  Confirm by hand (post as A, delete as B) then report (Medium: integrity of"
  echo "  community comments; any user can delete/forge others' comments)."
else
  echo "  Clean negative: VT enforces comment ownership (non-owner edit/delete denied)."
  echo "  VT free-tier surface now largely exhausted. Recommend pivot: Waze (backup)"
  echo "  or revisit a VT premium-gated area only if you have a paid/Enterprise trial."
fi
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
