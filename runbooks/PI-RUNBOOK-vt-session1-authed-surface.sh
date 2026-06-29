#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal (acquisition, in-scope) authenticated surface map
# Portable: Termux / Linux / Pi.
#
# Pivot target: VirusTotal. API-first, self-service signup, multi-tenant with
# public/private object visibility (graphs, collections, comments, user objects)
# = clean IDOR/BOLA surface testable with curl + x-apikey. This session maps the
# REAL authenticated object-id endpoints empirically (200/401/403/404) so the
# next session runs a precise two-account IDOR test.
#
# PREP (you do once, free):
#   1. Create a free VirusTotal account: https://www.virustotal.com/gui/join-us
#   2. Get your API key: https://www.virustotal.com/gui/my-apikey
#   3. Note your username (profile). Then run with:
#        VT_KEY=<your_api_key> VT_USER=<your_username> \
#          OUTDIR=$HOME/vt1 bash runbooks/PI-RUNBOOK-vt-session1-authed-surface.sh
#
# SAFETY: read-only GET with YOUR OWN key. No writes this session. The key is read
# from env and NEVER printed in full / committed. In scope (www.virustotal.com).
# Respect VT rate limits (free tier ~4 req/min) -> PACE defaults high.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vt1}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<your free VirusTotal api key> (see PREP in this script header)}"
VT_USER="${VT_USER:-}"
PACE="${PACE:-16}"   # free tier = 4/min; 16s keeps us safely under
B="https://www.virustotal.com/api/v3"
UA='vt-research/1.0 (authorized VRP testing)'
mask="${VT_KEY:0:4}…${VT_KEY: -3}"
echo "============================================================"
echo "VIRUSTOTAL AUTHED SURFACE MAP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "key=$mask  user=${VT_USER:-<unset>}  pace=${PACE}s/req (free-tier safe)  read-only"
echo "============================================================"; echo ""

vget(){ # path  -> prints code + short body; saves body
  local p="$1" tag; tag=$(printf '%s' "$p" | tr -c 'A-Za-z0-9' '_')
  local m code ct
  m=$(curl -s -L --max-time 25 -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" \
       -H 'Accept: application/json' -o "$OUTDIR/$tag.json" \
       -w '%{http_code}|%{content_type}|%{size_download}' "$B$p" 2>/dev/null) || m="000|-|0"
  code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
  local snip; snip=$(head -c 180 "$OUTDIR/$tag.json" 2>/dev/null | tr '\n\r' '  ')
  local f=""; case "$code" in 200) f="[OK]";; 401) f="[no-auth]";; 403) f="[forbidden]";; 404) f="[404]";; 429) f="[rate-limited]";; esac
  printf "  [%s] %-42s %s  size=%s\n" "$code" "$p" "$f" "$size"
  echo "       :: ${snip:0:140}"
  sleep "$PACE"
}

echo "═══ A: IDENTITY (confirm key works, find my user id) ═══"
[ -n "$VT_USER" ] && vget "/users/$VT_USER"
# quota object also reveals the user id
vget "/users/$VT_USER/api_usage" 2>/dev/null || true
echo ""

echo "═══ B: MY OBJECT COLLECTIONS (graphs / collections / comments) ═══"
# these are the privacy-controlled, object-id endpoints = IDOR surface
[ -n "$VT_USER" ] && {
  vget "/users/$VT_USER/graphs"
  vget "/users/$VT_USER/collections"
  vget "/users/$VT_USER/comments"
  vget "/users/$VT_USER/groups"
}
echo ""

echo "═══ C: OBJECT-TYPE ENDPOINTS (existence + auth model) ═══"
for p in \
  "/graphs" "/collections" "/comments" "/groups" \
  "/ioc_stream" "/monitor/items" "/intelligence/hunting_rulesets" \
  "/private/files" "/metadata"; do
  vget "$p"
done
echo ""

echo "════════════════════════════════════════════"
echo "READ-BACK / NEXT"
echo "════════════════════════════════════════════"
echo "  * Note which object types return [OK] and carry an 'id' + a visibility/"
echo "    'private'/'owner' attribute (graphs & collections do). Those are the IDOR"
echo "    targets. Capture one of YOUR object ids from Section B."
echo "  * session2 (two-account IDOR test): with account A create a PRIVATE graph/"
echo "    collection; then with account B's key AND unauthenticated, GET that id."
echo "    If B/unauth can read A's PRIVATE object => confirmed IDOR/BOLA."
echo "  * To prep, create a SECOND free VT account for the cross-account key."
echo ""
echo "  Paste this output (it contains no secrets — key is masked)."
echo "Evidence: $OUTDIR  (raw json saved locally; do not commit)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
