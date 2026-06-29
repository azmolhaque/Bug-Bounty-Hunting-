#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session6: Firebase RTDB safe-read test + deep route map
# Portable: Termux / Linux / Pi. Reuses session5's extracted strings (no re-DL).
#
# session5 recovered from the APK:
#   real API bases: lapi/rapi.photomath.net /v{N}/ , bhapi.photomath.net /api/v{N}/
#   and a Firebase Realtime DB:  https://erudite-idea-777.firebaseio.com
#   (the AIza key + ...googleusercontent.com oauth id are public-by-design = dropped)
#
# TWO jobs:
#  A. FIREBASE RTDB misconfig test — THE lead. If rules allow public read, the
#     whole DB is readable unauth. CONFIRM SAFELY with ?shallow=true (returns only
#     top-level KEY NAMES, no values => no PII pulled). LOCKED => drop. OPEN =>
#     real finding (cross-user data exposure); we STOP at key-names + count.
#  B. DEEP ROUTES — session5 missed Retrofit endpoint templates (unquoted
#     "{id}" path strings in the dex). Re-mine strings for {placeholder} routes +
#     version-prefixed paths, build real URLs on the known bases, probe unauth.
#
# SAFETY: read-only GET, >=0.3s/req. Firebase: shallow key-names ONLY, never dump
# values, never write. Never use any secret. No fuzzing (only mined routes).
#
# Run (Termux): OUTDIR=$HOME/pm5 bash runbooks/PI-RUNBOOK-photomath-session6-firebase-routes.sh \
#                 2>&1 | tee $HOME/pm5/pm6.log
#   (OUTDIR must point at session5's dir so strings.txt is reused; default below)
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/pm5}"; export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'
PACE="${PACE:-0.3}"
FB="${FB:-erudite-idea-777}"
echo "============================================================"
echo "PHOTOMATH session6  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Firebase RTDB safe test + deep route map. Read-only. Shallow keys only."
echo "============================================================"; echo ""

# ── ensure strings.txt exists (reuse session5; re-extract if needed) ──
if [ ! -s "$OUTDIR/strings.txt" ]; then
  echo "  (strings.txt missing — re-extracting from $OUTDIR/ex ...)"
  : > "$OUTDIR/strings.txt"
  find "$OUTDIR/ex" -type f 2>/dev/null | while read -r f; do
    grep -aoE '[[:print:]]{4,}' "$f" 2>/dev/null >> "$OUTDIR/strings.txt" || true
  done
fi
echo "  strings corpus: $(wc -c < "$OUTDIR/strings.txt" 2>/dev/null || echo 0) bytes"
echo ""

# ── A: FIREBASE RTDB safe read test ──
echo "═══ A: FIREBASE RTDB misconfig test ($FB) ═══"
fb_test(){ # base_url
  local U="$1"
  # shallow => key NAMES only, no values. The responsible confirmation.
  local m code ct
  m=$(curl -s -L --max-time 18 -H "User-Agent: $UA" -o "$OUTDIR/fb.json" \
       -w '%{http_code}|%{content_type}' "$U/.json?shallow=true" 2>/dev/null) || m="000|-"
  code="${m%%|*}"; ct="${m#*|}"
  local body; body=$(head -c 300 "$OUTDIR/fb.json" 2>/dev/null | tr '\n' ' ')
  echo "  GET $U/.json?shallow=true -> HTTP $code (${ct%%;*})"
  echo "    body: ${body:0:200}"
  if printf '%s' "$body" | grep -qiE 'permission denied|"error"'; then
    echo "    => LOCKED (rules deny public read). Not a finding. Good."
    return 1
  fi
  if printf '%s' "$body" | grep -qE '^\s*\{.*\}|^\s*null\s*$'; then
    if printf '%s' "$body" | grep -qE '^\s*null\s*$'; then
      echo "    => readable but EMPTY/null at root (open rules but no data here)."
    else
      local nk; nk=$(grep -oE '"[^"]+"' "$OUTDIR/fb.json" 2>/dev/null | wc -l)
      echo "    *** OPEN: shallow read returned top-level KEY NAMES (~$nk keys)."
      echo "    *** This is public-read RTDB misconfig => cross-user data exposure."
      echo "    STOP HERE. Do NOT pull values. Key names are enough to confirm + report."
    fi
    return 0
  fi
  echo "    => non-JSON / unclear — inspect $OUTDIR/fb.json by hand."
  return 2
}
HIT_FB=0
fb_test "https://$FB.firebaseio.com" && HIT_FB=1
sleep "$PACE"
# newer-region variants (only if classic locked/odd)
if [ "$HIT_FB" != 1 ]; then
  for R in us-central1 europe-west1 asia-southeast1; do
    fb_test "https://$FB-default-rtdb.$R.firebasedatabase.app" && { HIT_FB=1; break; }
    sleep "$PACE"
  done
fi
# Firestore REST (different product) — safe unauth list attempt of no collection (just root metadata)
echo "  (note: if RTDB locked, app may use Firestore — that needs a different test)"
echo ""

# ── B: deep route extraction (Retrofit {placeholder} templates) ──
echo "═══ B: DEEP ROUTE EXTRACTION ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
s=open(os.path.join(O,"strings.txt"),encoding="utf-8",errors="replace").read()
# Retrofit path templates: tokens containing {placeholder}
tmpl=set(re.findall(r'[A-Za-z0-9][A-Za-z0-9_/.\-]*\{[A-Za-z0-9_]+\}[A-Za-z0-9_/.\-{}]*', s))
# version-prefixed path segments (v1/..., api/v1/...)
verp=set(re.findall(r'\b(?:api/)?v[0-9]{1,2}/[A-Za-z0-9_][A-Za-z0-9_/.\-{}]{1,60}', s))
# plausible endpoint nouns (single segment, likely Retrofit relative paths)
nouns=set(re.findall(r'\b(users?|accounts?|me|profile|subscriptions?|purchases?|receipts?|orders?|history|solutions?|tasks?|problems?|books?|bookpoint|devices?|sessions?|auth|login|token|register|feedback|content|favou?rites?|notebook|bookmarks?)/[A-Za-z0-9_{}\-]{1,40}', s, re.I))
def clean(xs):
    out=[]
    for x in xs:
        x=x.strip().strip('"\'')
        if 3<=len(x)<=80 and not x.startswith(('com.','android','java','kotlin','http://schemas','www.w3')):
            out.append(x)
    return sorted(set(out))
tmpl=clean(tmpl); verp=clean(verp); nouns=clean(nouns)
print(f"  Retrofit {{placeholder}} routes ({len(tmpl)}):")
for t in tmpl[:80]: print("    "+t)
print()
print(f"  version-prefixed paths ({len(verp)}):")
for v in verp[:80]: print("    "+v)
print()
print(f"  endpoint-noun paths ({len(nouns)}):")
for n in nouns[:60]: print("    "+n)
print()
# build probe URLs on the known bases
BASES=["https://lapi.photomath.net/v1/","https://rapi.photomath.net/v1/",
       "https://bhapi.photomath.net/api/v1/"]
probe=set()
for seg in list(tmpl)+list(verp)+list(nouns):
    seg2=seg.lstrip('/')
    # if seg already has v1/ etc, also try directly on host root
    for b in BASES:
        probe.add(b+seg2)
    # versioned segments straight on host
    if re.match(r'(api/)?v[0-9]', seg2):
        for h in ["lapi.photomath.net","rapi.photomath.net","bhapi.photomath.net"]:
            probe.add(f"https://{h}/{seg2}")
open(os.path.join(O,"probe6.txt"),"w").write("\n".join(sorted(probe)))
print(f"  -> {len(probe)} candidate URLs queued for unauth probe")
PYEOF
echo ""

# ── C: probe deep routes unauth ──
echo "═══ C: PROBE DEEP ROUTES (unauth GET) ═══"
: > "$OUTDIR/route6-hits.txt"
if [ -s "$OUTDIR/probe6.txt" ]; then
  n=0
  while read -r U; do
    [ -z "$U" ] && continue
    n=$((n+1)); [ "$n" -gt "${MAXPROBE:-150}" ] && { echo "  (capped at $MAXPROBE)"; break; }
    PU=$(printf '%s' "$U" | sed -E 's/\{[^}]+\}/1/g')
    m=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" \
         -o "$OUTDIR/pb6.tmp" -w '%{http_code}|%{content_type}|%{size_download}' "$PU" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    case "$code" in
      404|000) : ;;
      *) snip=$(head -c 160 "$OUTDIR/pb6.tmp" 2>/dev/null | tr '\n\r' '  ')
         f=""; case "$code" in 200) f="[OPEN!]";; 401|403) f="[auth->IDOR target]";; 405) f="[exists/method]";; 400) f="[exists/badreq]";; esac
         echo "  [$code] $PU  $f"
         echo "    ct=${ct%%;*} size=$size :: ${snip:0:110}"
         echo "$code|$PU" >> "$OUTDIR/route6-hits.txt";;
    esac
    sleep "$PACE"
  done < "$OUTDIR/probe6.txt"
fi
[ -s "$OUTDIR/route6-hits.txt" ] || echo "  (all 404/000 — bases need auth header or app-specific path/version)"
echo ""

echo "════════════════════════════════════════════"
echo "READ-BACK"
echo "════════════════════════════════════════════"
echo "  A. Firebase: 'OPEN' = report-grade misconfig (we have key names only). 'LOCKED' = drop."
echo "  B/C. Any [auth->IDOR target] 401/403 on lapi/rapi/bhapi = real authenticated"
echo "     endpoint -> next session: free test account, capture bearer, test object-id swap."
echo "     Any 400 'exists/badreq' = endpoint exists, wants params -> map it."
echo ""
echo "Evidence: $OUTDIR (fb.json, probe6.txt, route6-hits.txt)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
