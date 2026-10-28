#!/usr/bin/env bash
# spa-map.sh — read a single-page app's own JavaScript and write down what it
# says about the API behind it.
#
# Why. The intrinsic.ai estate came into scope on 2026-10-28 and five of its
# hosts answer 200 with the title "Intrinsic Flowstate". An SPA shell answers
# 200 whether or not you are signed in, so the status code says nothing at all
# about authorisation. Everything that matters — which API host the app talks
# to, which routes exist, which OAuth client it uses, whether a source map was
# shipped — is written in the bundle the server hands to anyone who asks.
#
# Scope discipline, and it is load-bearing here. A bundle references assets on
# hosts we have no authorisation for (CDNs, analytics, Google's own origins).
# Those are LISTED and never fetched: scope-check decides what may be
# requested, and an asset URL in someone else's HTML is not a grant. The same
# rule is why source maps are only probed when they are same-origin.
#
# Usage:
#   SCOPE_FILE=$PWD/config/scope-acquisitions.yaml ./scripts/spa-map.sh flowstate-dev.intrinsic.ai
#   SCOPE_FILE=... HOSTS_FILE=/tmp/live.txt ./scripts/spa-map.sh
#   SCOPE_FILE=... ./scripts/spa-map.sh ~/acq/live-20261028-2344.tsv
#   ./scripts/spa-map.sh --selftest
set -uo pipefail

# Byte order for every sort in this file, and it is not cosmetic. The self-test
# compares an extractor's output against a written-out expectation, and the
# first run on the Pi failed where the same code passed in a container: a
# UTF-8 collation ignores punctuation, so "/apiary-x" sorts before
# "/api/v1/workcells", while a byte comparison puts "/api/v1/..." first ("/" is
# 0x2f, below "a"). Without this, the same bundle produces differently ordered
# output files on two machines, and tomorrow's diff against today's run shows
# changes that are only the locale.
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SCOPE="$HERE/scope-check.sh"
OUT="${ACQ_OUT:-$HOME/acq}"
STAMP="$(date +%Y%m%d-%H%M)-$$"
DELAY="${DELAY:-0.3}"
MAX_ASSETS="${MAX_ASSETS:-25}"
UA='Mozilla/5.0 (bug-bounty research; azmolhaque95@gmail.com)'

# ---- extraction ---------------------------------------------------------------
# Every extractor reads a file and writes one finding per line. They are
# separate functions so the self-test can drive them without a network.

assets_of() {   # assets_of <file> <host>  ->  "SAME|OFF<TAB>url"
  local f="$1" host="$2"
  # src= and href= on script/link, plus bare .js references in the HTML.
  grep -oE '(src|href)="[^"]+\.(js|mjs|cjs)([?#][^"]*)?"' "$f" 2>/dev/null \
    | sed -E 's/^(src|href)="//; s/"$//' \
    | while IFS= read -r u; do
        case "$u" in
          //*)      printf 'OFF\thttps:%s\n' "$u" ;;
          http://*|https://*)
            local h="${u#*://}"; h="${h%%/*}"; h="${h%%:*}"
            if [ "$h" = "$host" ]; then printf 'SAME\t%s\n' "$u"
            else printf 'OFF\t%s\n' "$u"; fi ;;
          /*)       printf 'SAME\thttps://%s%s\n' "$host" "$u" ;;
          *)        printf 'SAME\thttps://%s/%s\n' "$host" "$u" ;;
        esac
      done | sort -u
}

hosts_in() {    # hostnames worth knowing about
  # apps.googleusercontent.com is dropped here on purpose: an OAuth client id
  # ends in it, so leaving it in reports every client id a second time as if
  # it were a host. secrets_in already has it.
  #
  # Internal-looking suffixes are NOT matched bare. The first live run put
  # `a.local`, `e.internal`, `this.local` and `window.local` in the report —
  # about thirty of forty-four lines — because minified JavaScript is full of
  # property chains that read exactly like a hostname. An internal name that
  # the app really talks to appears inside a URL, so that is where it is read
  # from, and only names that are internal-looking or an address survive. A
  # list that mixes thirty inventions with ten facts is worse than no list:
  # somebody eventually reports the inventions as an internal hostname leak.
  {
    grep -ohE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.(intrinsic\.(ai|dev|equipment)|googleapis\.com|appspot\.com|run\.app|cloudfunctions\.net|firebaseio\.com|firebaseapp\.com|googleusercontent\.com)' "$@" 2>/dev/null
    grep -ohE 'https?://[a-zA-Z0-9][a-zA-Z0-9.-]{2,}' "$@" 2>/dev/null \
      | sed -E 's#^https?://##' \
      | grep -E '\.(internal|local|corp|lan|intranet)$|^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
  } | tr 'A-Z' 'a-z' | grep -v 'apps\.googleusercontent\.com$' | sort -u
}

paths_in() {    # quoted absolute paths, which is the route inventory
  grep -ohE '"/[A-Za-z0-9][A-Za-z0-9/_.:$~{}-]{3,120}"' "$@" 2>/dev/null \
    | sed -E 's/^"//; s/"$//' | sort -u
}

secrets_in() {  # things that should not be in a public bundle
  {
    # Google API keys are a fixed shape; the length is the whole check, so a
    # short lookalike must not match.
    grep -ohE 'AIza[0-9A-Za-z_-]{35}' "$@" 2>/dev/null
    grep -ohE '[0-9]{6,}-[a-z0-9]{16,}\.apps\.googleusercontent\.com' "$@" 2>/dev/null
    grep -ohE 'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}' "$@" 2>/dev/null
    grep -ohE '(ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}' "$@" 2>/dev/null
    grep -ohE '\-\-\-\-\-BEGIN [A-Z ]*PRIVATE KEY' "$@" 2>/dev/null
    grep -ohE 'storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{2,62}' "$@" 2>/dev/null
  } | sort -u
}

maps_in() {     # sourceMappingURL references
  grep -ohE 'sourceMappingURL=[^ */"'"'"']+' "$@" 2>/dev/null \
    | sed 's/^sourceMappingURL=//' | sort -u
}

# ---- self-test ----------------------------------------------------------------
# No network. Fixtures are written by hand so that a log which happens to hold
# nothing cannot make a broken extractor look correct.
selftest() {
  local d; d="$(mktemp -d)"; local fail=0
  cat > "$d/shell.html" <<'HTML'
<!doctype html><html><head>
<script src="/assets/main-abc123.js"></script>
<link rel="modulepreload" href="/assets/vendor-def456.js">
<script src="https://cdn.example.net/analytics.js"></script>
<script src="//fonts.example.org/loader.js"></script>
<script>window.__ENV={apiKey:"AIzaSyB1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
  shortLookalike:"AIzaTooShort",
  clientId:"123456789012-abcdefghijklmnopqrstuvwx.apps.googleusercontent.com",
  api:"https://flowstate-api-dev.intrinsic.ai",
  controller:"http://robot-controller.internal:8080/status",
  minified:function(e){return this.local&&e.internal&&window.local},
  routes:["/api/v1/workcells","/graphql","/apiary-not-a-route-x","/healthz"]};
</script>
</head><body></body></html>
HTML
  printf '//# sourceMappingURL=main-abc123.js.map\n' > "$d/main.js"

  # assets: two same-origin, two off-origin, and the off-origin ones must be
  # labelled rather than fetched.
  local got want
  got="$(assets_of "$d/shell.html" app.intrinsic.ai | sort | paste -sd';')"
  want='OFF	https://cdn.example.net/analytics.js;OFF	https://fonts.example.org/loader.js;SAME	https://app.intrinsic.ai/assets/main-abc123.js;SAME	https://app.intrinsic.ai/assets/vendor-def456.js'
  [ "$got" = "$want" ] || { echo "!! assets_of: got [$got]"; fail=1; }

  # secrets: the real key and client id, not the short lookalike.
  got="$(secrets_in "$d/shell.html" | paste -sd';')"
  case "$got" in
    *AIzaSyB1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p*) : ;;
    *) echo "!! secrets_in missed the API key (39-char AIza shape): [$got]"; fail=1 ;;
  esac
  case "$got" in
    *AIzaTooShort*) echo "!! secrets_in matched a short lookalike"; fail=1 ;;
  esac
  case "$got" in
    *123456789012-abcdefghijklmnopqrstuvwx.apps.googleusercontent.com*) : ;;
    *) echo "!! secrets_in missed the OAuth client id"; fail=1 ;;
  esac

  # hosts: the API host and the internal name that appears inside a URL, and
  # NOT this.local / e.internal / window.local, which are minified property
  # chains. Nothing from example.net either: a CDN in someone's HTML is not an
  # asset of the target.
  got="$(hosts_in "$d/shell.html" | paste -sd';')"
  want='flowstate-api-dev.intrinsic.ai;robot-controller.internal'
  [ "$got" = "$want" ] || { echo "!! hosts_in: got [$got], wanted [$want]"; fail=1; }

  # paths: the three real ones; /apiary-not-a-route-x is a path too and is
  # expected to appear — the point of the check is that nothing is invented
  # and nothing is dropped.
  got="$(paths_in "$d/shell.html" | paste -sd';')"
  want='/api/v1/workcells;/apiary-not-a-route-x;/assets/main-abc123.js;/assets/vendor-def456.js;/graphql;/healthz'
  [ "$got" = "$want" ] || { echo "!! paths_in: got [$got]"; fail=1; }

  got="$(maps_in "$d/main.js" | paste -sd';')"
  [ "$got" = "main-abc123.js.map" ] || { echo "!! maps_in: got [$got]"; fail=1; }

  rm -rf "$d"
  if [ "$fail" -eq 0 ]; then
    echo "POSITIVE  assets split same-origin from off-origin, a short key lookalike is ignored, and a source map is seen"
    return 0
  fi
  echo "!! BROKEN: fix the extractors before running this against a target"
  return 2
}

[ "${1:-}" = "--selftest" ] && { selftest; exit $?; }

# ---- run ----------------------------------------------------------------------
command -v curl >/dev/null || { echo "!! curl missing"; exit 1; }
[ -x "$SCOPE" ]           || { echo "!! scope-check.sh missing — CLAUDE.md 0 says stop"; exit 1; }
mkdir -p "$OUT"
WORK="$OUT/spa-$STAMP"; mkdir -p "$WORK"
LOG="$OUT/spa-$STAMP.log"

# host list: args (hosts or a live TSV), or HOSTS_FILE
HOSTS=()
if [ "$#" -gt 0 ] && [ -f "$1" ]; then
  mapfile -t HOSTS < <(awk -F'\t' 'NR>1 && $3 !~ /^(DEAD|ERR|000)$/ {print $1}' "$1" | sort -u)
elif [ "$#" -gt 0 ]; then
  HOSTS=("$@")
elif [ -n "${HOSTS_FILE:-}" ]; then
  mapfile -t HOSTS < <(grep -vE '^\s*(#|$)' "$HOSTS_FILE" | tr 'A-Z' 'a-z' | sort -u)
else
  echo "!! give a host, a live TSV, or HOSTS_FILE"; exit 1
fi

{
echo "# what the app's own JavaScript says about its API"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# scope: ${SCOPE_FILE:-<default>}"
echo "# work : $WORK"
echo
echo "== CONTROL =="
selftest || exit 2
echo

echo "== ${#HOSTS[@]} host(s) =="
echo

for h in "${HOSTS[@]}"; do
  [ -n "$h" ] || continue
  if ! "$SCOPE" "$h" >/dev/null 2>&1; then
    printf '%-34s SKIP      not in scope\n' "$h"; continue
  fi

  hd="$WORK/$h"; mkdir -p "$hd"
  code="$(curl -sS -m 25 -L --max-redirs 10 -A "$UA" \
          -D "$hd/shell.hdr" -o "$hd/shell.html" -w '%{http_code}' "https://$h/" 2>/dev/null)"
  sz=$(wc -c < "$hd/shell.html" 2>/dev/null || echo 0)
  if [ "${code:0:1}" != "2" ]; then
    printf '%-34s NO-SHELL  HTTP %s (%s bytes) — not "no javascript", the page did not load\n' "$h" "$code" "$sz"
    sleep "$DELAY"; continue
  fi

  mapfile -t A < <(assets_of "$hd/shell.html" "$h")
  same=0; off=0; fetched=0; failed=0
  : > "$hd/offorigin.txt"
  for e in "${A[@]}"; do
    kind="${e%%$'\t'*}"; url="${e##*$'\t'}"
    if [ "$kind" = "OFF" ]; then
      off=$((off+1)); echo "$url" >> "$hd/offorigin.txt"; continue
    fi
    same=$((same+1))
    [ "$fetched" -ge "$MAX_ASSETS" ] && continue
    ah="${url#*://}"; ah="${ah%%/*}"
    "$SCOPE" "$ah" >/dev/null 2>&1 || { echo "$url" >> "$hd/offorigin.txt"; continue; }
    n=$(printf '%s' "$url" | md5sum | cut -c1-8)
    if curl -sS -m 30 -A "$UA" -o "$hd/asset-$n.js" "$url" 2>/dev/null \
       && [ -s "$hd/asset-$n.js" ]; then
      fetched=$((fetched+1))
    else
      failed=$((failed+1)); rm -f "$hd/asset-$n.js"
    fi
    sleep "$DELAY"
  done

  files=("$hd/shell.html")
  for f in "$hd"/asset-*.js; do [ -f "$f" ] && files+=("$f"); done

  hosts_in  "${files[@]}" > "$hd/hosts.txt"
  paths_in  "${files[@]}" > "$hd/paths.txt"
  secrets_in "${files[@]}" > "$hd/secrets.txt"
  maps_in   "${files[@]}" > "$hd/maps.txt"

  nh=$(grep -c . "$hd/hosts.txt" || true)
  np=$(grep -c . "$hd/paths.txt" || true)
  ns=$(grep -c . "$hd/secrets.txt" || true)
  nm=$(grep -c . "$hd/maps.txt" || true)

  printf '%-34s HTTP %-3s  assets %d same / %d off, %d fetched, %d failed | %d host, %d path, %d secret, %d map\n' \
         "$h" "$code" "$same" "$off" "$fetched" "$failed" "$nh" "$np" "$ns" "$nm"
  [ "$failed" -gt 0 ] && echo "      note: $failed asset(s) could not be fetched — the counts above are a floor, not a total"

  # A shipped source map is the whole frontend source. Probe only same-origin,
  # in-scope maps, and record the status either way.
  if [ "$nm" -gt 0 ]; then
    while IFS= read -r m; do
      [ -n "$m" ] || continue
      case "$m" in
        http://*|https://*|//*) echo "      map off-origin, not fetched: $m"; continue ;;
      esac
      mu="https://$h/$(printf '%s' "$m" | sed 's#^\./##; s#^/##')"
      # Most bundlers emit the map beside the asset, so try the asset dir too.
      for cand in "$mu" "https://$h/assets/$(basename "$m")" "https://$h/static/js/$(basename "$m")"; do
        mc="$(curl -sS -m 25 -o "$hd/map-$(basename "$m")" -w '%{http_code}' -A "$UA" "$cand" 2>/dev/null)"
        msz=$(wc -c < "$hd/map-$(basename "$m")" 2>/dev/null || echo 0)
        if [ "$mc" = "200" ] && [ "$msz" -gt 1000 ]; then
          echo "      *** SOURCE MAP SERVED: $cand ($msz bytes) ***"
          break
        else
          rm -f "$hd/map-$(basename "$m")"
        fi
        sleep "$DELAY"
      done
    done < "$hd/maps.txt"
  fi

  [ "$ns" -gt 0 ] && { echo "      secrets seen in the bundle:"; sed 's/^/        /' "$hd/secrets.txt"; }
  [ "$nh" -gt 0 ] && { echo "      hosts named:"; sed 's/^/        /' "$hd/hosts.txt"; }
  sleep "$DELAY"
done

echo
echo "== every path any bundle named, by how many hosts named it =="
cat "$WORK"/*/paths.txt 2>/dev/null | sort | uniq -c | sort -rn \
  | grep -vE '\.(js|mjs|css|png|svg|jpg|woff2?|ico|map)"?$' | head -60

cat <<'NOTE'

== reading it ==
A path in a bundle is a route the app believes in, not a route you may call,
and calling one is the next step rather than this one. A secret in a bundle is
only a finding if it unlocks something: an AIza key is usually a browser key
restricted by referrer and Google's own VRP drops unrestricted-key reports
unless you show what it reaches. The two things here that are worth dropping
everything for:

  SOURCE MAP SERVED   the frontend source, including every route string and
                      every client-side permission check, which is the map for
                      the server-side test that follows.
  an API host named   especially one the live sweep has not seen, and most
                      especially a dev or staging API named by a production
                      bundle.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "work : $WORK"
echo "log  : $LOG"
