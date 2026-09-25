#!/data/data/com.termux/files/usr/bin/bash
# H12 unauthenticated probes — Meta Graph API
# No token, no account, no user data. Read-only GETs.
#
# Uses the oracle found on 2026-09-25:
#   "An active access token must be used..."  -> path component RECOGNISED
#   "Unknown path components: /..."           -> NOT recognised
#
# Rate limited deliberately. Meta throttles unauthenticated traffic and a block
# costs us the whole program. Do not remove the sleeps.

set -u
UA='H12-research'
OUT="${OUT:-$HOME/h12-out}"
mkdir -p "$OUT"

probe() { # $1 = full path after host
  curl -s --max-time 15 -A "$UA" "https://graph.facebook.com/$1"
}

recognised() { # stdin -> 0 if the path component was recognised
  ! grep -q 'Unknown path components'
}

# ---------------------------------------------------------------- test 1
# Enumerate the accepted version set. Completes the legacy-path list that
# T1-T7 will be re-run against.
t1_versions() {
  echo "== test 1: version allowlist  -> $OUT/versions.txt"
  : > "$OUT/versions.txt"
  {
    for M in $(seq 0 25); do echo "$M.0"; done
    for m in $(seq 0 15); do echo "2.$m"; done
    for m in $(seq 0 8);  do echo "3.$m"; done
    for m in $(seq 0 9);  do echo "0.$m"; done
  } | sort -u -t. -k1,1n -k2,2n | while read -r v; do
    if probe "v$v/me" | recognised; then
      printf 'v%-6s ACCEPTED\n' "$v" | tee -a "$OUT/versions.txt"
    fi
    sleep 0.4
  done
  echo "-- accepted versions: $(wc -l < "$OUT/versions.txt")"
}

# ---------------------------------------------------------------- test 2
# Which of the SDK's 525 edge names does the Graph API recognise as a
# ROOT path? Most are node edges (/{id}/client_pages) and should be
# unrecognised at root. Anything that IS recognised at root is an
# undocumented root endpoint and worth a hard look.
#
# Needs edges.txt — see "setup" below.
t2_rootpaths() {
  [ -f "$OUT/edges.txt" ] || { echo "!! run setup first"; return 1; }
  echo "== test 2: root paths  -> $OUT/rootpaths.txt"
  : > "$OUT/rootpaths.txt"
  n=0
  while read -r e; do
    [ -z "$e" ] && continue
    n=$((n+1))
    body=$(probe "v23.0/$e")
    # Class 1 (noise): "Object with ID 'x' does not exist, cannot be loaded..."
    #   = code 100 / subcode 33, the string is treated as an unknown NODE ID.
    # Everything else is signal:
    #   Class 2  GraphMethodException "Please read the Graph API documentation"
    #            -> recognised, GET unsupported
    #   Class 3  "(#200) Provide valid app ID"
    #            -> recognised as a real root endpoint wanting an app ID
    if ! printf '%s' "$body" | grep -q 'does not exist, cannot be loaded'; then
      printf '%-40s %s\n' "$e" "$(printf '%s' "$body" | head -c 150)" \
        | tee -a "$OUT/rootpaths.txt"
    fi
    [ $((n % 50)) -eq 0 ] && echo "   ...$n checked"
    sleep 0.4
  done < "$OUT/edges.txt"
  echo "-- recognised root paths: $(wc -l < "$OUT/rootpaths.txt") of $n"
}

# ---------------------------------------------------------------- setup
setup() {
  cd "$OUT" || exit 1
  if [ ! -d sdk ]; then
    git clone --depth 1 --filter=blob:none -q \
      https://github.com/facebook/facebook-python-business-sdk sdk || return 1
  fi
  grep -rhoE "endpoint='/[a-z_0-9]+'" sdk/facebook_business/adobjects/*.py \
    | sed "s/endpoint='\///;s/'//" | sort -u > "$OUT/edges.txt"
  echo "-- edges.txt: $(wc -l < "$OUT/edges.txt") names"
}

# ---------------------------------------------------------------- test 3
# Same 525 names, but against an OLD version. t2 only ever tested v23.0.
# A root path recognised on a legacy version but NOT on v23.0 is a legacy
# endpoint still routable — which is the whole point of the version axis.
#
#   bash probe-unauth.sh t3 1.0
t3_rootpaths_at() {
  V="${1:-1.0}"
  [ -f "$OUT/edges.txt" ] || { echo "!! run setup first"; return 1; }
  [ -f "$OUT/rootpaths.txt" ] || { echo "!! run t2 first (need the v23.0 baseline)"; return 1; }
  echo "== test 3: root paths at v$V  -> $OUT/rootpaths-v$V.txt"
  : > "$OUT/rootpaths-v$V.txt"
  n=0
  while read -r e; do
    [ -z "$e" ] && continue
    n=$((n+1))
    body=$(probe "v$V/$e")
    printf '%s' "$body" | grep -q 'does not exist, cannot be loaded' || \
      printf '%-40s %s\n' "$e" "$(printf '%s' "$body" | head -c 150)" \
        >> "$OUT/rootpaths-v$V.txt"
    [ $((n % 100)) -eq 0 ] && echo "   ...$n checked"
    sleep 0.4
  done < "$OUT/edges.txt"

  echo
  echo "-- v$V recognised: $(wc -l < "$OUT/rootpaths-v$V.txt")   v23.0 recognised: $(wc -l < "$OUT/rootpaths.txt")"
  echo
  echo "== ONLY on v$V (legacy-only routes — this is the interesting set):"
  comm -23 <(awk '{print $1}' "$OUT/rootpaths-v$V.txt" | sort -u) \
           <(awk '{print $1}' "$OUT/rootpaths.txt"      | sort -u)
  echo
  echo "== ONLY on v23.0 (added since v$V — expected, low interest):"
  comm -13 <(awk '{print $1}' "$OUT/rootpaths-v$V.txt" | sort -u) \
           <(awk '{print $1}' "$OUT/rootpaths.txt"      | sort -u)
}

case "${1:-}" in
  setup) setup ;;
  t1)    t1_versions ;;
  t2)    t2_rootpaths ;;
  t3)    t3_rootpaths_at "${2:-1.0}" ;;
  *)     echo "usage: bash probe-unauth.sh {setup|t1|t2|t3 [version]}" ;;
esac
