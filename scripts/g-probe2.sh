#!/data/data/com.termux/files/usr/bin/bash
# g-probe2.sh — third pass. Four of probe1's six are closed by their own canaries.
# This goes after the two that are not, plus two cheap reads.

B=https://looker-opensource-components.looker.com
echo "####################################################################"
echo "# 1. looker-opensource-components  — bucket PERMISSIONS, read-only #"
echo "####################################################################"
echo "  Public LISTING is confirmed, but a bucket named 'opensource-components'"
echo "  serving .jar files is probably public ON PURPOSE. Listing alone is the"
echo "  Hard Rejection List, section 3: disclosure with nothing exploitable."
echo "  What would matter is WRITE. These are all reads; they ask the bucket to"
echo "  describe its own permissions."
for q in acl policy cors website versioning location logging; do
  printf '  ?%-12s ' "$q"
  curl -s -o /tmp/.s3 --max-time 8 -w '%{http_code} %{size_download}b  ' "$B/?$q" 2>/dev/null
  head -c 150 /tmp/.s3 2>/dev/null | tr -d '\n'; echo
  sleep 0.6
done
echo
echo "  --- how big is this bucket, and what is newest in it? ---"
curl -s --max-time 10 "$B/?list-type=2" \
  | grep -oE '<Key>[^<]+</Key>|<LastModified>[^<]+</LastModified>' \
  | paste - - 2>/dev/null | tail -8
echo "  key count:"; curl -s --max-time 10 "$B/?list-type=2" | grep -c '<Key>'

echo
echo "####################################################################"
echo "# 2. feed-moderation.fitbit.com — decode the Ember config blob     #"
echo "####################################################################"
echo "  Root and canary are byte-identical, so the 200 is just SPA routing, not an"
echo "  auth bypass. But Ember ships its whole runtime config in a meta tag, and"
echo "  that blob routinely carries API hosts, feature flags and sometimes keys."
curl -s --max-time 10 https://feed-moderation.fitbit.com/ \
  | grep -oE 'content="%7B[^"]*"' | sed 's/content="//;s/"$//' \
  | python3 -c "import sys,urllib.parse,json
raw=urllib.parse.unquote(sys.stdin.read().strip())
try: print(json.dumps(json.loads(raw),indent=2)[:3000])
except Exception: print(raw[:3000])"
echo "  --- script bundles (where the API paths live) ---"
curl -s --max-time 10 https://feed-moderation.fitbit.com/ | grep -oE 'src="[^"]+\.js"' | sort -u

echo
echo "####################################################################"
echo "# 3. dfa.nestlabs.com — the page references /api/...               #"
echo "####################################################################"
curl -s --max-time 10 https://dfa.nestlabs.com/ | grep -oE 'src="[^"]+"|href="[^"]+"|/api/[A-Za-z0-9_/-]*' | sort -u | head -20

echo
echo "####################################################################"
echo "# 4. online.cameyo.com — TIER0, and NOT the wildcard default       #"
echo "####################################################################"
echo "  The wildcard canary redirects to /login. online.cameyo.com redirects to"
echo "  /public. Different destination, so this is a distinct application, and"
echo "  '/public' is an unauthenticated area by its own name."
for u in "https://online.cameyo.com/public" "https://online.cameyo.com/login" "https://zzz-canary-7x2.cameyo.com/public" "https://marketplace.cameyo.com/"; do
  printf '  %-52s ' "$u"
  curl -s -o /dev/null --max-time 8 -w '%{http_code} %{size_download}b %{content_type}\n' "$u"
  sleep 0.6
done
echo "  --- what is on /public ---"
curl -s --max-time 10 "https://online.cameyo.com/public" | grep -oiE '<title>[^<]*</title>' | head -2
