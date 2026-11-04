#!/data/data/com.termux/files/usr/bin/bash
# g-probe1.sh — second pass on the six rows from the sweep that look like real
# applications on acquisition stacks rather than Google frontends.
#
# No path is invented. Every path below is a DOCUMENTED endpoint of a named product
# (JFrog Artifactory, S3 REST, nginx status), which is fingerprinting, not guessing.
# Every target gets a canary path so a blanket rule cannot be mistaken for a finding.

p() { # p <label> <url>
  printf '  %-46s ' "$2"
  curl -s -o /dev/null --max-time 8 -w '%{http_code} %{size_download}b %{content_type}\n' "$2" 2>/dev/null || echo "ERR"
  sleep 0.6
}

echo "##################################################################"
echo "# 1. artifactory.cpie.io  — JFrog Artifactory, TIER2, 200 24.9KB #"
echo "##################################################################"
echo "  If anonymous read is on, api/repositories returns the repo list. That is"
echo "  build artifacts, and build artifacts are where credentials live."
A=https://artifactory.cpie.io
p x "$A/"
p x "$A/artifactory/api/system/ping"
p x "$A/artifactory/api/repositories"
p x "$A/artifactory/api/zzz-canary-7x2"          # CANARY
p x "$A/zzz-canary-7x2"                          # CANARY
echo "  --- what the root actually is ---"
curl -s --max-time 8 "$A/" | grep -oiE '<title>[^<]*</title>|artifactory|jfrog|nexus|sonatype' | sort -u | head -5

echo
echo "##################################################################"
echo "# 2. looker-opensource-components.looker.com — server: AmazonS3  #"
echo "##################################################################"
echo "  A Google-owned hostname served by an S3 bucket. Public LISTING is the"
echo "  question; a listable bucket on a TIER1 domain is a real finding, and a"
echo "  writable one is a much bigger one."
L=https://looker-opensource-components.looker.com
p x "$L/?list-type=2&max-keys=5"
p x "$L/zzz-canary-7x2"                          # CANARY
echo "  --- is it ListBucketResult? ---"
curl -s --max-time 8 "$L/?list-type=2&max-keys=5" | head -c 600; echo

echo
echo "##################################################################"
echo "# 3. feed-moderation.fitbit.com — TIER1, 200, no identity gate   #"
echo "##################################################################"
echo "  The name says moderation tooling. A moderation console answering 200 with"
echo "  no redirect to a login is worth two requests."
p x "https://feed-moderation.fitbit.com/"
p x "https://feed-moderation.fitbit.com/zzz-canary-7x2"   # CANARY
curl -s --max-time 8 "https://feed-moderation.fitbit.com/" | head -c 500; echo

echo
echo "##################################################################"
echo "# 4. pring — Google-acquired JP payments. TIER0 callbacks.       #"
echo "##################################################################"
echo "  shop.pring.app runs Apache/2.4.67 on Debian: a raw server, not Google"
echo "  infrastructure. Payments acquisition + own stack is the Tesla pattern."
p x "https://shop.pring.app/"
p x "https://shop.pring.app/zzz-canary-7x2"      # CANARY
p x "https://www.pring.jp/"
p x "https://staging.www.pring.jp/"
p x "https://development.www.pring.jp/"
p x "https://callback.pring.app/"
p x "https://callback.pring.app/zzz-canary-7x2"  # CANARY

echo
echo "##################################################################"
echo "# 5. dfa.nestlabs.com — akka-http/10.1.15 answering directly     #"
echo "##################################################################"
p x "https://dfa.nestlabs.com/"
p x "https://dfa.nestlabs.com/zzz-canary-7x2"    # CANARY
curl -s --max-time 8 "https://dfa.nestlabs.com/" | head -c 400; echo

echo
echo "##################################################################"
echo "# 6. selling.mandiant.com — 404 status with a 266 KB body        #"
echo "##################################################################"
echo "  A 404 carrying 266 KB is not an error page. Probably a SPA served under a"
echo "  404 status, which means the app is there and the router simply missed."
p x "https://selling.mandiant.com/"
p x "https://selling.mandiant.com/zzz-canary-7x2"  # CANARY
curl -s --max-time 8 "https://selling.mandiant.com/" | grep -oiE '<title>[^<]*</title>' | head -2

echo
echo "##################################################################"
echo "# 7. cameyo wildcard check — canary was 200 300b, online was 301b #"
echo "##################################################################"
echo "  One byte apart. Either the wildcard page echoes the hostname, or these are"
echo "  genuinely different pages. Reading both settles it."
curl -s --max-time 8 "https://zzz-canary-7x2.cameyo.com/" | head -c 320; echo
echo "  ---"
curl -s --max-time 8 "https://online.cameyo.com/"        | head -c 320; echo
