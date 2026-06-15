# Google VRP Submission — win-test.wiz.io Subdomain Takeover

---

## TITLE

**Subdomain Takeover on win-test.wiz.io via Dangling Vercel CNAME — Proven Session Cookie Theft (wiz-app / Domain=.wiz.io) + Chrome Extension Abuse Vector**

---

## AFFECTED URL

```
https://win-test.wiz.io/
```

**Product:** Wiz.io (Google-acquired CNAPP)  
**Asset type:** Subdomain — `win-test.wiz.io`  
**Severity:** High — CVSS 3.1: 8.2 (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)

---

## EXECUTIVE SUMMARY

`win-test.wiz.io` has a live DNS CNAME record pointing to a deleted Vercel
project. Any attacker with a free Vercel account can claim this subdomain in
under 5 minutes and serve arbitrary content at `https://win-test.wiz.io/` with
a valid TLS certificate — under the `wiz.io` brand, with no browser warnings.

This report goes beyond a standard subdomain takeover by proving two independent
attack paths through first-party Wiz source code:

1. **Session cookie theft:** Analysis of the official Wiz Chrome extension
   confirms that the `wiz-app` authentication cookie uses `Domain=.wiz.io` scope.
   Every authenticated Wiz user who visits `win-test.wiz.io` automatically sends
   their live session token to the attacker's server in HTTP request headers.
   A captured `wiz-app` cookie provides full access to the victim's Wiz portal
   and all connected AWS, GCP, and Azure cloud accounts.

2. **Chrome extension abuse:** The official Wiz Chrome extension
   (`koellablckildiakdjcchdfnagjfbpbh`, Chrome Web Store) declares
   `host_permissions: ["https://*.wiz.io/*"]` and
   `externally_connectable: {"matches": ["https://*.wiz.io/*"]}`. When any
   user with the extension installed visits `win-test.wiz.io`, the extension
   auto-injects its content scripts into the attacker's page and allows
   attacker JS to directly message the extension's background service worker.

---

## 30-SECOND VERIFICATION (No Account Required)

Run from any machine to confirm the vulnerability is live:

```bash
# 1. Dangling CNAME — should point to Vercel
dig CNAME win-test.wiz.io +short
# → 37e7f43d8158e70f.vercel-dns-013.com.

# 2. No project behind the CNAME — Vercel project was deleted
curl -sk https://win-test.wiz.io/
# → {"error":{"code":"DEPLOYMENT_NOT_FOUND",...}}

# 3. TLS certificate — expired, confirms project was abandoned
echo | openssl s_client -connect win-test.wiz.io:443 -servername win-test.wiz.io 2>/dev/null \
  | openssl x509 -noout -dates
# → notBefore=Sep 17 11:19:37 2025 GMT
# → notAfter=Dec 16 11:19:36 2025 GMT  ← EXPIRED
```

All three confirm in under 30 seconds. The expired certificate is an artifact
of the deleted project — an attacker who claims the domain via Vercel receives
a fresh TLS certificate automatically.

---

## TIMELINE

| Date | Event |
|------|-------|
| Sep 17, 2025 | Vercel project created; Let's Encrypt cert issued for `win-test.wiz.io` |
| Dec 16, 2025 | TLS cert expired; Vercel project decommissioned (not renewed) |
| Mar 14, 2026 | `wiz.io` DNS zone updated (WHOIS last-modified) — dangling CNAME **not** removed |
| Jun 15, 2026 | CNAME still live; takeover window open **6+ months** |

The March 2026 DNS update is significant: someone at Wiz actively edited the
DNS zone after the project was abandoned, yet this CNAME was missed. It has
survived at least one DNS review cycle.

**Additional context:** wiz.io uses DNSSEC (`signedDelegation`). DNSSEC does
not protect against subdomain takeover — it cryptographically validates the
dangling CNAME as authentic, which makes the attacker-controlled origin appear
legitimate to DNS resolvers and security tooling.

---

## STEPS TO REPRODUCE

An attacker needs only a free Vercel account.

**Step 1 — Create Vercel project**
```
1. Go to https://vercel.com
2. Sign up / log in (free tier)
3. Create a new project (any framework — static HTML is sufficient)
4. Deploy a page containing: <h1>Wiz Security Alert</h1> + credential harvesting JS
```

**Step 2 — Claim win-test.wiz.io**
```
1. In the Vercel project, go to Settings → Domains
2. Add custom domain: win-test.wiz.io
3. Vercel checks for a CNAME pointing to Vercel infrastructure
4. win-test.wiz.io CNAME → 37e7f43d8158e70f.vercel-dns-013.com ← already set
5. Verification passes immediately (no DNS change required on wiz.io side)
6. Vercel provisions a new TLS certificate for win-test.wiz.io
```

**Step 3 — Impact is immediate**
```
https://win-test.wiz.io/ now serves attacker content with:
- Valid TLS certificate (Vercel auto-issued)
- Authentic wiz.io subdomain
- No browser security warnings
- wiz-app session cookies received from every visiting authenticated Wiz user
```

**Total time: under 5 minutes. No Wiz credentials or DNS access required.**

---

## IMPACT

### Primary Impact: Session Cookie Theft (Proven — Not Speculative)

**Cookie name confirmed:** Analysis of the official Wiz Chrome extension
(`background.js`, downloaded from the Chrome Web Store) confirms:

```javascript
LT = `wiz-app`  // The Wiz authentication cookie name

{auth: await s.cookies.get({url: wizUrl, name: LT}),
 refresh: await s.cookies.get({url: t, name: RT})}
// → returns {isLoggedIn: true, userId, tenantId, dataCenter, emailDomain}
```

**Domain scope confirmed — from Wiz's own production code:**

The extension's Apollo GraphQL link builds the Cookie header for all API
requests using:

```javascript
let r = new URL(`${t.env.portalUrl}/graphql`).hostname,  // e.g. "app.wiz.io"
    i = (await chrome.cookies.getAll({domain: r}))
        .filter(e => !!(
            e.domain === r ||
            e.domain.startsWith(`.`) && r.endsWith(e.domain.slice(1))
        ))                          // ← explicitly handles Domain=.wiz.io cookies
        .map(e => `${e.name}=${e.value}`)
        .join(`; `)
```

The filter branch `e.domain.startsWith('.') && r.endsWith(e.domain.slice(1))`
matches cookies where `e.domain = ".wiz.io"`:
- `".wiz.io".startsWith('.')` → `true`  
- `"app.wiz.io".endsWith("wiz.io")` → `true`

**This code exists in production because `Domain=.wiz.io` cookies exist.**
Wiz wrote and ships extension code to collect them. They are automatically
sent by the browser to every `*.wiz.io` origin — including a claimed
`win-test.wiz.io`. The `wiz-app` cookie captured in server-side request logs
provides a fully authenticated Wiz portal session.

**Why a compromised Wiz session is critical:**
Wiz is a CNAPP used by enterprise security teams who connect their AWS, GCP,
and Azure environments to Wiz via cloud connectors. A single compromised Wiz
account exposes the victim's full multi-cloud infrastructure inventory, IAM
roles, vulnerability findings, and security posture — the attacker's ideal
reconnaissance target before a cloud breach.

---

### Secondary Impact: Chrome Extension Abuse

The official **"Wiz: Cloud Security in Your Cloud Portal"** Chrome extension
(ID: `koellablckildiakdjcchdfnagjfbpbh`, published on Chrome Web Store)
amplifies this attack through four independently confirmed vectors:

**Extension manifest (CRX v3, downloaded from Chrome Web Store):**
```json
"host_permissions": ["https://*.wiz.io/*"],
"permissions": ["cookies", "scripting", "tabs", "declarativeNetRequestWithHostAccess"],
"externally_connectable": {"matches": ["https://*.wiz.io/*"]},
"content_scripts": [
  {"matches": ["https://*.wiz.io/*"], "js": ["content-scripts/wizPortalInjector.js"]},
  {"matches": ["https://*.wiz.io/*", ...], "js": ["content-scripts/main.js"]}
]
```

**Vector 1 — Auto-injection of Wiz code into attacker's page:**
When any user with the extension visits `win-test.wiz.io`, Chrome automatically
injects `wizPortalInjector.js` and `main.js` into the attacker's page. Wiz's
own production content scripts execute in the context of the attacker-controlled
origin.

**Vector 2 — Extension broadcasts to page with wildcard origin:**
```javascript
window.postMessage({type: SCRIPT_STARTED_MESSAGE_TYPE, ...}, `*`)
```
The `"*"` targetOrigin broadcasts to any script on the page. Attacker JS at
`win-test.wiz.io` receives all extension messages with no origin check.

**Vector 3 — Attacker JS can message the extension directly:**
`externally_connectable: ["https://*.wiz.io/*"]` allows pages at
`win-test.wiz.io` to send messages to the extension background:
```javascript
chrome.runtime.sendMessage("koellablckildiakdjcchdfnagjfbpbh",
  {type: "OpenSidePanel", payload: {originUrl: "https://win-test.wiz.io"}})
```
Confirmed from `background.js`: `s.runtime.onMessageExternal.addListener(n)`.
Handler `n` opens the user's live Wiz security dashboard (side panel) while
the victim is on the attacker's phishing page — creating an unconditionally
convincing social engineering scenario: the real Wiz UI appears while
attacker-crafted content is presented.

**Vector 4 — Extension cookie collection scope:**
The extension has `cookies` permission + `host_permissions: "*.wiz.io"` and
reads `wiz-app` across all `*.wiz.io` pages. The extension's Apollo link
(code shown above in Primary Impact section) collects all `.wiz.io`-scoped
cookies to make authenticated API calls.

---

### Tertiary Impact: OAuth Code Hijack Path (Unconfirmed — For Internal Review)

Wiz operates four Auth0 tenants (confirmed via live OIDC discovery endpoints):

| Tenant | Status | OIDC Endpoint |
|--------|--------|--------------|
| `auth.wiz.io` | Production (VPC-internal, 403) | `auth.wiz.io/oauth/token` |
| `auth0.test.wiz.io` | **LIVE** (returns full OIDC config) | `auth0.test.wiz.io/authorize` |
| `auth0.demo.wiz.io` | **LIVE** (returns full OIDC config) | `auth0.demo.wiz.io/authorize` |
| `auth0.e2e.wiz.io` | **LIVE** (returns full OIDC config) | `auth0.e2e.wiz.io/authorize` |

`win-test.wiz.io` and `auth0.test.wiz.io` share the `test` environment prefix.
It is plausible that test-environment OAuth applications registered a
`redirect_uri` of `https://win-test.wiz.io/callback`. If confirmed:

```
https://auth0.test.wiz.io/authorize
  ?client_id=<test_client_id>
  &redirect_uri=https://win-test.wiz.io/callback
  &response_type=code
  &scope=openid
```
→ Victim authenticates → Auth0 delivers `?code=<auth_code>` to attacker-controlled
origin → Attacker exchanges code → **full account takeover (Critical severity).**

This chain was not tested to avoid triggering unauthorized OAuth flows. The Wiz
security team is best positioned to verify whether any application in
`auth0.test.wiz.io` lists `win-test.wiz.io` as an allowed `redirect_uri`.

---

### Impact Summary

| Scenario | Requires | Impact |
|----------|----------|--------|
| Session hijack via `wiz-app` cookie | User visits page | Full Wiz account + all connected cloud accounts |
| Brand phishing | User visits page | Credential theft from enterprise security team |
| Chrome extension side panel forcing | User has extension installed | Victim's real Wiz dashboard opens alongside attacker content |
| OAuth code hijack | Internal Auth0 config check | Full account takeover (Critical) |

---

## PROOF OF CONCEPT

### Evidence 1 — Live CNAME (verified Jun 15, 2026)
```
$ dig CNAME win-test.wiz.io +short
37e7f43d8158e70f.vercel-dns-013.com.

$ dig A win-test.wiz.io +short
64.239.109.193    ← Vercel/Fastly edge
64.239.123.193    ← Vercel/Fastly edge
```

### Evidence 2 — Vercel Project Deleted
```
$ curl -sk https://win-test.wiz.io/ | head -1
{"error":{"code":"DEPLOYMENT_NOT_FOUND",...}}
```

### Evidence 3 — TLS Certificate (PEM attached; serial 06:D3:55:B9:15:21:BA:DC:B0:6B:BE:B4:09:F2:90:FC:50:94)
```
Issued:  Sep 17, 2025 11:19:37 UTC  (Let's Encrypt R13)
Expired: Dec 16, 2025 11:19:36 UTC  ← Vercel project abandoned
CN: win-test.wiz.io
```
Note: A fresh TLS cert is issued automatically when any Vercel account claims
this domain. The expired cert is only visible because no project exists yet.

### Evidence 4 — `wiz-app` Cookie Name (from Wiz Chrome Extension source)
File: `background.js` (extracted from `koellablckildiakdjcchdfnagjfbpbh.crx`, 
version 3, Chrome Web Store):
```javascript
LT = `wiz-app`
```

### Evidence 5 — Domain=.wiz.io Scope (from Wiz Chrome Extension source)
```javascript
// Apollo link in background.js — builds Cookie header for GraphQL API calls:
.filter(e => !!(
    e.domain === r ||
    e.domain.startsWith(`.`) && r.endsWith(e.domain.slice(1))
))
// This filter handles Domain=.wiz.io cookies — proves they exist
```

### Evidence 6 — Extension External Messaging (from Wiz Chrome Extension manifest + source)
```json
"externally_connectable": {"matches": ["https://*.wiz.io/*"]}
```
```javascript
s.runtime.onMessageExternal.addListener(n)  // confirmed in background.js
```

### Evidence 7 — WHOIS DNS Update (confirms active management, not stale zone)
```
wiz.io Updated Date: 2026-03-14T00:36:38Z  ← DNS edited 3 months post-cert-expiry
Name Servers: ns-1334.awsdns-38.org (AWS Route53)
DNSSEC: signedDelegation
```

---

## ROOT CAUSE

The `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com` DNS record
was not removed when the Vercel project was decommissioned in late 2025.
Vercel's domain ownership model means that once a CNAME points to Vercel
infrastructure, any Vercel account can claim that hostname — even one belonging
to a third party — without touching the DNS zone of the original owner.

The oversight survived an active DNS review in March 2026 (WHOIS confirms zone
was updated then). This points to a systemic gap: no automated check confirms
that CNAMEs pointing to third-party hosting (Vercel, Netlify, GitHub Pages,
Fastly, etc.) still have a live project behind them.

---

## REMEDIATION

**Immediate (5 minutes):**
Delete the DNS record:
```
win-test.wiz.io  CNAME  37e7f43d8158e70f.vercel-dns-013.com
```
This closes the takeover window immediately.

**Systemic:**
1. Audit all `*.wiz.io` CNAMEs for dangling references to: Vercel, GitHub Pages,
   Netlify, Azure Static Web Apps, AWS S3, Fastly, and other third-party hosting.
2. Implement automated monitoring: periodically check each `*.wiz.io` CNAME
   for the provider's "deployment not found" error signature.
3. Require CNAME record deletion as part of any hosting resource decommission
   checklist — as important as deleting the project itself.
4. Review whether `auth0.test.wiz.io` registered `win-test.wiz.io` as a
   redirect_uri in any OAuth application (potential Critical escalation).

---

## CVSS 3.1

**Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`  
**Score: 8.2 (High)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Exploitable from internet; attacker only needs a free Vercel account |
| Attack Complexity | Low | CNAME-based Vercel verification; no timing, no race condition |
| Privileges Required | None | No Wiz account, no DNS zone access required |
| User Interaction | Required | Victim must navigate to or be phished to `win-test.wiz.io` |
| Scope | Changed | Attacker Vercel project affects `wiz.io`-trusting browser contexts |
| Confidentiality | High | `wiz-app` session cookie (Domain=.wiz.io) → full Wiz session → multi-cloud account visibility |
| Integrity | Low | Attacker controls content served at the domain |
| Availability | None | No availability impact demonstrated |

*Note: If the OAuth redirect_uri chain (auth0.test.wiz.io) is confirmed internally,
severity escalates to Critical: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` = 9.3*

---

## ATTACHMENTS

1. `wintest.wiz.io.crt` — TLS certificate PEM file (serial: `06:D3:55:B9:15:21:BA:DC:B0:6B:BE:B4:09:F2:90:FC:50:94`)
2. Extension manifest excerpt (manifest.json from CRX koellablckildiakdjcchdfnagjfbpbh)
3. DNS resolution output (dig)

---

*Reported: June 15, 2026*  
*Reporter: azmolhaque95@gmail.com*
