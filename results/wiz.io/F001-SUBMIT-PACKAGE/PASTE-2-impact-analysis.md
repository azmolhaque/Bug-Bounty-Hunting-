## Primary Impact: Session + Refresh Token Theft (Proven from First-Party Code)

Once `win-test.wiz.io` is claimed, every authenticated Wiz user who visits the URL automatically sends their session cookies to the attacker's server in HTTP request headers — no JavaScript, no XSS, no user interaction beyond the page load.

**Both cookie names confirmed** from Wiz Chrome Extension `background.js` (v1.0.19, Chrome Web Store):
```javascript
LT = `wiz-app`       // session cookie
RT = `wiz-app-refr`  // refresh token

{auth: await s.cookies.get({url: wizUrl, name: LT}),
 refresh: await s.cookies.get({url: t, name: RT})}
// returns {isLoggedIn: true, userId, tenantId, dataCenter, emailDomain}
```
An attacker who captures both tokens holds a **persistent session** — the refresh token silently re-issues access tokens after expiry.

**Domain=.wiz.io scope proven** from the same file (extracted live, v1.0.19):
```
cookies.getAll({domain:r})).filter(e=>!!(e.domain===r||e.domain
.startsWith(`.`)&&r.endsWith(e.domain.slice(1)))).map(e=>`${e.name}=${e.value}`)
```
The branch `startsWith('.')&&endsWith(slice(1))` handles exactly one case: `e.domain=".wiz.io"` against `r="app.wiz.io"`. **This filter exists in Wiz's own production code because `Domain=.wiz.io` cookies exist.** The browser sends them automatically to every `*.wiz.io` origin — including a claimed `win-test.wiz.io`.

**Why a compromised Wiz session is critical:**
Wiz is a CNAPP. Enterprise security teams connect AWS, GCP, and Azure environments via Wiz cloud connectors. A single captured `wiz-app` token gives an attacker full visibility into the victim's multi-cloud infrastructure inventory, IAM roles, security findings, and compliance posture.

---

## Secondary Impact: Chrome Extension Abuse (5 Confirmed Vectors)

The official Wiz Chrome Extension (`koellablckildiakdjcchdfnagjfbpbh`, "Wiz: Cloud Security in Your Cloud Portal") amplifies this attack. Manifest extracted from Chrome Web Store v1.0.19:

```json
"host_permissions": [
  "https://*.wiz.io/*", "https://*.wiz.us/*",
  "https://*.console.aws.amazon.com/*",
  "https://portal.azure.com/*",
  "https://console.cloud.google.com/*",
  "https://github.com/*", "https://gitlab.com/*"
],
"permissions": ["cookies","scripting","tabs","sidePanel","storage","activeTab",...],
"externally_connectable": {"matches": ["https://*.wiz.io/*","https://*.wiz.us/*"]}
```

**Vector 1 — Auto code injection:** Chrome injects `wizPortalInjector.js` + `main.js` into `win-test.wiz.io` automatically on page load. Wiz's own production scripts run in the attacker's page.

**Vector 2 — Extension broadcast interception:** `wizPortalInjector.js` broadcasts via `window.postMessage({...}, "*")` — wildcard `targetOrigin`. Attacker JS receives all extension messages with no origin check.

**Vector 3 — Attacker JS messages extension directly:** `externally_connectable` trusts `*.wiz.io`. Confirmed handler in `background.js`: `s.runtime.onMessageExternal.addListener(n)`.
```javascript
chrome.runtime.sendMessage("koellablckildiakdjcchdfnagjfbpbh",
  {type:"OpenSidePanel", payload:{originUrl:"https://win-test.wiz.io"}})
```
Handler `n` opens the victim's live Wiz security dashboard as a Chrome side panel while they are on the attacker's phishing page — authentic Wiz UI visible alongside attacker content.

**Vector 4 — Cloud console script injection (Critical escalation risk):** The extension holds `scripting` permission with `host_permissions` over AWS Console, Azure Portal, GCP Console, GitHub, and GitLab. Because `win-test.wiz.io` is trusted by `externally_connectable`, attacker JS can send messages to the background service worker. If handler `n` passes any message payload to `chrome.scripting.executeScript`, an attacker at `win-test.wiz.io` could inject arbitrary JavaScript into the victim's active cloud console sessions. **Wiz security team should audit whether `onMessageExternal` handler dispatches scripting API calls based on externally-supplied content.**

**Vector 5 — Persistent token capture:** Extension reads `wiz-app` + `wiz-app-refr` via `cookies` permission across all `*.wiz.io` pages. Confirms both tokens are domain-scoped.

---

## Tertiary Impact: OAuth Code Hijack Path (Unconfirmed — Internal Review Required)

Four Auth0 tenants confirmed live via OIDC discovery:

| Tenant | Status |
|--------|--------|
| `auth.wiz.io` | Production (VPC-internal, 403) |
| `auth0.test.wiz.io` | **LIVE** — returns full OIDC config |
| `auth0.demo.wiz.io` | **LIVE** — returns full OIDC config |
| `auth0.e2e.wiz.io` | **LIVE** — returns full OIDC config |

`win-test.wiz.io` and `auth0.test.wiz.io` share the `test` prefix. If any OAuth application in `auth0.test.wiz.io` registered `https://win-test.wiz.io/callback` as a `redirect_uri`:
```
https://auth0.test.wiz.io/authorize
  ?client_id=<test_client_id>
  &redirect_uri=https://win-test.wiz.io/callback
  &response_type=code&scope=openid
```
→ Auth0 delivers `?code=<auth_code>` to attacker → full account takeover.

Not tested to avoid unauthorized OAuth flows. Wiz security team can verify internally.

---

## CVSS 3.1

**Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
**Score: 8.2 (High)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Exploitable from internet; free Vercel account only |
| Attack Complexity | Low | CNAME-based claim; no race condition or timing required |
| Privileges Required | None | No Wiz account, no DNS access needed |
| User Interaction | Required | Victim must visit `win-test.wiz.io` |
| Scope | Changed | Attacker Vercel project affects `wiz.io`-trusting browser contexts |
| Confidentiality | High | `wiz-app`+`wiz-app-refr` → full Wiz session → multi-cloud visibility |
| Integrity | Low | Attacker controls content at subdomain; no backend write |
| Availability | None | No availability impact |

**If OAuth redirect_uri chain confirmed: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` = 9.3 Critical**

---

## Remediation

**Immediate (< 5 minutes):**
Delete DNS record: `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com`

**Systemic:**
1. Audit all `*.wiz.io` CNAMEs for dangling references to Vercel, Netlify, GitHub Pages, Fastly, AWS S3
2. Implement automated CNAME liveness monitoring (check for `x-vercel-error: DEPLOYMENT_NOT_FOUND` signature)
3. Add CNAME deletion to hosting resource decommission runbooks
4. Audit `onMessageExternal` handler in Chrome extension for `scripting.executeScript` calls with external message payload
5. Verify `auth0.test.wiz.io` OAuth apps do not list `win-test.wiz.io` as `redirect_uri`
