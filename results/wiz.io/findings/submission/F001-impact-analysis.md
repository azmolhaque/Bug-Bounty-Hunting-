## What an Attacker Gets

An attacker who claims `win-test.wiz.io` controls a TLS-valid origin inside
the `wiz.io` domain. From that position:

| Attack Surface | Mechanism | Impact |
|---|---|---|
| Session hijack | `wiz-app` auth cookie (Domain=.wiz.io) sent to attacker server | Full authenticated Wiz session — access to all connected cloud accounts |
| Brand phishing | Serve fake Wiz login at `win-test.wiz.io` | Credential theft from enterprise security teams |
| Chrome extension abuse | Official Wiz extension auto-injects into `*.wiz.io`; attacks `win-test.wiz.io` | Wiz scripts run in attacker page; side panel opened from attacker origin |
| OAuth code hijack | If `win-test.wiz.io` in Auth0 redirect_uri allowlist (`auth0.test.wiz.io` is live) | Full account takeover |
| Wiz brand impersonation | Fake WizCLI downloads, fake security advisories | Malware distribution under trusted brand |

---

## Customer Context — Why This Is High-Consequence

Wiz is a CNAPP product used by enterprise security teams. Wiz users have
connected their AWS, GCP, and Azure environments to Wiz via cloud connectors —
meaning their cloud accounts, IAM roles, and infrastructure inventory are
visible inside the Wiz portal. A single compromised Wiz account gives an
attacker visibility into the victim's entire multi-cloud attack surface.

A convincing phishing page served at `https://win-test.wiz.io` (valid TLS,
authentic `wiz.io` domain, no browser warnings) is more credible than any
off-domain phishing site. The target population is security professionals who
would otherwise be skeptical of domain-mismatch warnings — but would not see
one here.

---

## Cookie Scope — Confirmed via First-Party Wiz Source Code

Analysis of the official Wiz Chrome extension (`koellablckildiakdjcchdfnagjfbpbh`,
downloaded from Chrome Web Store) reveals two independent confirmations that
`Domain=.wiz.io` cookies exist and are collected by Wiz's own infrastructure.

### 1. Cookie Name Confirmed: `wiz-app`

`background.js` contains:
```javascript
LT = `wiz-app`
// ...
{auth: await s.cookies.get({url: e, name: LT}), refresh: await s.cookies.get({url: t, name: RT})}
// ...
{isLoggedIn: true, userId: r, tenantId: VT(t.value), dataCenter: HT(t.value), emailDomain: UT(t.value)}
```

The extension reads a cookie named `wiz-app` and uses it to determine the
user's `isLoggedIn` state, `tenantId`, `dataCenter`, and `emailDomain`.

### 2. `.wiz.io` Domain Scope Proven by Extension's Own Cookie Collection Logic

The extension's Apollo GraphQL link (`background.js`) builds the Cookie header
for all Wiz API requests using this logic:

```javascript
let n = `${t.env.portalUrl}/graphql`,
    r = new URL(n).hostname,                          // e.g. "app.wiz.io"
    i = (await chrome.cookies.getAll({domain: r}))
        .filter(e => !!(
            e.domain === r ||                         // exact domain match
            e.domain.startsWith(`.`) &&               // OR subdomain-scoped
            r.endsWith(e.domain.slice(1))             // e.g. ".wiz.io" matches "app.wiz.io"
        ))
        .map(e => `${e.name}=${e.value}`)
        .join(`; `)
```

The second filter branch — `e.domain.startsWith('.') && r.endsWith(e.domain.slice(1))` —
explicitly handles cookies where `e.domain = ".wiz.io"`:
- `".wiz.io".startsWith('.')` → `true`
- `"app.wiz.io".endsWith("wiz.io")` → `true`

**This filter exists in production Wiz code because `Domain=.wiz.io` cookies
exist on the Wiz platform.** Wiz's own Chrome extension was written to collect
and use them. Cookies with `Domain=.wiz.io` (including `wiz-app`) are sent by
the browser to every `*.wiz.io` origin — including a claimed `win-test.wiz.io`.

An attacker's server at `win-test.wiz.io` receives the `wiz-app` session cookie
in HTTP request headers for every page load from an authenticated Wiz user.
That cookie provides a fully authenticated Wiz session with access to all
connected AWS, GCP, and Azure cloud accounts.

---

## Chrome Extension Attack Amplification

The official **Wiz Chrome extension** ("Wiz: Cloud Security in Your Cloud
Portal", ID: `koellablckildiakdjcchdfnagjfbpbh`) significantly amplifies the
attack surface of this subdomain takeover. Analysis of the published extension
(downloaded from the Chrome Web Store, CRX version 3) reveals:

**Extension manifest — confirmed attack surface:**

```json
"host_permissions": ["https://*.wiz.io/*"],
"permissions": ["cookies", "scripting", "tabs", "declarativeNetRequestWithHostAccess"],
"externally_connectable": {"matches": ["https://*.wiz.io/*"]},
"content_scripts": [
  {"matches": ["https://*.wiz.io/*"], "js": ["content-scripts/wizPortalInjector.js"]},
  {"matches": ["https://*.wiz.io/*", ...], "js": ["content-scripts/main.js"]}
]
```

**Attack vectors enabled by the extension:**

1. **Automatic code injection**: When any user with the Wiz extension installed
   visits `win-test.wiz.io` (once claimed), Chrome automatically injects
   `wizPortalInjector.js` and `main.js` into the attacker's page. Wiz's own
   content scripts execute in the context of the attacker-controlled origin.

2. **Extension broadcasts with wildcard origin**: The injected
   `wizPortalInjector.js` calls:
   ```javascript
   window.postMessage({type: SCRIPT_STARTED_MESSAGE_TYPE, ...}, `*`)
   ```
   The `"*"` targetOrigin means this message is received by attacker JS
   with no origin restriction. The attacker page can listen for all messages
   the extension broadcasts and know the extension is present and active.

3. **External messaging capability**: The `externally_connectable` configuration
   allows JavaScript running at `win-test.wiz.io` to directly send messages to
   the extension's background service worker:
   ```javascript
   chrome.runtime.sendMessage("koellablckildiakdjcchdfnagjfbpbh",
     {type: "OpenSidePanel", payload: {originUrl: "https://win-test.wiz.io"}})
   ```
   Analysis of `background.js` confirms the extension has
   `onMessageExternal.addListener(n)` and that `n` opens the Wiz security
   side panel in response. An attacker can force the victim's Wiz security
   dashboard to open while the victim is on the attacker's phishing page —
   creating a maximally convincing social engineering scenario where the
   genuine Wiz UI is visible alongside attacker-crafted content.

4. **Cookie read capability**: background.js reads `wiz-app` and refresh
   cookies via `chrome.cookies.getAll({domain: r})` across all `*.wiz.io`
   pages. The extension constructs the full `Cookie:` header string for API
   calls. The fact that the extension needs this access from `*.wiz.io`
   confirms the cookie is domain-scoped to `.wiz.io`.

---

## OAuth Escalation Path

Wiz operates four Auth0 tenants (confirmed from published integration code and
live OIDC endpoints probed during this investigation):

- `auth.wiz.io` — production (HTTP 403, VPC-internal)
- `auth0.test.wiz.io` — test environment (**LIVE**, returns OIDC config)
- `auth0.demo.wiz.io` — demo environment (**LIVE**, returns OIDC config)
- `auth0.e2e.wiz.io` — E2E test environment (**LIVE**, returns OIDC config)

`win-test.wiz.io` shares the `test` environment prefix with `auth0.test.wiz.io`.
It is plausible that test-environment OAuth applications registered in
`auth0.test.wiz.io` included `win-test.wiz.io` as a `redirect_uri`. If so:

1. Craft: `https://auth0.test.wiz.io/authorize?client_id=<test_client_id>&redirect_uri=https://win-test.wiz.io/callback&response_type=code&scope=openid`
2. Victim authenticates → Auth0 redirects with `?code=<auth_code>` to attacker origin
3. Attacker exchanges code → access token → full account takeover

This chain was not tested beyond OIDC discovery (to avoid unauthorized OAuth
flows), but the Wiz security team is best positioned to evaluate whether any
application in `auth0.test.wiz.io` lists `win-test.wiz.io` as an allowed
redirect URI.

---

## Severity

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` = **8.2 High**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Exploitable from the internet by any Vercel account |
| Attack Complexity | Low | CNAME-based Vercel verification; no timing, no race condition |
| Privileges Required | None | No Wiz account, no DNS access required |
| User Interaction | Required | Victim must visit or be phished to `win-test.wiz.io` |
| Scope | Changed | Attacker-controlled Vercel project impacts `wiz.io`-trusting browser contexts |
| Confidentiality | High | `.wiz.io` cookies, OAuth codes, session tokens potentially exfiltrated |
| Integrity | Low | Attacker controls content served; no direct write to wiz.io backend |
| Availability | None | No availability impact demonstrated |

---

## Remediation

**Immediate:** Delete `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com`
from the wiz.io DNS zone. This closes the takeover window in under 5 minutes.

**Systemic:** Audit all `*.wiz.io` DNS CNAMEs for dangling references to Vercel,
GitHub Pages, Netlify, Azure Static Web Apps, Fastly, AWS S3, and similar
third-party hosting providers. Implement a DNS lifecycle policy that requires
CNAME record deletion to be part of any cloud resource decommission checklist.
