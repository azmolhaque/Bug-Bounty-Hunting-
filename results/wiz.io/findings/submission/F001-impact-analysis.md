## What an Attacker Gets

An attacker who claims `win-test.wiz.io` controls a TLS-valid origin inside
the `wiz.io` domain. From that position:

| Attack Surface | Mechanism | Impact |
|---|---|---|
| Brand phishing | Serve fake Wiz login at `win-test.wiz.io` | Credential theft from enterprise security teams |
| Cookie theft | `Domain=.wiz.io` cookies sent to attacker JS | Wiz session token exfiltration |
| OAuth code hijack | If `win-test.wiz.io` in Auth0 redirect_uri allowlist | Full account takeover |
| CSP trust abuse | Any `*.wiz.io` wildcard in `script-src`/`connect-src` | Attacker JS executes in portal context |
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

## Cookie Scope

Any cookie set by `app.wiz.io`, `www.wiz.io`, or other portal origins with
`Domain=.wiz.io` (without the `__Host-` prefix that restricts to the exact
issuing origin) is sent by the browser to `win-test.wiz.io`. An attacker
serving any page at that origin receives these cookies in every request.

---

## OAuth Escalation Path

Wiz uses Auth0 for SSO. If any Auth0 application in the `auth0.demo.wiz.io`,
`auth0.e2e.wiz.io`, or `auth0.app.wiz.io` tenants includes `win-test.wiz.io`
in its `redirect_uri` allowlist (common for test/demo/e2e environments):

1. Craft: `https://auth0.*.wiz.io/authorize?...&redirect_uri=https://win-test.wiz.io/callback`
2. Victim authenticates → Auth0 redirects with `?code=<auth_code>` to the attacker-controlled origin
3. Attacker exchanges code → access token → full account takeover

This chain was not tested (to avoid unauthorized OAuth flows), but the
presence of `auth0.demo.wiz.io` and `auth0.e2e.wiz.io` in the Wiz subdomain
fleet makes it a realistic escalation path that should be evaluated alongside
this report.

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
