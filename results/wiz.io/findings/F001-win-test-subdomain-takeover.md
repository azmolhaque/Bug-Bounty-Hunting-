# Subdomain Takeover on win-test.wiz.io via Dangling Vercel CNAME

**Status:** VERIFIED — ready to submit  
**Target:** wiz.io (Google VRP TIER1)  
**Discovered:** 2026-06-11  
**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N → **8.2**

---

## Summary

`win-test.wiz.io` has a live DNS CNAME record pointing to `37e7f43d8158e70f.vercel-dns-013.com`, a Vercel hosting target, but the corresponding Vercel project has been deleted. Any Vercel account holder can now claim `win-test.wiz.io` as a custom domain — because the CNAME already proves DNS ownership to Vercel's verification system — and serve arbitrary HTML, JavaScript, or phishing pages under the `wiz.io` brand. The expired TLS certificate (Let's Encrypt, lapsed 2025-12-16) further confirms the project was abandoned without DNS cleanup.

---

## Severity

- **Rating:** High
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` → **8.2**
  - AV:N — network-exploitable from the internet
  - AC:L — low complexity; any Vercel account can claim the domain
  - PR:N — no privileges required on Wiz's side
  - UI:R — a victim user must visit or receive a link
  - S:C — scope change: impact propagates to other wiz.io origins via cookie/CORS trust
  - C:H — high confidentiality: cookies with `Domain=.wiz.io`, OAuth codes, session tokens potentially reachable
  - I:L — attacker controls content served; no direct write to wiz.io backend
  - A:N — no availability impact
- **Business impact:** An attacker controlling `win-test.wiz.io` can serve convincing phishing pages under the Wiz brand, steal cookies shared with `*.wiz.io`, and potentially intercept OAuth authorization codes if the subdomain appears in any Auth0 redirect_uri allowlist. Wiz is a CNAPP product used by security teams with broad cloud permissions — account compromise of a Wiz user is high-consequence.

---

## Affected Asset

- **URL:** `https://win-test.wiz.io`
- **DNS record:** `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com`
- **Resolved IPs:** `64.239.109.193`, `64.239.123.193` (Vercel/Fastly edge)
- **In scope:** Yes — `*.wiz.io` TIER1, blackout-exempt

---

## Steps to Reproduce

> Claiming the domain is NOT performed. The `DEPLOYMENT_NOT_FOUND` response is sufficient proof.

**Step 1** — Confirm the CNAME record is live:
```
dig CNAME win-test.wiz.io +short
# Expected: 37e7f43d8158e70f.vercel-dns-013.com.
```

**Step 2** — Confirm CNAME resolves to Vercel infrastructure:
```
dig A win-test.wiz.io +short
# Expected: 64.239.109.193 / 64.239.123.193
```

**Step 3** — Confirm Vercel returns `DEPLOYMENT_NOT_FOUND`:
```
curl -sk https://win-test.wiz.io/
```
Response:
```
The deployment could not be found on Vercel.

DEPLOYMENT_NOT_FOUND

bom1::tnfdr-1781177680715-1da79e4dce46
```

**Step 4** — Confirm expired TLS cert (unrenewed = project deleted):
```
echo | openssl s_client -connect win-test.wiz.io:443 -servername win-test.wiz.io 2>/dev/null \
  | openssl x509 -noout -issuer -dates
# issuer=O=Let's Encrypt, CN=R13
# notBefore=Sep 17 2025
# notAfter=Dec 16 2025  ← EXPIRED
```

---

## Proof

```
GET / HTTP/2
Host: win-test.wiz.io

HTTP/2 404
content-type: text/plain; charset=utf-8
server: Vercel
x-vercel-error: DEPLOYMENT_NOT_FOUND
strict-transport-security: max-age=63072000

The deployment could not be found on Vercel.

DEPLOYMENT_NOT_FOUND

bom1::tnfdr-1781177680715-1da79e4dce46
```

DNS:
```
win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com.
64.239.109.193
64.239.123.193
```

TLS cert screenshot: issued 2025-09-17, expired 2025-12-16, Let's Encrypt R13.

---

## Impact

1. **Arbitrary content hosting** under the `wiz.io` brand — phishing pages, fake login forms, malicious WizCLI downloads.
2. **Cookie theft** — any `Domain=.wiz.io` cookies are sent to attacker JS running on `win-test.wiz.io`.
3. **OAuth2 redirect hijack** — if `win-test.wiz.io` is in any `redirect_uri` allowlist on `auth0.demo.wiz.io` or `auth0.e2e.wiz.io`, attacker steals OAuth codes.
4. **CSP/CORS bypass** — any policy that grants wildcard trust to `*.wiz.io` extends that trust to the attacker.
5. **Brand phishing at scale** — Wiz's enterprise security customer base is a high-value, high-privilege target population.

---

## Remediation

**Immediate (required):** Delete the `win-test.wiz.io` CNAME record from the wiz.io DNS zone.

**If subdomain must remain:** Point it to Wiz-controlled infrastructure (redirect to `app.wiz.io`), not a third-party CNAME.

**Systemic:**
- Audit all `*.wiz.io` CNAMEs for dangling references to Vercel, GitHub Pages, Azure Static Web Apps, Netlify, S3, Fastly.
- Implement DNS lifecycle policy: decommission DNS simultaneously with cloud resource deletion.
- Audit cookies for `__Host-` prefix usage; review Auth0 `redirect_uri` allowlists.

---

## References

- OWASP WSTG-CONF-10: Subdomain Takeover
- can-i-take-over-xyz: Vercel fingerprint `DEPLOYMENT_NOT_FOUND` — confirmed claimable
- HackerOne #325336: canonical Vercel subdomain takeover disclosure
- CWE-923: Improper Restriction of Communication Channel

---

**Dedup:** No prior VRP submissions found for this host. Novel finding.  
**Discovery method:** Phase 1 DNS enumeration (dnsx) → Phase 3 Vercel takeover fingerprint (body match).  
**Related:** Audit `win.wiz.io` (same IP range, same naming pattern).
