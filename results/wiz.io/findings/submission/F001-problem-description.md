## Verify Before Reading Further

Run these from any machine:

    dig CNAME win-test.wiz.io +short
    # Expected: 37e7f43d8158e70f.vercel-dns-013.com.

    curl -sk https://win-test.wiz.io/
    # Expected body: The deployment could not be found on Vercel.
    #                DEPLOYMENT_NOT_FOUND

    echo | openssl s_client -connect win-test.wiz.io:443 -servername win-test.wiz.io 2>/dev/null \
      | openssl x509 -noout -issuer -dates
    # Expected: issuer=O=Let's Encrypt, CN=R13
    #           notAfter=Dec 16 2025   ← EXPIRED; project was abandoned

All three confirm in under 30 seconds. No account required.

**Certificate timeline (confirms real project, not historic stale record):**
- Cert issued: **Sep 17, 2025** — Vercel project was live and actively serving content
- Cert expired: **Dec 16, 2025** — project decommissioned but DNS record never cleaned up
- **DNS zone updated: Mar 14, 2026** — wiz.io DNS was actively edited 3 months after cert expiry, yet this CNAME was not removed (WHOIS last-updated timestamp)
- As of report date (**Jun 15, 2026**): CNAME still live, takeover window open 6+ months

**DNSSEC note:** wiz.io uses DNSSEC (`signedDelegation`, nameservers: AWS Route53). DNSSEC
does not prevent subdomain takeover — it signs and validates the dangling CNAME as
legitimate, which makes the attacker-controlled origin appear more trustworthy to resolvers
and security tooling that checks DNSSEC validity.

---

## The Vulnerability

`win-test.wiz.io` has a live DNS CNAME record pointing to
`37e7f43d8158e70f.vercel-dns-013.com`, but the corresponding Vercel project has
been deleted. Any Vercel account holder can now claim this subdomain and serve
arbitrary content under the `wiz.io` domain.

Vercel's domain verification is CNAME-based: because the DNS record already
points to Vercel infrastructure, Vercel accepts a new project's claim to this
hostname without requiring any change to the `wiz.io` DNS zone. The abandoned
subdomain is therefore claimable by anyone with a free Vercel account.

---

## DNS Proof

    win-test.wiz.io.   CNAME   37e7f43d8158e70f.vercel-dns-013.com.
    win-test.wiz.io.   A       64.239.109.193    (Vercel/Fastly edge)
    win-test.wiz.io.   A       64.239.123.193    (Vercel/Fastly edge)

Vercel responds with `x-vercel-error: DEPLOYMENT_NOT_FOUND` and HTTP 404,
confirming the project behind this CNAME no longer exists. The expired TLS
certificate (Let's Encrypt, issued 2025-09-17, expired 2025-12-16) further
confirms the project was abandoned without cleaning up the DNS record.

---

## Exploitation

An attacker does not need to touch the `wiz.io` DNS zone. The steps are:

1. Create a free Vercel account.
2. Add `win-test.wiz.io` as a custom domain to a new Vercel project.
3. Vercel verifies ownership by checking that the CNAME already points to
   Vercel infrastructure — it does. Verification passes immediately.
4. Deploy arbitrary HTML, JavaScript, or a phishing page to the project.
5. `https://win-test.wiz.io/` now serves attacker-controlled content under the
   `wiz.io` brand with a **new, valid TLS certificate** automatically provisioned
   by Vercel (DigiCert/Let's Encrypt). The currently-expired certificate is an
   artifact of the deleted project; Vercel issues fresh TLS upon claim.

No interaction with Wiz is required after step 1. No Wiz credentials needed.

**Note on the expired TLS certificate:** The current `openssl` output shows an
expired Let's Encrypt cert (expired 2025-12-16). This does NOT protect against
exploitation — it is only present because no active project is responding.
Any attacker who completes step 2-3 above immediately receives a new, valid cert
from Vercel's infrastructure, removing the browser warning entirely.

---

## Root Cause

DNS record `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com` was
not removed when the corresponding Vercel project was decommissioned. The
subdomain is now a dangling CNAME — pointing to third-party infrastructure
where ownership has lapsed — which allows any third party to claim it.

This is an oversight in DNS lifecycle management, not an intended product
behavior. The remediation is a single DNS record deletion.
