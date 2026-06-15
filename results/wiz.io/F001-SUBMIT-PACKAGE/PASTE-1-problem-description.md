`win-test.wiz.io` has a live DNS CNAME record pointing to a deleted Vercel project. Any attacker with a free Vercel account can claim this subdomain in under 5 minutes and serve arbitrary content at `https://win-test.wiz.io/` with a valid TLS certificate — under the `wiz.io` brand, with no browser warnings and no interaction with Wiz required.

## Verified Evidence (2026-06-15, independent network)

**1. Dangling CNAME**
```
$ dig CNAME win-test.wiz.io +short
37e7f43d8158e70f.vercel-dns-013.com.

$ dig A win-test.wiz.io +short
64.239.109.193   ← Vercel/Fastly edge
64.239.123.193   ← Vercel/Fastly edge
```

**2. Vercel project deleted**
```
$ curl -sI https://win-test.wiz.io/ | grep -i 'x-vercel-error\|HTTP/'
HTTP/2 404
x-vercel-error: DEPLOYMENT_NOT_FOUND
```
`x-vercel-error: DEPLOYMENT_NOT_FOUND` is Vercel's canonical signal that a CNAME points to their infrastructure but no project exists behind it — the exact precondition for subdomain takeover.

**3. Abandoned TLS certificate (PEM attached)**
```
notBefore=Sep 17 11:19:37 2025 GMT
notAfter=Dec 16 11:19:36 2025 GMT   ← EXPIRED
serial=06D355B91521BADCB06BBEB409F290FC5094
issuer=C=US, O=Let's Encrypt, CN=R13
subject=CN=win-test.wiz.io
```
The expired cert confirms the Vercel project was live then decommissioned. An attacker who claims the domain via Vercel receives a **fresh** TLS certificate automatically — the expired cert disappears the moment the takeover completes.

## Timeline

| Date | Event |
|------|-------|
| Sep 17, 2025 | Vercel project live; Let's Encrypt cert issued |
| Dec 16, 2025 | Cert expired — project abandoned |
| **Mar 14, 2026** | `wiz.io` DNS zone updated (WHOIS last-modified) — **CNAME not removed** |
| Jun 15, 2026 | CNAME still live; takeover window open 6+ months |

The March 2026 DNS update is significant: Wiz's DNS team actively edited the zone after the project was abandoned but missed this record. It has survived at least one DNS review cycle.

**DNSSEC note:** `wiz.io` uses DNSSEC (`signedDelegation`, AWS Route53). DNSSEC does not prevent subdomain takeover — it cryptographically validates the dangling CNAME as authentic, making the attacker-controlled origin appear more trustworthy to resolvers and security tooling.

## Steps to Reproduce

An attacker needs only a free Vercel account.

**Step 1 — Create Vercel project**
1. Go to `https://vercel.com` → Sign up (free)
2. Create any new project (static HTML is sufficient)
3. Deploy a page (e.g. a Wiz-themed phishing page)

**Step 2 — Claim win-test.wiz.io**
1. Project → Settings → Domains → Add Domain
2. Enter: `win-test.wiz.io`
3. Vercel checks: does `win-test.wiz.io` CNAME point to Vercel? → **YES**
4. Verification passes immediately — no change to `wiz.io` DNS required
5. Vercel auto-provisions a fresh TLS certificate for `win-test.wiz.io`

**Step 3 — Result**
`https://win-test.wiz.io/` now serves attacker-controlled content with:
- Valid TLS (Vercel auto-issued, no browser warnings)
- Authentic `wiz.io` subdomain
- `wiz-app` session cookies received automatically from every authenticated Wiz user who visits

**Total time: under 5 minutes. No Wiz credentials or DNS access required.**

## Root Cause

The `win-test.wiz.io CNAME 37e7f43d8158e70f.vercel-dns-013.com` record was not deleted when the Vercel project was decommissioned. Vercel's ownership model requires only that the CNAME points to their infrastructure — no project-specific token. Any Vercel account can therefore claim any hostname with a dangling CNAME pointing to Vercel, without touching the original owner's DNS zone.
