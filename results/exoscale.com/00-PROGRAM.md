# Exoscale — Intigriti Bug Bounty (Phase 0: scope & rules)

**Platform:** Intigriti · **Status:** Public / **Open** · Industry: IT Services
**Company:** Exoscale — leading Swiss/European cloud service provider.
**Saturation:** ~**45 researchers**, **7 accepted** total — among the least-hunted
programs on the platform with a real ceiling. `<24h` last submission (actively worked).

## Bounties
| Tier | Range |
|---|---|
| **Tier 2** | **€50 – €5,000** |
| Tier 3 | €50 – €2,000 |

Validation SLAs: Exceptional/Critical 2 working days · High 5 · Medium/Low 15.
**€25 bonus** if they validate outside those timelines.

---

## ⚠️ MANDATORY RULES — read before a single request

1. **Accounts MUST be registered with an `@intigriti.me` email address.**
   Not gmail. Intigriti issues these aliases to researchers. Exoscale must be able to
   contact us through them. **Sign-up with any other address violates the program.**
2. **Every request must carry the header `X-Intigriti-Username: {Username}`.** Required,
   not optional. This is the program's identifying header (CLAUDE.md §0.3).
3. **Automated tooling capped at 10 requests/second.**
4. **Blacklist `https://portal.exoscale.com/api/tickets`** from any automation — calling it
   opens a real support ticket.
5. **Do not disrupt service quality for existing customers.**
6. **Customers' accounts, resources and infrastructure are OUT OF SCOPE.**
   > *"Exoscale is a public cloud provider. Do not attempt to attack any resource that may
   > be owned by an Exoscale customer."*
   **This is FO-14 stated by the program itself.** Only our own two orgs. Never guess or
   enumerate a resource ID that might belong to a real tenant. The Looker incident is
   exactly the failure mode this rule exists to prevent.
7. Safe harbour applies. No social engineering. No DoS/brute force.

---

## Assets

| Asset | Type | Tier |
|---|---|---|
| `https://portal.exoscale.com/` | URL | **Tier 2** |
| `https://api-*exoscale.com/v2` | Wildcard | **Tier 2** |
| `https://sos-*.exo.io` (object storage) | Wildcard | **Tier 2** |
| `https://sks-*.exo.io` (Kubernetes) | Wildcard | **Tier 2** |
| `*.internal.exoscale.ch` | Wildcard | **Tier 2** |
| `https://www.exoscale.com/` | URL | Tier 3 |
| `https://community.exoscale.com/` | URL | Tier 3 |
| changelog / status / academy / jobs | URL | **OUT** |
| CDN service, Marketplace products | Other | **OUT** |

## In-scope services
- **Compute** — Instances (managed KVM), Containers (SKS)
- **Storage** — Block storage, **Object storage (S3-compatible)**
- **Networking** — IP, EIP, NLB, DNS zones, Security groups, Private Network
- **DBaaS** — PostgreSQL, MySQL, Kafka, OpenSearch, Valkey, Grafana
  *(in partnership with **Aiven** — Aiven runs its own program, so DBaaS-internal bugs
  may route there. Check before investing in that surface.)*
- **IAM** ← **the target for us**

---

## Their out-of-scope list ≈ our Hard Rejection List

This is a strong signal the program is well-run. Explicitly excluded:
- *Blind SSRF without proven business impact (**pingbacks aren't sufficient**)* → our FO-11
- ***Subdomain takeover without taking over the subdomain*** → **exactly the Wiz F001 mistake**
- Host header injection without proven business impact → the Cameyo class
- Verbose messages / directory listings without sensitive data → the `/about` class
- Missing security headers · CORS on non-sensitive endpoints · rate-limit issues ·
  username/email enumeration · self-XSS · missing cookie flags · banner/version disclosure

**Every class that produced a closed report in the Google portfolio is named here as
out-of-scope.** Hunting those would be a guaranteed N/A. Do not.

---

## Why this target fits us

1. **Multi-tenant cloud with explicit IAM** — organizations, users, roles, API keys, access
   policies. Object-level authorization is the core of the product.
2. **Self-serve signup** — the wall that killed Wiz Chains 3/4/13 does not exist here.
3. **The `H3-PROCEDURE.md` methodology transfers directly**: two orgs, canary-named
   resources, positive control, catch-all control, swap one ID, watch for the canary.
4. **45 researchers / 7 accepted** — genuinely under-hunted for a €5,000 ceiling.
5. Their reject list matches ours, so the classes that pay here are the classes we now
   know how to test.

## Hunt thesis
**Cross-tenant object authorization on the Exoscale API v2 and Object Storage (SOS).**
Primary: Org A's API key + Org B's resource ID → does it return B's data?
Secondary: SOS bucket ACLs (S3-compatible services are historically ACL-buggy).
Tertiary: IAM role/policy escalation *within* an org (restricted key → privileged action).

## Blockers before any active testing
- [ ] Obtain the `@intigriti.me` email alias(es) from the Intigriti profile
- [ ] Confirm the exact Intigriti username string for the `X-Intigriti-Username` header
- [ ] Create **two** Exoscale orgs with `@intigriti.me` addresses
- [ ] Confirm free tier / trial credit is sufficient to create resources
