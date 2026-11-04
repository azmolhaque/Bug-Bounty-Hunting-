# Exoscale — hunt plan (Phase 1–2)

Scope, tiers and mandatory rules: see `00-PROGRAM.md`. **Read that first.**

---

## The authorization model (from public docs — passive recon only)

Exoscale IAM is unusually rich, which is good news: rich policy engines are where
authorization bugs live.

| Concept | Detail |
|---|---|
| **Organization** | The tenant boundary |
| **Users** | Portal access |
| **IAM Roles** | Carry a **Policy** |
| **Policies** | `default-service-strategy` (e.g. `deny`) + per-service rules |
| **Service keys** | `compute`, `iam`, `dns`, `dbaas`, `sos`, `block-storage`, `organization` |
| **API Keys** | Bound to a Role+Policy. Programmatic only, **no portal access**. Cannot be updated or reassigned — create / list / delete only |
| **Built-in `Billing` role** | `deny-all` policy; billing/admin info only, cannot manage resources or the org |

Two independent boundaries to attack, and they have very different risk profiles.

---

## H1 (START HERE) — intra-org IAM policy bypass

> **A restricted API key performs an operation its own policy denies.**

**Why this is the right first test:**
- Needs **one org only** — can begin before the second account exists
- **Zero chance of touching a customer resource.** Everything is inside our own org, which
  directly satisfies the program's "customers' resources are out of scope" rule and FO-14
- Binary and unarguable: the policy says `deny`, the operation returned `200` and did the thing
- **IAM is explicitly in-scope**, and this is Tier 2 (€50–€5,000)

### Procedure
1. Create a **restricted Role** with `default-service-strategy: deny`, allowing exactly one
   service (say `dns` only).
2. Create an **API key** bound to that role. Record it.
3. **Gate 0A (positive control):** call an operation the policy *allows* (`dns` list) →
   must succeed. Proves the key, signing, and the header are all correct.
4. **Gate 0B (negative baseline):** call an operation the policy *denies* (`compute` list) →
   should be denied. **Record the exact error.**
5. Now attack the boundary. For each denied service (`compute`, `sos`, `block-storage`,
   `dbaas`, `iam`, `organization`) try:
   - the plain operation
   - **alternate API versions / paths** for the same action
   - **the CLI (`exo`) vs raw API** — different code paths sometimes enforce differently
   - **read vs list vs get-by-id** — policies often cover `list` but miss `get`
   - operations on a resource whose **ID we already know** from the allowed service
6. **Finding = a denied operation that succeeds.** Capture request + response verbatim.

### Highest-value variant
A key restricted to something harmless (`dns`) that can nonetheless call **`iam`** —
i.e. create a *new* unrestricted key. That is full privilege escalation from a
least-privilege key, and it is a clean Critical story.

---

## H2 — cross-org object authorization (the H3 methodology, transferred)

> **Org A's API key + Org B's resource ID → does it return B's data?**

Requires both orgs. Identical structure to the Looker Studio H3 run, which is now proven.

- **Both orgs are ours.** Never guess or enumerate an ID. Every ID used must come from a
  resource *we created*. A guessed UUID could belong to a real Exoscale customer — that is
  the single worst outcome available on this program and the program forbids it explicitly.
- Canary-name every resource: instance `zt-orgA-<canary>`, bucket `zt-orgb-<canary>`, etc.
- **Gate 0A:** A's key reads A's own resource → 200 + canary
- **Gate 0B:** B's key reads B's own resource → 200 + canary
- **Gate 0C:** A's portal UI cannot see B's resource
- **FO-2 control:** A's key + a **syntactically valid but non-existent** ID → record the
  response. If that also returns data, the API is a catch-all and every hit is a false positive.
- **Cross:** A's key + B's resource ID. **Proof is B's canary in A's response**, not a status code.

Resource types, highest impact first:
| Target | Why it matters |
|---|---|
| **API keys / IAM** (`iam`) | Another org's credentials — Critical |
| **Object storage** (`sos`) | Another org's stored data |
| **Block storage / snapshots** | Another org's disk contents |
| **Instances** (`compute`) | Another org's VM config, IPs, SSH keys |
| **DNS zones** | Another org's zone records |

---

## H3 — Object Storage (SOS) bucket ACLs

`sos-*.exo.io` is **S3-compatible**, and S3-compatible implementations have a long history
of ACL and policy-parsing bugs. Tier 2.

Test, using only our own two orgs' buckets:
- Bucket ACL and bucket-policy handling — does a `private` bucket stay private to org B?
- Pre-signed URL generation and expiry handling
- Path-style vs virtual-host-style addressing — do they enforce identically?
- Anonymous access to a bucket created as private
- Cross-org: B's key against A's bucket name

**Note:** *"Arbitrary file upload without proof of the existence of the uploaded file"* is
explicitly out of scope — so always fetch back what you upload.

---

## Deliberately NOT hunting

Their out-of-scope list names, by class, everything that produced a closed report in the
Google portfolio. Hunting any of it is a guaranteed N/A:

- Blind SSRF without proven impact (*pingbacks aren't sufficient*)
- **Subdomain takeover without actually taking over the subdomain** ← the Wiz F001 mistake
- Host header injection without proven impact ← the Cameyo class
- Verbose messages / directory listings without sensitive data ← the `/about` class
- Missing headers · CORS on non-sensitive endpoints · rate limits · user enumeration ·
  self-XSS · missing cookie flags · banner/version disclosure

Also skip **DBaaS internals** until confirmed — it is run in partnership with **Aiven**, who
have their own program, so those bugs may not belong to Exoscale.

---

## Blockers before the first request

- [ ] **`@intigriti.me` email alias** from the Intigriti profile — mandatory for signup
- [ ] Exact **Intigriti username** for the `X-Intigriti-Username` header
- [ ] **Two Exoscale orgs** created with those addresses
- [ ] Confirm trial credit covers creating a small instance + bucket + DNS zone
- [ ] Set up a request wrapper that **always** sends `X-Intigriti-Username` and stays
      **under 10 req/sec**
- [ ] Blacklist `portal.exoscale.com/api/tickets` from anything automated

## Order of work
1. **H1** — starts with one org, zero customer risk, IAM is in scope. Best first hunt.
2. **H2** — once the second org exists.
3. **H3** — SOS ACLs, after the API model is familiar.
