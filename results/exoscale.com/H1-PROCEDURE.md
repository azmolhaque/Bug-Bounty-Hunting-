# Exoscale H1 — intra-org IAM policy bypass

**Target:** `api-*.exoscale.com/v2` + `portal.exoscale.com` — Tier 2 (**€50–€5,000**).
**Class:** Broken access control / privilege escalation within a single organization.
**Why first:** one org only, **zero chance of touching a customer resource**, binary result,
and IAM is explicitly in scope.

---

## The boundary that must be crossed (FO-9)

A finding exists **only** if:

> **An API key whose policy DENIES a service successfully performs an operation on that
> service** — and we can show the denial in the policy and the success in the response.

**Not a finding:** the endpoint existing; a confusing error; a policy that *looks* permissive;
`list` returning an empty array. **A denied operation that actually worked, or nothing.**

---

## Mandatory rules (from `00-PROGRAM.md` — non-negotiable)

1. `X-Intigriti-Username: gorib` on **every** request
2. **≤ 10 requests/second**
3. **Never** call `portal.exoscale.com/api/tickets`
4. Only our own org. No customer resources, ever.

---

## PHASE 0 — setup

### 0.1 Cost discipline (post-paid has no hard cap)
- **Create no compute instances.** H1 needs none — IAM objects are free.
- After each session: `portal → Billing` and confirm the balance hasn't moved.
- If you ever create anything billable, delete it the same session.

### 0.2 Confirm the header is live
Load `portal.exoscale.com` → DevTools → Network → any request → **Request Headers**.
Must show `X-Intigriti-Username: gorib` **and** a normal Chrome User-Agent. 📸

### 0.3 Note your zone
The API host is per-zone: `https://api-<zone>.exoscale.com/v2`
(`ch-gva-2`, `ch-dk-2`, `de-fra-1`, `de-muc-1`, `at-vie-1`, `at-vie-2`, `bg-sof-1`).
Record the zone your org defaults to.

### 0.4 Tooling — solving the signing + header problem
Exoscale API v2 uses **EXO2 HMAC request signing**. Hand-rolling it is error-prone, and the
`exo` CLI signs correctly but won't add our required header. Two workable rigs:

**Option A (recommended): `exo` CLI behind a local proxy that injects the header**
```bash
# install mitmproxy, then run a tiny addon that adds the header
cat > /tmp/hdr.py <<'PY'
def request(flow):
    flow.request.headers["X-Intigriti-Username"] = "gorib"
PY
mitmdump -s /tmp/hdr.py -p 8080 &
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
# then every `exo ...` call carries the header
```
Verify once in the mitmdump output that the header is present before testing anything.

> ⚠️ **CA trust is a prerequisite, not an optional step.** `exo` is a Go binary and validates
> TLS against the OS trust store. Until mitmproxy's CA is installed there, every call fails with
> a certificate error. On Windows: start `mitmdump`, browse to `http://mitm.it` **through the
> proxy**, download the Windows cert, and install it into **Trusted Root Certification
> Authorities**. **A TLS error is a rig failure, not a test result.**

> ⚠️ **Read the HTTP status from the mitmdump log, not the CLI text.** With no DNS zones created,
> `exo dns list` prints an empty table — which looks similar to a refusal in the terminal but is a
> `200`. Gate 0A passes on the **status code**, not on whether rows appeared.

**Option B: capture and replay.** Run one `exo` command through mitmproxy, copy the fully
signed request, and replay with curl — adding the header by hand. Signatures are
time-bound, so re-capture when they expire. **An expired-signature error is not a negative
result.**

---

## PHASE 1 — build the restricted key

In the portal: **IAM → Roles → Add**.

Create role `zt-dns-only`:
- `default-service-strategy`: **deny**
- Allow **only** the `dns` service

Then **IAM → API Keys → Add**, bound to `zt-dns-only`. Record key + secret **locally, never
in git**.

Also note the built-in **`Billing`** role — documented as `deny-all`, billing/admin info only.
A second key on that role is a useful comparison case later.

---

## PHASE 2 — the two gates (do both before attacking)

| Gate | Command | Required result |
|---|---|---|
| **0A — positive control** | `exo dns list` with the restricted key | **Succeeds.** Proves key, signing, proxy and header all work. Without this, every later denial is meaningless |
| **0B — negative baseline** | `exo compute instance list` with the same key | **Denied.** Record the **exact** error string and HTTP status |

📸 Both. Gate 0A is the one people skip and it is the one that makes the negatives real.

---

## PHASE 3 — the attack matrix

For each **denied** service, try every route to the same action. Policies are often written
per-verb or per-path and miss a sibling.

Services to attack: `compute`, `sos`, `block-storage`, `dbaas`, `iam`, `organization`

For each, vary:
| Axis | Try |
|---|---|
| **Verb** | `list` vs `get` vs `show` — policies frequently cover `list` and miss `get-by-id` |
| **Path** | direct API call vs the CLI's route — different code paths, sometimes different enforcement |
| **ID-known** | operations on an ID we already learned via the *allowed* service |
| **Zone** | the same call against a **different zone's** API host — is the policy evaluated per-zone? |
| **Case / encoding** | service name casing, trailing slashes, URL-encoded segments |

> **Zone-crossing is the sleeper.** A per-zone policy cache that isn't consistent across
> regions is a classic multi-region authorization bug.

### 🎯 The prize
A `dns`-only key that can reach **`iam`** — specifically **create a new API key**. That is
full privilege escalation from a least-privilege credential, and it's a clean Critical story:
*"a key intended to manage DNS can mint an unrestricted key."*

Test in this order: `iam list keys` → `iam get role` → `iam create key`.
**If create succeeds: stop immediately, screenshot, delete the created key, and write it up.**
Do not use the escalated key for anything further — the escalation itself is the finding.

---

## Reading results

| Response | Meaning |
|---|---|
| **Denied operation returns 200 + real data/effect** | 🎯 **Finding.** Capture request + response verbatim |
| Clean deny, consistent with the policy | Correctly enforced. Log the negative, next axis |
| Signature/expiry error | **Not a result.** Re-sign and retry |
| 429 / rate limited | You exceeded 10 req/s. Slow down — this is a rules violation, not a finding |

---

## Drop conditions

- Every denied service stays denied across all axes → **enforcement is sound. H1 closes.**
  Log honestly (FO-7) and move to H2 (needs Org B) or H3 (SOS ACLs).
- The "bypass" turns out to be a service the policy actually allowed → re-read the policy first.
- Behaviour matches documented IAM semantics → intended (Quality Bar #2). **Read the policy
  guide before writing anything.**

---

## Evidence checklist (CLAUDE.md §9.8)

- [ ] The **policy JSON** showing the service is denied
- [ ] Gate 0A screenshot: allowed operation succeeds
- [ ] Gate 0B screenshot: denied operation is denied
- [ ] The **bypass request and response verbatim** — full headers + body
- [ ] `X-Intigriti-Username: gorib` visible in the captured request
- [ ] Date/time + external IP (`curl ifconfig.me`)
- [ ] Differential: expected (denied, per policy) vs observed (succeeded)
- [ ] **API key and secret redacted** — first/last 4 chars only
- [ ] Only our own org touched; no customer resource involved
- [ ] First-person plain voice, real terminal output (FO-10)

## Safety
- Read-only wherever possible. The one exception is the `iam create key` test — if it
  succeeds, **delete the created key immediately** and note that in the report.
- No destructive operations. No DoS. No load testing.
- If any response ever contains data belonging to another organization: **stop, do not save
  it, report that fact.**
