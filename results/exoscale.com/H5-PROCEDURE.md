# Exoscale H5 — SOS policy/storage parameter-binding mismatch

**Target:** `sos-ch-gva-2.exo.io` (Simple Object Storage, S3-compatible) — Tier 2 (**€50–€5,000**).
**Class:** Broken access control via authorization/handler disagreement on the resource identity.
**Cost:** two objects of a few bytes. Fractions of a centime. Deleted same session.

---

## Why this is not "more of the same"

Sessions 1–2 attacked the **IAM policy engine on the API control plane**, four ways, and it
held. That verdict does **not** transfer here:

- SOS is a **separate implementation** behind an **S3 protocol compatibility layer**.
- The CEL evaluator being correct is irrelevant if it is fed the **wrong input**. We proved
  expressions evaluate correctly. We have not tested **what gets bound to `parameters.bucket`**.
- S3 hands us the wedge for free: **two legal ways to name the same bucket.**

```
path-style:          https://sos-ch-gva-2.exo.io/BUCKET/key
virtual-host style:  https://BUCKET.sos-ch-gva-2.exo.io/key
```

Two components must each answer *"which bucket is this request for?"* — the policy engine, from
`parameters.bucket`, and the storage handler, from the request. **If they derive it differently,
a request denied for bucket B can still read bucket B.**

---

## The boundary that must be crossed (FO-9)

A finding exists **only** if:

> **A response body contains bucket B's canary string while the key's policy carries an explicit
> `deny` rule for bucket B** — with the plain request for B proven to return 403.

**Not a finding:** a 403 with odd wording · a 400 · a redirect · an empty 200 · listing bucket
names · the addressing modes behaving differently *without* data crossing.

---

## Test design — use a DENY rule, not an allow-list

An allow-list policy (`allow if bucket == A`, default deny) is the **wrong** design here: an
unbound `parameters.bucket` makes the expression error, and we already proved errors fail
**closed**. It would test nothing new.

Instead grant broad access and **carve out one bucket**:

```json
{
  "default-service-strategy": "deny",
  "services": {
    "sos": {
      "type": "rules",
      "rules": [
        { "action": "deny",  "expression": "parameters.bucket == 'zt-bravo-<CANARY>'" },
        { "action": "allow", "expression": "true" }
      ]
    }
  }
}
```

Now the question is purely about **binding**: can we reach bravo's bytes while
`parameters.bucket` fails to equal the literal string `zt-bravo-<CANARY>`?

---

## PHASE 0 — setup (portal, free)

1. **STORAGE → Buckets → Add**, zone `ch-gva-2`, two buckets:
   - `zt-alpha-<CANARY>`
   - `zt-bravo-<CANARY>`

   `<CANARY>` = 8 random lowercase alphanumerics, no dictionary words. Buckets are globally
   named, so this also avoids collisions.

2. Upload one tiny text file to **each**:
   - into alpha: `canary.txt` containing `ALPHA-<CANARY>-OK`
   - into bravo: `canary.txt` containing `BRAVO-<CANARY>-SECRET`

   A few bytes each. **Delete both buckets at the end of the session.**

3. **IAM → Roles → Add → Advanced mode**, paste the policy above as `zt-sos-nobravo`.
   Role permissions **unchecked**. (The portal's Advanced-mode JSON editor accepts rules
   policies, so no Owner API key is needed this session.)

4. **IAM API Keys → Add** → `zt-sos-nobravo-key`, bound to that role. Secret stays local.

---

## PHASE 1 — the gates (do both, screenshot both)

| Gate | Request | Required |
|---|---|---|
| **0A** positive control | GET `zt-alpha-<CANARY>/canary.txt` | **200** + `ALPHA-<CANARY>-OK` |
| **0B** negative baseline | GET `zt-bravo-<CANARY>/canary.txt` | **403** — record the exact body |

Without 0A every later denial is meaningless. Without 0B there is nothing to bypass.

---

## PHASE 2 — the binding matrix

Every row tries to read **bravo's** object. The policy denies bravo by exact string match.

| # | Variant | What it probes |
|---|---|---|
| 1 | **virtual-host style** `zt-bravo-X.sos-ch-gva-2.exo.io/canary.txt` | bucket from **Host** vs from **path** |
| 2 | **path-style** (whichever 0B did *not* use) | the mirror of 1 |
| 3 | **Uppercase bucket** `ZT-BRAVO-X` | CEL `==` is case-sensitive; is the storage layer? |
| 4 | **Mixed case** `Zt-Bravo-X` | partial-fold handling |
| 5 | **Trailing dot in host** `zt-bravo-X.sos-ch-gva-2.exo.io.` | FQDN root label — often stripped late |
| 6 | **Explicit port in Host** `…exo.io:443` | Host parsed before or after port strip |
| 7 | **URL-encoded bucket** `%7At-bravo-X` / `zt%2Dbravo%2DX` | decode ordering |
| 8 | **Leading/double slash** `//zt-bravo-X/canary.txt` | path normalisation |
| 9 | **Dot segment** `/zt-alpha-X/../zt-bravo-X/canary.txt` | which segment binds |
| 10 | **Unicode-equivalent name** | NFC/NFKC normalisation |
| 11 | **Presigned URL** minted by this key for bravo | is the rule applied at signing, at redemption, or neither? |
| 12 | **Multipart** `create-multipart-upload` on bravo | does the rule cover every operation name? |
| 13 | **ListBuckets** `GET /` | an operation with **no** bucket parameter — what binds then? |
| 14 | **CopyObject** alpha → bravo, and bravo → alpha | the **source** bucket may bind differently from the destination |

> **Rows 11 and 14 are the sleepers.** Presigned URLs move the decision to a different moment,
> and copy operations involve *two* buckets where implementations frequently bind only one.

---

## Tooling

SOS speaks **S3, signed with AWS SigV4** — the EXO2 signer from H1/H4 does **not** apply here.
Use boto3, which handles SigV4 and lets us force the addressing style and add the required
header:

```bash
sudo apt install -y python3-boto3
```

```python
import boto3, botocore
cfg = botocore.config.Config(s3={"addressing_style": "path"})   # or "virtual"
s3 = boto3.client("s3",
        endpoint_url="https://sos-ch-gva-2.exo.io",
        region_name="ch-gva-2",
        aws_access_key_id=KEY, aws_secret_access_key=SECRET,
        config=cfg)
s3.meta.events.register(
    "before-send.s3.*",
    lambda request, **kw: request.headers.add_header("X-Intigriti-Username", "gorib"))
```

For the raw host/path tricks that boto3 will normalise away (rows 5–9), fall back to the
mitmproxy rig from H1 and rewrite the request in the addon.

---

## Reading results

| Response | Meaning |
|---|---|
| **200 containing `BRAVO-<CANARY>-SECRET`** | 🎯 **Finding.** Policy denied the bucket; the bytes came back anyway |
| 200 with an **empty** body | Not a finding. Capture it, keep going |
| 403 | Correctly enforced on that axis. Log the negative, next row |
| 400 / signature error | **Rig failure, not a result.** Re-sign and retry |
| 404 | Routed nowhere — bucket name mangled past recognition |

**The proof is the canary, not the status code.**

---

## Drop conditions

- Every row returns 403 or 404 → **binding is consistent. H5 closes.** Log honestly (FO-7).
- A variant returns bravo's bytes but the policy turns out not to have applied (typo in the
  bucket name in the rule) → **void, not a finding.** Re-read the policy first, every time.
- Behaviour matches documented S3-compatibility caveats → intended (Quality Bar #2).

---

## Evidence checklist (CLAUDE.md §9.8)

- [ ] The role policy JSON showing the explicit `deny` on bravo
- [ ] Gate 0A: alpha readable, 200 + alpha canary
- [ ] Gate 0B: bravo plainly denied, 403, exact body
- [ ] The bypass request and response **verbatim**, with **bravo's canary visible**
- [ ] `X-Intigriti-Username: gorib` in the captured request
- [ ] Date/time, external IP (`curl ifconfig.me`), tool versions
- [ ] Differential: expected (403 per policy) vs observed (200 + bravo's data)
- [ ] Both buckets are ours; no third-party bucket name was ever requested
- [ ] Keys/secrets redacted to first/last 4
- [ ] First-person plain voice, real terminal output (FO-10)

## Safety & cost

- **Read-only against bravo.** The only writes are our own canary objects into our own buckets.
- **Never** probe a bucket name we do not own — SOS bucket names are a global namespace and a
  guessed name is someone's real data (FO-14, and the programme's explicit customer rule).
- Delete both buckets and the key at session end. Balance must still read 20.00 CHF.
