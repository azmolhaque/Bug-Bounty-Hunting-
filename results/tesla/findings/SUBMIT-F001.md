# F001 — Bugcrowd submission text (paste-ready)

**Do not submit until Bugcrowd identity verification is complete.**
Attach: the four screenshots listed in F001 §Evidence held locally, including the
`www.tesla.com` `config_web.json` one.

---

## Title

```
Unauthenticated Tesla config files expose a working unrestricted Baidu Maps key and a live ipinfo.io account token (www.tesla.com and www.tesla.cn)
```

## Target

`*.tesla.com`, `*.tesla.cn`

## VRT — choose `Pay-Per-Use Abuse`

`Sensitive Data Exposure > Disclosure of Secrets > Pay-Per-Use Abuse`

Read off Tesla's live submission form, the siblings under `Disclosure of Secrets` and their
default priorities are:

| Subcategory | Priority |
|---|---|
| For Publicly Accessible Asset | **P1** |
| For Internal Asset | P3 |
| **Pay-Per-Use Abuse** | **P4** ← correct for this finding |
| Data/Traffic Spam | P5 |
| Intentionally Public, Sample or Invalid | **P5** ← the risk to pre-empt |
| Non-Corporate User | P5 |

**Do not pick P1.** "For Publicly Accessible Asset" means a secret that grants access to the
*program's own* asset. Ours grants access to a third-party metered account (ipinfo, Baidu), which
is exactly what `Pay-Per-Use Abuse` is defined for. Picking P1 here would be the severity
inflation that gets reports auto-closed, and it would be wrong on the facts.

**The real danger is P5 "Intentionally Public, Sample or Invalid"** — a triager skimming this
could decide a client-side maps key is public by design and close it in thirty seconds. Two
sentences kill that argument, so they must come first in the description, before anything else:

> Tesla restricts its own Google Maps keys — the same call shape is refused with
> `REQUEST_DENIED: API keys with referer restrictions cannot be used with this API`. This Baidu
> key is not restricted, and the ipinfo.io token cannot be restricted at all, because ipinfo
> offers no referrer control — it is a server-side credential published in a client-side file.

Neither credential is a sample and both are live, which disposes of the rest of that P5 bucket.

## CVSS 3.1

`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` — **6.5 Medium**

Confidentiality Low: Tesla's ipinfo account plan and usage are readable.
Availability Low: the quotas these credentials consume back two customer-facing features
(the China "Find Us" map, the configurator's IP region lookup), and the ipinfo plan is a free
tier with no overage headroom, so exhaustion is an outage rather than a bill.

## Description

Paste the body of `F001-unrestricted-baidu-maps-key.md` from "## The point in one sentence"
onward. It already contains, in order: the two credentials, the host-by-host spread table,
the Baidu accept/refuse ceiling (5 services accepted, 4 refused), the `ipinfo.io/me` account
read with the negative control, the proof the token is in live production use, the Google-key
differential, impact, remediation, the GitHub 0-results dedup check, and the reproduction block
with timestamp, IP and curl version.

---

## Honest expectation before you submit

- The Baidu key alone is the kind of finding programs commonly rate **P4 (~$100)**.
- The parts that lift it above a routine key leak, and that you should make sure the triager
  reads, are: (1) the key is **unrestricted while Tesla's own Google keys are restricted** —
  that kills "intended behavior"; (2) the ipinfo token **cannot be referrer-restricted at all**,
  so it is unambiguously a server-side secret published client-side; (3) `ipinfo.io/me` returns
  **Tesla's account state**; (4) it is on **`www.tesla.com`**, not just the China site.
- Do not re-argue the severity if it is set lower than you hoped. Per FO-12, a rejection is not
  re-litigated with the same evidence.

---

## SUBMITTED — 2026-10-06

Submission `c036dc61-24a7-442d-8783-67b6a86fd81f`, state **New** (awaiting triage).
Target `*.tesla.com`. VRT accepted as **P4 — Sensitive Data Exposure > Disclosure of Secrets >
Pay-Per-Use Abuse**. Nine attachments: four screenshots, four JSON files, one manifest.

Program stats read off the engagement page at submission time:

```
Validation within   4 days      75% of submissions accepted or rejected within 4 days (last 3 months)
Average payout      $1,312.24   last 3 months
```

The average is **not** a forecast for this report. It is dominated by vehicle and infrastructure
findings at P1/P2. A P4 credential leak sits far below it.

### Honest outcome estimate, recorded before the answer is known

| Outcome | Estimate | Why |
|---|---|---|
| **Duplicate** | ~40% | The single largest risk. `/api/findus/env` is a plain unauthenticated endpoint on a ten-year-old program with thousands of hunters. The archive-derived `config_web.json` path is the less-trodden half of the finding; the Baidu key is not. |
| **Accepted P4** | ~30% | The likely accept. Recent comparable web accepts on this program: $500 (2 Oct, `*.tesla.com`), $700 (1 Oct, `*.tesla.cn`). |
| **Accepted P3** | ~10% | Only if the triager weighs the `ipinfo.io/me` account read and the proven server-side spend on `.com` as more than pay-per-use. |
| **N/A / Informational / Won't Fix** | ~20% | "Third-party key, accepted risk." The Google-key differential is the defence against this and it is a strong one, but it is not a guarantee. |

Realistic expected value: **$150–$400**, with a good case of **$500–$700** and a real chance of
**$0**. Anyone reading this later should not treat the $1,312 average as the number to expect.

### Rule for the wait

Do not chase this submission. Do not ask for a status update before the 4-day window has passed,
do not argue the tier if it lands P4, and do not re-argue a close with the same evidence (FO-12).
The correct use of the waiting period is the next finding, not this one.
