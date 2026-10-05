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

## VRT

`Sensitive Data Exposure > Disclosure of Secrets > Pay-Per-Use Abuse`

If the triager prefers it, the `ipinfo.io/me` result (the token reads Tesla's plan, month-to-date
usage and remaining balance, i.e. account state, not just a lookup) supports
`Sensitive Data Exposure > Disclosure of Secrets` at one tier higher. I am not arguing severity up
myself — I am stating what I proved and leaving the tier to triage.

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
