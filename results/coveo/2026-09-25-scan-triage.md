# Coveo — automated scan triage, 2026-09-25

Scope confirmed before triage: `*.cloud.coveo.com` is **in scope, Tier 2**, Coveo Public Bug
Bounty on Intigriti. Hosts touched were in scope.

A ~30 minute automated scan produced **three finding classes and over 100 `[FINDING]`
lines. Zero are valid bugs.** Two are scanner logic errors; one is an unclaimable
precondition. Recorded in full because the failure modes are reusable, not because the
results are.

---

## 1. `[SSL-MISMATCH]` ×2 — FALSE POSITIVE (scanner logic error)

```
status.cloud.coveo.com        CN: now.phtech.com                     HTTP 200
status-hipaa.cloud.coveo.com  CN: dallasisd.status.powerschool.com   HTTP 200
```

Both certificates are **Atlassian Statuspage shared certs**. The operator's own screenshots
settle it: the SAN list of the `now.phtech.com` cert contains `status.cloud.coveo.com`
alongside dozens of unrelated tenants — `status.finout.io`, `status.kinsta.com`,
`status.iterable.com`, `status.tresorit.com`, `status.secureauth.com`. The
`dallasisd.status.powerschool.com` cert likewise carries `status-hipaa.cloud.coveo.com`.

**TLS validates against SAN, not CN.** CN-based hostname matching has been deprecated since
RFC 2818 and browsers ignore CN entirely. The pages load with a valid padlock.

**Scanner bug:** compares CN to the requested hostname and never reads SAN. One-line fix.

Doubly dead: Statuspage is third-party, which Coveo's policy redirects to the provider.

## 2. `[OPEN-REDIRECT]` ×100+ — FALSE POSITIVE (scanner logic error)

```
https://analytics-au.cloud.coveo.com?next=https://…evil.com
  -> location: https://platform-au.cloud.coveo.com/?next=https://…evil.com
```

**Every single `Location` points at a `*.cloud.coveo.com` host.** This is a fixed
`analytics-*` → `platform-*` redirect that preserves the query string. The canary appears in
the URL because it is carried along, not because it is the destination. The attacker
controls nothing about the target host.

**Scanner bug:** matches the payload appearing anywhere in the `Location` header without
comparing the **host** before and after. One-line fix: parse the Location and compare
netloc.

Doubly dead: even a genuine redirect to a target-owned domain is on the Hard Rejection List
(CLAUDE.md §3 — "open redirect to a domain owned by the target").

## 3. `[DANGLING-CNAME]` ×1 — REAL DANGLE, UNCLAIMABLE. Closed.

```
api.appcues.cloud.coveo.com  ->  85197.custom-domains.appcues.com
```

Verified:

```
dig 85197.custom-domains.appcues.com   ->  status: NXDOMAIN, ANSWER: 0
dig +short custom-domains.appcues.com  ->  (empty — no A record)
curl -sI https://api.appcues.cloud.coveo.com  ->  no response at all
```

The dangle is genuine. **The takeover is not possible**, for a mechanical reason rather than
a policy one: `85197` is an **Appcues-assigned account identifier**. Registering with Appcues
gets you a number of their choosing, not one of yours, so there is no path to serving content
on that hostname — no content, no canary, no takeover. The parent `custom-domains.appcues.com`
does not resolve either, so there is no wildcard behind it.

Three independent blocks, any one sufficient:

1. Coveo's out-of-scope list, verbatim: **"Subdomain takeover without taking over the subdomain."**
2. CLAUDE.md §6 — a dangling CNAME is a precondition. Same error as `win-test.wiz.io`, where
   claimability was assumed and never proven.
3. Appcues is third-party; Coveo redirects those to the provider.

Closed, with the claimability question actually answered rather than assumed.

---

## Lesson — candidate for METHODOLOGY.md

**FO-18 — A scanner's word "FINDING" is a label, not a judgement.**
This run emitted 100+ lines tagged `[FINDING]` and contained zero findings. Both false-positive
classes came from the tool checking a *substring* where the *semantics* mattered: CN instead of
SAN, and payload-in-header instead of host-changed. Before triaging any scanner output, ask what
comparison the check actually performs — and read one full response by hand before believing a
hundred summaries.

Cost of not doing so here: 30 minutes of scan plus the triage time. Cost of a submission would
have been program reputation.
