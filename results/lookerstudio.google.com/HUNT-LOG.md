# Looker Studio (Data Studio) Hunt Log
Target: lookerstudio.google.com / datastudio.google.com
Program: Google / Alphabet VRP — bughunters.google.com
Tier: TIER1 (Looker acquisition, 2019, $2.6B)
Started: 2026-06-19

---

## Status Summary

| ID | Class | Surface | Status | Severity |
|----|-------|---------|--------|----------|
| LS-L001 | SSRF (Apps Script UrlFetchApp) | Community Connector — JSON by Windsor.ai | LEAD | Low as-is / High if IMDS reachable |

---

## Session 1 — 2026-06-19

### Background

Looker Studio allows third-party "community connectors" — Google Apps Script projects that
act as data sources. Connector code runs on Google's Apps Script servers (GCP AS15169)
and calls `UrlFetchApp.fetch()` to retrieve data. Many connectors accept a user-supplied
URL as a configuration parameter, making the Apps Script server fetch an attacker-controlled
endpoint on the user's behalf.

This is a SSRF-class issue: the _server_ makes the request, not the user's browser.
The key question is whether the Apps Script server-side fetch can reach GCP-internal
resources (IMDS, internal APIs), turning this into a High/Critical.

### Surface Discovery

- **Entry point**: lookerstudio.google.com → "+ Create" → "Data Source" → "Build your own connector"
  or browse the connector gallery
- **Attack-relevant connector found**: "JSON" by Windsor.ai
  - URL: configured in the Looker Studio Data Source setup
  - Accepts a user-supplied URL
  - Calls `UrlFetchApp.fetch(url)` in its Apps Script backend
  - Fetches must be JSON-parseable for the connector to succeed; OOB endpoint only
    needs to respond with valid HTTP (JSON body preferred but DNS hit alone is sufficient)

### Test LS-L001 — OOB SSRF via JSON Community Connector

**Date**: 2026-06-19 ~21:39 UTC  
**Technique**: Entered OOB URL in JSON connector "URL" field → clicked CONNECT  
**OOB URL**: `https://d8qr3pq69r82jtv3r0dgypczrcgc81t3k.oast.pro`  
**Listener**: `interactsh-client -server oast.pro`

**OOB hits received**:

```
[21:39:59] DNS interaction (A) from 34.116.28.176
           [d8qr3pq69r82jtv3r0dgypczrcgc81t3k] Received DNS interaction (A) from 34.116.28.176
           ASN: AS15169 (Google LLC)

[21:39:59] HTTP interaction from 35.187.134.140
           GET / HTTP/1.1
           Host: d8qr3pq69r82jtv3r0dgypczrcgc81t3k.oast.pro
           Accept: application/json
           Accept-Encoding: gzip, deflate, br
           Connection: keep-alive
           User-Agent: Mozilla/5.0 (compatible; Google-Apps-Script; beanserver; +https://script.google.com; id: UAEmdDd_AEHKSuIakjA1MJYbkp8mqyDAvo4w)
           X-Forwarded-For: 2a09:bac5:55fd:18be:0:0:277:ae
           ASN: AS15169 (Google LLC)
```

**Confirmed**:
- DNS resolver: `34.116.28.176` (GCP) — confirms DNS-layer SSRF
- HTTP fetcher: `35.187.134.140` (GCP) — confirms HTTP SSRF
- User-Agent: `Google-Apps-Script; beanserver` — definitely Apps Script server-side, not browser
- `Accept: application/json` — the connector expects JSON response
- `X-Forwarded-For`: user's real IPv6 `2a09:bac5:55fd:18be:0:0:277:ae` is forwarded to the server

**No auth tokens or GCP SA credentials in the request headers** (checked: no Authorization,
no X-Goog-*, no metadata headers).

### Triage Assessment

**Attacker gain (current evidence)**:
- Server-side HTTP request originates from GCP AS15169 — request appears to Google infrastructure origin
- User's real IPv6 is forwarded to whatever server they enter
- No credentials or internal data confirmed accessible

**Severity as-is**: LOW/INFORMATIONAL
- OOB hit from GCP is confirmed but no sensitive resource access demonstrated
- X-Forwarded-For IP leak: user controls the URL so they see their own IP — not an attacker-impacts-victim finding unless a malicious connector is the vector (see Chain note below)

**Chain potential (BLOCKED by security constraints)**:
- If `UrlFetchApp` is NOT restricted from fetching `169.254.169.254` or `metadata.google.internal`,
  this escalates to CRITICAL (GCP SA token exfil from Apps Script service account)
- Per session security constraints: IMDS/internal IP probing is PROHIBITED
- Decision: Cannot verify chain without violating constraints; logged as HIGH-PRIORITY LEAD

**Intended behavior question**:
- `UrlFetchApp` is a documented Apps Script API
- Community connectors are explicitly designed to fetch external data
- BUT: Google may not intend for user-supplied URLs to trigger server-side fetches without restriction
- Key distinction: the URL comes from the _user_ configuring a _third-party_ connector inside _Google's_ product
- Comparable to: SSRF in a webhook receiver — the platform controls the fetch, user supplies the URL

**Google VRP angle**:
- If Google's Apps Script sandbox does NOT block IMDS → reportable Critical
- If it blocks IMDS but allows RFC1918 → reportable High (reach other GCP internal services)
- If fully restricted to external IPs → probably "intended" — Apps Script fetches external data as designed

### Decision Log

- **2026-06-19**: LEAD logged. Cannot escalate without IMDS test (security constraint prohibits).
  Action: Research public disclosures on UrlFetchApp SSRF / IMDS access. If prior public
  evidence exists that IMDS is NOT blocked, submit with OOB evidence + citation.
  Otherwise, hold and watch for constraint to be lifted or scope to clarify.

### Research Results — 2026-06-19

Public research sweep completed:
- **No public CVE or bug bounty disclosure found** for Apps Script UrlFetchApp → IMDS access (2020-2026)
- Google's official UrlFetchApp docs are silent on internal IP restrictions (no explicit block documented)
- Tenable's "LeakyLooker" (2025, 9 Looker Studio vulns) focused on SQLi / cross-tenant data leak — did NOT surface SSRF-to-IMDS, suggesting either (a) not tested or (b) blocked by sandbox
- No HackerOne/bugcrowd disclosures for community connector SSRF chains
- Absence of public disclosure for a high-value class suggests: either IMDS is blocked (hence no reports), or the attack surface hasn't been deeply tested

**Inference**: IMDS access via UrlFetchApp may be blocked in Google's current Apps Script sandbox. However this is unconfirmed. The silence is ambiguous — it could mean "patched before disclosure" or "blocked from day 1."

**Security constraint block**: Direct IMDS/RFC1918 probing is prohibited. Cannot verify the critical chain link.

### Final Decision

**HOLD indefinitely.** The OOB hit alone does not meet the CLAUDE.md §2 submission bar:
- Attacker gain is not concrete (no internal data accessible demonstrated)
- Likely intended behavior (UrlFetchApp fetching user-supplied URLs is Apps Script's purpose)
- Without IMDS chain, the finding would be closed as informational

**Do not submit LS-L001 as-is.** Revisit only if:
- Security constraints are explicitly lifted for this specific test
- Public research surfaces that UrlFetchApp does NOT block IMDS in some connector context
- A redirect-based chain from an external URL to an internal resource is discovered without direct probing

**Next action**: Pivot to Wing.com (00-plan.md exists, completely untested, free target).
