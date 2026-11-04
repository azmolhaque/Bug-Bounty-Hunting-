# AppSheet — OSINT Prior-Art Review & Next-Session Leads

**Date:** 2026-06-16  
**Method:** Passive only (public search + published writeups). No target access — this
container's egress allowlist blocks `*.appsheet.com`, so live testing must run on the Pi /
authenticated browser. Nothing here touched the live target or any non-public data.

---

## 1. AppSheet public vulnerability history (what's already known/fixed)

| Year | Bug | Subsystem | Class | Reward | Status |
|------|-----|-----------|-------|--------|--------|
| 2021 | Webhook SSRF → GCP metadata token | **Webhook automation** | SSRF (CWE-918) | ~$6,267 | Fixed (point-fix in webhook path) |
| 2022 | Deserialization RCE (malicious .NET object → PowerShell) | **Automation Bot** | Insecure deserialization (CWE-502) | $10,000 | Fixed |
| 2023 | CVE-2023-4212 | *Trane thermostats* — **NOT AppSheet** | OS command injection | n/a | Unrelated (mis-citation) |

**Reading:** every real AppSheet VRP win sits in the **Automation Bot / webhook** subsystem.
Our F002 is in a **different** subsystem (the OData **data connector**), which is why it is
net-new — see `F002-dedup-CVE-2023-4212.md`.

---

## 2. The systemic insight (this is the high-impact angle)

The 2021 SSRF was fixed **only in the webhook path** (legacy metadata endpoint + specific
metadata headers). No centralized, IP-level egress filter was added. F002 confirms the OData
connector — a separate server-side-fetch feature — **still reaches `169.254.169.254` at the
TCP layer in 2026**, gated only by the .NET client incidentally not following HTTPS→HTTP
redirects.

**Hypothesis worth proving (clean, in-bounds):** AppSheet relies on **per-feature** SSRF
mitigations rather than one egress control. If so, *other* user-controllable server-side-fetch
features likely also lack egress filtering. Demonstrating the gap across **multiple** connectors
(not just OData) turns F002 from a single SSRF into a **systemic egress-control gap** — a
stronger, higher-tier narrative for Google VRP.

---

## 3. Candidate server-side-fetch surfaces to test next (Pi / authed browser)

All are "make the AppSheet backend fetch a URL I control" primitives. For each: point at an
OOB listener, confirm a GCP-origin hit, then **stop** (do not pivot to internal/IMDS, do not
read others' data). Prove the egress gap; let Google confirm escalation.

1. **REST API data connector** (distinct from OData) — HUNT-LOG action #2. Likely same code
   family, separate validation.
2. **Image / file URL columns** — app data referencing an external image/file URL; does the
   backend fetch it server-side (thumbnailing, caching)?
3. **PDF / report generation with external resources** — HUNT-LOG action #5; report templates
   pulling remote images/CSS.
4. **Other connector types** (e.g., Salesforce/SQL/HTTP connectors) that take a host/URL.
5. **OData "valid-TLS metadata" path** (HUNT-LOG "Path 3", incomplete) — serve valid OData
   XML over HTTPS, add the source, trigger a **data** fetch (`/Rows`); test whether the
   data-fetch code path differs from the metadata-test path. Note: this is for confirming the
   *fetch* reaches your server — **not** for redirect/IMDS chaining.

If ≥2 of these show an unfiltered GCP-origin fetch, file a single consolidated
"systemic SSRF egress gap" report referencing F002, plus the credential-forwarding issue.

---

## 4. F001 escalation lever — staging App UUID (passive collection only)

F001 → Critical needs a valid `gcp-staging` App UUID. Passive OSINT sources to check from the
Pi (do **not** use any found UUID to read staging data — collect candidates and let Google
validate, or test only against an app you own on staging):

- Public GitHub code/issues for AppSheet API samples leaking real `appId` values
  (several public AppSheet API wrapper repos exist: `tyayers/appsheet-api-template`,
  `Qodea/AppSheetApp`, `hoangsetup/appsheet-client-api`, `calderonsamuel/appsheet`).
- AppSheet community/forum posts and tutorials embedding app links (`appId` is in app URLs).
- Google-employee/AppSheet org public repos or docs referencing `gcp-staging`.

**Ethical note:** finding a UUID is OSINT; *using* it against staging to read/modify data is
data access and is out of bounds for our methodology. The clean proof is: confirmed auth is
absent (done) + a valid UUID exists → hand to Google.

---

## 5. Could not run from this container (deferred to Pi)

- `crt.sh` / CT-log subdomain enumeration — WebFetch is 403'd by crt.sh here. Run on the Pi:
  `curl -s 'https://crt.sh/?q=%25.appsheet.com&output=json' | jq -r '.[].name_value' | sort -u`
  (the Pi recon already found ~50 subdomains; cross-check for any new `*-staging` / `dev` /
  `internal` hosts and re-run the F001 auth-bypass diff against each API-like host).

---

## Sources

- 2021 AppSheet webhook SSRF: https://dayzerosec.com/vulns/2021/12/13/ssrf-vulnerability-in-appsheet-google-vrp.html · https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
- 2022 AppSheet deserialization RCE: https://bughunters.google.com/reports/vrp/oCeVFaaoi · https://infosecwriteups.com/10-000-google-bug-bounty-how-a-deserialization-rce-in-appsheet-could-have-led-to-remote-code-955b0a2e840b
- CVE-2023-4212 (Trane, unrelated): https://nvd.nist.gov/vuln/detail/CVE-2023-4212
- Public AppSheet API repos: https://github.com/tyayers/appsheet-api-template · https://github.com/Qodea/AppSheetApp
