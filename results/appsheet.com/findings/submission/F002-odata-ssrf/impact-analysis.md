## Confirmed Impact (demonstrated)
- **SSRF:** a server-side HTTP request executes from AppSheet's GCP backend
  (`35.203.182.241`) to an arbitrary attacker-controlled URL, with DNS resolved via
  Google resolvers (AS15169).
- **Credential leak:** any Username/Password entered into the OData form is forwarded in
  an `Authorization: Basic` header to the attacker-controlled destination. In the
  shared-/imported-connector scenario below, this harvests a *victim's* real OData service
  credentials.
- **Internal header leak:** the `Traceparent` W3C trace context exposes AppSheet's
  backend distributed-tracing identifiers.
- **Info disclosure:** the destination's response content type is reflected in AppSheet's
  error message.
- No protection beyond a free account; no rate limit, no IP restriction on the Test action.

## Documented Risk (NOT exploited)
- The GCP Instance Metadata Service (`169.254.169.254:443`) is **TCP-reachable** from the
  AppSheet backend pod (established via TLS-failure differentiation). This is reported as
  network-reachability only. No metadata, token, or credential was retrieved; no redirect
  chaining or internal port probing was performed. A redirect-based escalation toward IMDS
  is a plausible path **if** the backend client follows cross-scheme redirects, but it was
  intentionally not tested and is flagged for AppSheet's internal assessment.

## Attack Scenarios
1. **Self-initiated SSRF / internal reachability mapping:** attacker registers a free
   account, sets the OData URL to their server, and confirms server-side requests
   originate from inside GCP — establishing internal network reach.
2. **OData credential phishing via shared connector:** attacker publishes/share an OData
   connector "template" pointing at their server; a victim importing it and entering their
   real OData credentials has those credentials forwarded to the attacker by AppSheet's
   backend — no browser interaction required on the attacker side.

## Severity (CVSS 3.1)
**Confirmed SSRF with credential + internal-header leak:**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered via the AppSheet web app |
| Attack Complexity | Low | Single Test click against an attacker URL |
| Privileges Required | Low | Free AppSheet account |
| User Interaction | None | Self-initiated SSRF (phishing variant adds victim UI) |
| Scope | Changed | Requests originate from the GCP backend (separate authorization boundary) and reach internal/link-local network space |
| Confidentiality | High | Credential forwarding + internal tracing-header leak + confirmed internal/link-local network reach |
| Integrity / Availability | None | No write or DoS demonstrated |

**Conservative floor:** if triage scores only data definitively exfiltrated in the
self-test, `...S:C/C:L/...` = **5.0 (Medium)**. The credential-phishing variant and the
confirmed internal reachability justify the **High** rating; the score does not depend on
IMDS credential retrieval, which was not performed.

## Why This Matters for Google VRP
A TIER0 Google asset (`*.appsheet.com`) executes attacker-directed server-side requests
from inside GCP, forwards user credentials to arbitrary hosts, leaks internal tracing
context, and has confirmed TCP reachability to the GCP metadata service — a classic
SSRF-to-IMDS pre-condition that should be closed at the egress/network layer.
