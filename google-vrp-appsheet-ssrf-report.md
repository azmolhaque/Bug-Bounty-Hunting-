# Google VRP Submission: SSRF in AppSheet Apigee API Connection Feature

## Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in AppSheet's "Add Apigee API
connection information" feature. When a user supplies a URL in the "Apigee OpenAPI Spec URL"
field, AppSheet's backend fetches that URL server-side through Google's internal Squid proxy
(`squid-proxy-open-api-us-west1-sqws`). This was confirmed via out-of-band (OOB) HTTP and
DNS callbacks containing Google-infrastructure headers.

---

## Product / Affected URL

- **Product**: AppSheet (appsheet.com)
- **Feature**: Account → API → Add Apigee API connection information
- **Endpoint**: `https://appsheet.com/Account/Api` (exact path omitted to avoid exposing
  internal routing; the vulnerable field is the "Apigee OpenAPI Spec URL" input)

---

## Vulnerability Type

Server-Side Request Forgery (SSRF) — CWE-918

---

## Severity

**Medium–High** (estimated P2)

The backend fetch originates from Google infrastructure and passes through an internal Squid
proxy. Direct access to GCP metadata (`169.254.169.254`) and `metadata.google.internal` is
blocked by the proxy's ACL, and the proxy does not follow HTTP redirects. However:

- The SSRF is confirmed and controllable.
- The internal proxy hostname is disclosed.
- The server can be directed to probe other internal or external hosts.
- HTTPS response bodies are partially reflected in error messages, enabling blind content
  exfiltration from reachable hosts.

---

## Steps to Reproduce

> Prerequisites: An AppSheet account with access to the Apigee API settings page.

1. Log in to AppSheet and navigate to **Account → API**.
2. Click **Add Apigee API connection information** (or open the equivalent modal).
3. In the **"Apigee OpenAPI Spec URL"** field, enter an OOB interaction URL such as:
   ```
   http://<your-interactsh-subdomain>.oast.pro/test
   ```
   (or any collaborator URL that logs incoming HTTP requests)
4. Click **Save** or **Connect**.
5. Observe the DNS and HTTP callbacks on your OOB listener — the request originates from a
   Google IP address with the following header:
   ```
   Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
   ```

### Variant — HTTPS body reflection

1. Repeat step 3 using an **HTTPS** OOB URL:
   ```
   https://<your-interactsh-subdomain>.oast.pro/test
   ```
2. The AppSheet error response includes partial HTML from the page served at that URL,
   confirming the server fetched and read the response body.

### Variant — Internal host probing (error fingerprinting)

The following test URLs produce distinct, differentiable error messages, confirming the
backend reaches (or attempts to reach) each target:

| Test URL | AppSheet Error Response |
|---|---|
| `http://nonexistent-domain-xyz.invalid/` | "servers temporarily unavailable" (DNS failure) |
| `http://169.254.169.254/` | "You do not have permission" (Squid reached the IP, blocked by ACL) |
| `http://metadata.google.internal/` | "You do not have permission" (same — internal DNS resolved) |
| `http://10.x.x.x/` (RFC-1918 range) | "You do not have permission" |
| `http://<oast-http-domain>/` | "temporarily unavailable" + OOB callback received |
| `https://<oast-https-domain>/` | HTML body of the OOB response reflected in error |

---

## Proof-of-Concept Evidence

### 1. OOB DNS and HTTP Callback

Interactsh (`oast.pro`) listener received the following interaction when the OOB URL was
submitted:

```
[DNS]  q-type=A  from=<Google-IP>  subdomain=<oast-subdomain>
[HTTP] GET /test HTTP/1.1
       Host: <oast-subdomain>.oast.pro
       Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
       X-Forwarded-For: <Google-IP>
```

The source IP resolves to Google LLC ASN infrastructure, consistent with an AppSheet
backend worker in GCP's us-west1 region.

### 2. HTTPS Body Reflection

Submitting `https://<oast-subdomain>.oast.pro/` caused the AppSheet error modal to include
verbatim HTML from the page served at that URL, confirming:
- The server fetched the full HTTP response.
- Part of the body is embedded in the client-facing error message.

### 3. Internal Hostname Resolution

`http://metadata.google.internal/` returned "You do not have permission" rather than a DNS
failure, confirming that:
- The backend resolves internal GCP hostnames.
- The request is blocked only at the Squid ACL layer, not at the DNS or network layer.

---

## Impact

1. **Internal network probing**: An attacker can use error-message differences to map which
   internal hosts and ports are reachable from the AppSheet backend.
2. **Partial response exfiltration**: HTTPS URLs cause response bodies to be reflected in
   error messages, enabling content to be read from any HTTPS host reachable by the backend.
3. **Proxy hostname disclosure**: The internal proxy identifier
   (`squid-proxy-open-api-us-west1-sqws`) is exposed in outgoing HTTP headers.
4. **Potential for escalation**: If the Squid ACL is ever misconfigured, adjusted, or bypassed
   (e.g., via a future URL parser confusion bug), the confirmed SSRF channel could reach the
   GCP metadata service and retrieve OAuth tokens for the instance's service account.

---

## Root Cause

AppSheet's Apigee integration backend fetches user-supplied URLs without sufficient restriction
to allow only legitimate Apigee API spec hosts. The URL is passed directly to a server-side
HTTP client (routed through Squid), and the response is partially surfaced to the user.

---

## Suggested Remediation

1. **Allowlist**: Only fetch URLs from known Apigee/GCP API Management domains
   (`*.apigee.com`, `*.apigee.net`, etc.) and reject all others.
2. **Block internal address ranges**: Enforce egress controls so the fetch client cannot
   reach RFC-1918 ranges, link-local addresses (`169.254.0.0/16`), or internal DNS names.
3. **Strip or sanitize error messages**: Never include fetched response bodies or proxy
   headers in client-facing error messages.
4. **Validate OpenAPI spec content-type**: Only accept responses with a valid
   `application/json` or `application/yaml` content-type to limit what can be fetched.

---

## References

- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- Google VRP scope: https://bughunters.google.com/about/rules/6625378258649088

---

## Attachments Checklist

When submitting, include:
- [ ] Screenshot of AppSheet "Add Apigee API connection information" form with OOB URL entered
- [ ] Screenshot of the error response showing "Via: squid-proxy..." header disclosure
- [ ] Interactsh / Burp Collaborator log showing DNS + HTTP callbacks from Google IPs
- [ ] Screenshot of HTTPS body-reflection error message
- [ ] Screenshot of "You do not have permission" error for `169.254.169.254`
- [ ] HTTP traffic capture (Burp Suite) showing the full request/response cycle

---

*Reported by: zahinshahriar3@gmail.com*  
*Date: 2026-06-18*  
*Program: Google Vulnerability Reward Program — https://bughunters.google.com*
