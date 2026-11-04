# ICRC VDP Hunt Log

**Program**: ICRC Vulnerability Disclosure Policy (*.icrc.org)
**Status**: SUSPENDED — no exploitable pre-auth surface found
**Date**: 2026-06-20

## Subdomains Discovered
| Host | IP | Status | Notes |
|------|----|--------|-------|
| www.icrc.org | Azure Front Door | 200 | Main site, Azure CDN |
| api.icrc.org | 80.94.147.175 | 404 all paths | JBoss/WildFly + F5 ASM WAF; "No context-path matches" error; unknown deployment paths |
| auth.icrc.org | 80.94.147.172 | WAF BLOCKED | E-XPERT SOLUTIONS SSO; Pi IP blocked after probe |
| test.icrc.org | 80.94.146.176 | Auth wall | F5 BIG-IP APM; SSO_ORIG_URI errorcode=22 |
| extranet.icrc.org | 80.94.147.215 | Auth wall | F5 BIG-IP login required |
| elearning.icrc.org | 128.65.195.27 | 403/404 | Apache; root 403; all paths 404; likely internal-only |
| shop.icrc.org | 45.157.190.36 | DOWN | TCP connection refused globally |
| ext.icrc.org | 80.94.147.x | Auth wall | F5 BIG-IP APM → portal.ext.icrc.org |
| portal.ext.icrc.org | 80.94.147.96 | 404 | F5 BIG-IP; requires SSO session |
| ap6.ext.icrc.org | 80.94.147.x | Auth wall | F5 APM SSO; SSO_ORIG_URI errorcode=22 |
| formlogin.ext.icrc.org | 80.94.147.x | Login form | F5 APM email+password login (SFA for external users) |
| matomo.ext.icrc.org | 80.94.147.x | ERR_EMPTY | HTTP 302 → HTTPS broken TLS; self-hosted Matomo |
| analytics.ext.icrc.org | 80.94.147.x | 200 | Tag manager container (Tealium/custom), not interesting |
| familylinks.icrc.org | Azure Front Door | SKIP | SENSITIVE — missing persons data |
| casebook.icrc.org | Azure Front Door | SKIP | SENSITIVE — detainee data |
| library.icrc.org | Azure Front Door | 200 | Document library |

## Key Findings
- **F5 BIG-IP APM** protects all ext.icrc.org, test, extranet — SSO_ORIG_URI URL validation active (errorcode=22, no open redirect)
- **E-XPERT SOLUTIONS** SSO at auth.icrc.org and ap6.ext.icrc.org — same vendor both
- External users get **SFA only** (email+password, no MFA) per apm.css class naming
- api.icrc.org uses **JBoss/WildFly** backend with F5 ASM WAF; no deployed app paths discovered
- shop.icrc.org completely **offline** (TCP refused, not blocked)

## Decisions
- All pre-auth attack surfaces tested; no exploitable findings
- Credentials required to test any application functionality
- Resuming if: (a) shop.icrc.org comes back online, or (b) test account obtained for portal
