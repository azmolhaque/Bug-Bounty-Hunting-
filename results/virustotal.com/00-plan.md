# Hunt Plan — VirusTotal (virustotal.com)
**Target:** virustotal.com / www.virustotal.com  
**Tier:** TIER1 (Google VRP — up to $31,337 for High)  
**Also in scope:** virustotal-plugins.com, gtidocs.virustotal.com  
**Date started:** 2026-06-13  

## Archetype Classification
Multi-tenant threat intelligence SaaS with public REST API (v3). Primary users are
security researchers, enterprise SOC teams, and antivirus vendors. Architecture:
- Public file/URL/domain/IP analysis (community tier, free API)
- Premium intelligence: saved queries, hunting rules (YARA), retrohunt, threat graphs
- GTI (Google Threat Intelligence): enterprise integration, private scanning
- Plugins ecosystem (virustotal-plugins.com): third-party integrations

## Hunt Thesis
VirusTotal's API v3 exposes multiple object types (files, urls, analyses, graphs,
rulesets, retrohunt jobs, feeds) across community and enterprise tiers. The most
plausible high-value bugs are:

1. **SSRF via URL scanning** — VT fetches submitted URLs server-side from GCP VMs.
   Submitting redirect chains or alternate schemes targeting GCP metadata
   (`metadata.google.internal`) could yield service account tokens. This is CRITICAL.

2. **IDOR across analysis objects** — Analysis IDs encode `sha256:timestamp` in base64.
   Private/premium analyses might be accessible to community users by reconstructing
   or enumerating the analysis ID. Cross-tenant intel leak.

3. **Premium endpoint access with free API key** — Intelligence search, retrohunt,
   hunting rulesets, and feeds are "enterprise only." API might return different error
   codes for existing vs non-existing enterprise resources, leaking information. Or
   endpoints might accept free keys if the right parameters are used.

4. **File relationship traversal on private submissions** — Even "private" files have a
   sha256 hash. `/api/v3/files/{sha256}/relationships/{relationship}` might return
   relationship data (contacted IPs, embedded URLs, registry keys) from private
   submissions without checking privacy flag.

5. **CORS misconfiguration** — If the API allows arbitrary origins on authenticated
   endpoints, attacker can steal API key responses via XSS elsewhere.

6. **gtidocs.virustotal.com** — New GTI docs subdomain may have different auth model
   or expose internal API endpoints not visible on main site.

## Priority Attack Chains
| # | Chain | Impact | Confidence |
|---|-------|--------|------------|
| H1 | URL scan → redirect → GCP IMDS → service account token | CRITICAL | Medium |
| H2 | Analysis ID prediction → private analysis access | HIGH | Medium |
| H3 | File relationship traversal bypasses privacy flag | MEDIUM | Medium |
| H4 | Free key accesses premium endpoint (info disclosure) | MEDIUM | Medium |
| H5 | CORS * on authenticated API → key exfil via XSS | MEDIUM | Low |

## Commands
- Phase 1+2: `bash scripts/vt-recon.sh 2>&1 | tee ~/vt-recon-output.txt`
- Phase 3: `VT_API_KEY=<key> bash scripts/vt-attack.sh 2>&1 | tee ~/vt-attack-output.txt`
- API key: get free key at https://www.virustotal.com/gui/sign-in → API Key tab
