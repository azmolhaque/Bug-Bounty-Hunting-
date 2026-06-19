# Hunt Plan — wing.com
Generated: 2026-06-19T22:00:00Z

## Target Classification
- Target: `wing.com`, `opensky.wing.com`
- Program: Google & Alphabet Vulnerability Reward Program (VRP)
- Tier: TIER1 (high reward)

## Scope Gate
Per scope.yaml (acquisition domain default-deny rule):
- IN SCOPE: wing.com (apex), opensky.wing.com
- OUT OF SCOPE: all other *.wing.com subdomains (not explicitly listed)

## Target Overview
Wing is Alphabet's drone delivery subsidiary. Two distinct API surfaces:
1. **Wing Delivery Platform** — partner-only delivery ordering/tracking API (Walmart, DoorDash, Papa Johns)
2. **OpenSky** — consumer drone airspace authorization (LAANC USS, FAA-approved, CASA-approved)

## Hunt Thesis
opensky.wing.com is the highest-value target. It serves as both a consumer product AND a partner API.
The LAANC USS function means Wing integrates with FAA's FIMS and the InterUSS DSS ecosystem.
This creates potential for:
- Multi-party integration points (Wing USS <-> FAA FIMS <-> other USSs)
- Partner API authorization issues (IDOR, broken object-level authorization)
- OAuth/JWT validation issues in the airspace authorization flow

wing.com is low-value (Framer marketing site, no server backend).

## Top Attack Hypotheses
1. **opensky.wing.com IDOR**: Partner API endpoints that reference flight authorizations or
   airspace data by predictable IDs could allow partner A to read/modify partner B's data.
   Auth-bypass would be safety-critical (drone airspace = high impact narrative).
2. **opensky.wing.com OAuth flow**: Consumer auth via Google/Apple Sign-in may have
   redirect_uri validation bypass or state forgery, enabling account takeover.
3. **opensky.wing.com API auth bypass**: Unauthenticated access to health/metrics/swagger
   endpoints, or insufficient auth on LAANC status query endpoints.

## Phase Notes
- Phase 1 (Asset Discovery): COMPLETE
  - 13 total subdomains resolved; 2 in scope (wing.com, opensky.wing.com)
  - Infrastructure fully mapped via DNS (HTTP egress blocked)
  - No CNAME takeover candidates
- Phase 2 (Surface Mapping): BLOCKED (HTTP egress proxy blocks wing.com, opensky.wing.com)
  - Need HTTP access to enumerate paths, headers, tech stack
  - Recommend adding opensky.wing.com to egress allowlist to continue
- Phase 3+: Pending HTTP access
