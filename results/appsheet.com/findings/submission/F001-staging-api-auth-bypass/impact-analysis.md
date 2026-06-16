## Confirmed Impact (demonstrated)
- The `ApplicationAccessKey` authentication control is fully bypassed on
  `api.gcp-staging.appsheet.com`.
- Every tested AppSheet REST v2 endpoint is reachable **unauthenticated** from the
  public internet (external non-Google IP confirmed).
- No network-layer protection (VPN, IP allowlist, IAP, VPC-SC) is present.

No application UUID was guessed, brute-forced, or used, and no data was read or
modified — this report establishes the authentication control failure only.

## Full Impact on Supplying a Valid Staging App UUID
A valid staging application UUID is the only remaining prerequisite for data access; the
authentication control itself is already defeated. With one:
- **Confidentiality:** unauthenticated read of all rows/columns of every table in the
  target staging app (`POST .../tables/{TABLE}/Action` with `{"Action":"Find"}`).
- **Integrity:** unauthenticated write/edit/delete of that app's table data
  (`{"Action":"Edit"}` / `{"Action":"Delete"}`).
- Staging is used by AppSheet/Google engineers for pre-production testing; apps there
  may contain production-clone test data and data-connector configurations that can hold
  third-party or internal credentials/tokens.

## Severity (CVSS 3.1)
- **Confirmed state (auth bypass, no data accessed):**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 (Medium)**
- **With a valid staging UUID (full read/write):**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 (Critical)**

| Metric | Confirmed | Rationale |
|---|---|---|
| Attack Vector | Network | Public internet, any IP |
| Attack Complexity | Low | Single unauthenticated HTTP request |
| Privileges Required | None | No account, no key |
| User Interaction | None | Fully automated |
| Scope | Unchanged | Impact within the AppSheet API authorization boundary |
| Confidentiality / Integrity | Low / Low (→ High / High with valid UUID) | Auth bypass confirmed; data access gated only by knowing a UUID |

## Why This Matters for Google VRP
A TIER0 Google asset (`*.appsheet.com`) exposes a production-adjacent API with the
production authentication control entirely absent and no network isolation. The barrier
to mass data read/write is reduced from "valid credentials" to "knowing an app UUID,"
which can leak from repositories, docs, or be enumerated if IDs are guessable.
