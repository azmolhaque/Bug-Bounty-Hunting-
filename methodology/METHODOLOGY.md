# The Methodology — An Intelligent, Agentic Bug Bounty Hunting Playbook

> "The difference between a $500 report and a $15,000 report is not the bug class.
> It is the quality of the impact story and the discipline to only write reports
> that triagers immediately recognize as real."

This document is the brain of the system. It defines **how to think**, **what to
do in each phase**, **which tool to reach for**, and **how the agent reasons**
about what it finds. Read CLAUDE.md Section 3 (Hard Rejection List) before Phase 3.

---

## Guiding Philosophy

Three ideas separate elite hunters from scanner-runners:

1. **Attack surface is the product of recon × understanding.** You cannot exploit
   what you have not discovered, and you cannot prioritize what you do not
   understand. Recon maximizes *what exists*; understanding maximizes *what
   matters*.

2. **Automation is for breadth; cognition is for depth.** Let tools enumerate
   thousands of hosts and fire templated checks. Reserve reasoning for business
   logic, access control, state machines, and chaining — the classes of bugs no
   scanner will ever find.

3. **A bug is a hypothesis until it is reproduced AND impact is confirmed.**
   A scanner hit earns 5 minutes of investigation. A confirmed impact earns a
   report. Nothing in between earns a submission.

---

## Phase 0 — Scope, Authorization & Recon Planning

**Goal:** Establish an unambiguous legal boundary and a hunting thesis.

**Do:**
- Parse `config/scope.yaml`: in_scope, out_of_scope, rules, reward tiers.
- Classify target archetype — steers everything downstream:
  - *Wildcard / large-surface* (`*.example.com`) → recon-heavy, asset sprawl,
    subdomain takeovers, forgotten test environments.
  - *Single web app* → depth-heavy, logic/authz focus, IDOR.
  - *API-first program* → schema discovery, object-level authorization (BOLA).
  - *Multi-tenant SaaS* → cross-tenant isolation, IDOR, GraphQL schema.
  - *CNAPP / security product* → SSRF via integrations/webhooks, connector abuse,
    cloud metadata, cross-tenant cloud asset access.
  - *Mobile + backend* → static analysis of the app, then its API.
- Write a **hunt thesis** in `results/<target>/00-plan.md`:
  - Where do you expect the bugs? Why?
  - What is the #1 attack chain hypothesis?
  - What is the fastest path to a High/Critical finding?

**Agent reasoning:** Refuse to proceed if scope is empty/ambiguous. Write the
thesis. The thesis is a living document — update it when new assets or behaviors
reshape your expectations.

---

## Phase 1 — Asset Discovery

**Goal:** Enumerate the full footprint. Most criticals live on assets the target
forgot they had.

**Techniques & tools (ARM64-native):**
- **Passive subdomain enum:** `subfinder`, `amass enum -passive`, `github-subdomains`,
  certificate transparency (`crt.sh`), `gau`/`waybackurls` for historical hosts.
- **Active DNS resolution:** `dnsx`, `puredns`/`shuffledns` bruteforce with a
  quality wordlist, permutation (`gotator`/`altdns`).
- **ASN & cloud:** `asnmap` → CIDR ranges → reverse-DNS; S3/GCS/Azure bucket
  discovery; `trufflehog`/`gitleaks` on org repos if in scope.
- **Acquisitions:** new acquisitions are goldmines — unintegrated security posture.

**Output:** `results/<target>/01-assets/` → `subdomains.txt`, `resolved.txt`.

**Agent reasoning:** Classify every subdomain. Flags to prioritize immediately:
`dev-`, `test-`, `staging-`, `internal-`, `legacy-`, `admin-`, `api-`, `rde-`,
`grafana`, `jenkins`, `kibana`, `dashboard`. These are the 2% worth deep-diving.

**Subdomain takeover screen (do this early):**
For every subdomain with a CNAME to a cloud service:
1. Check if the CNAME target is a recognized takeover-vulnerable fingerprint
2. Confirm with `DEPLOYMENT_NOT_FOUND` / `NoSuchBucket` / etc.
3. **Immediately evaluate impact:** are cookies shared with the parent domain?
   Does the subdomain appear in any OAuth redirect_uri allowlist? Does it receive
   real user traffic? If any yes: this is a valid High finding. File it NOW.
4. If none of the above: log as Low candidate, do not write a report until a
   chain is confirmed.

---

## Phase 2 — Attack-Surface Mapping

**Goal:** Turn a list of hosts into a map of interactable attack surface.

**Techniques & tools:**
- **Probing:** `httpx` — status, title, tech (`-td`), CDN, TLS, response hash.
  Cluster by response similarity to find unique apps.
- **Content discovery:** `ffuf`/`feroxbuster` with smart wordlists. Discover admin
  panels, backups (`.bak`, `.old`, `.zip`), VCS dirs, config files, API docs
  (`/swagger`, `/openapi.json`, `/graphql`).
- **Crawling & JS analysis:** `katana`/`hakrawler`; mine JS with `linkfinder`/regex
  for hidden routes, API keys, internal hostnames. **JS is where modern apps leak
  their attack surface.**
- **Parameter discovery:** `arjun`/`x8` + historical params from `gau`.
- **API discovery:** OpenAPI/Swagger/GraphQL introspection; reconstruct the API
  model (objects, IDs, verbs) — the foundation for IDOR hunting.

**Output:** `results/<target>/02-surface/` → `live.txt`, `endpoints.txt`,
`apis.md`, `priority.md`.

**Priority.md must answer:**
- Which endpoints handle auth, tokens, money, files, user data, or admin actions?
- Which hosts are non-production (test/staging/dev)? These get first attention.
- What tech is confirmed (framework, auth system, cloud provider)? Maps to
  highest-probability bug classes.

---

## Phase 3 — Vulnerability Discovery

**Goal:** Produce a prioritized list of **confirmed candidates** — not maybes.
Kill noise fast. Pursue depth only on leads that can realistically yield Medium+.

### The Lead Qualification Gate

Before spending more than 5 minutes on any signal, answer three questions:

> **Q1 — What does the attacker concretely gain?**
> Not "information" — specifically: whose data, which account, what capability?
> If the answer is vague, drop it.

> **Q2 — Is this the intended behavior?**
> Check API docs, public changelog, program known-issues, and common sense.
> If it is plausibly intentional product design, drop it.

> **Q3 — Would the vendor fix this?**
> If the fix is trivially "add a header" and no exploit path exists, the triager
> will close as informational. Drop it.

Only leads that pass all three questions proceed to testing.

### 3a. Automated Breadth

- **`nuclei`** with curated templates (CVEs, misconfigs, exposures, default creds,
  takeovers). Tune severity and rate for the Pi.
- **Subdomain takeover:** `nuclei` takeover templates + `subjack`/`dnsx` CNAME
  checks. Apply the takeover impact screen above before logging as a finding.
- **Secrets/exposures:** `.env`, `.git`, backups, directory listings, debug
  endpoints, stack traces. Only report if the secret is active and enables access.

### 3b. Manual / Agentic Depth (where the real bounties are)

For each high-priority target, pick the **2-3 most plausible bug classes** based
on the tech and behavior — do not shotgun every class at every endpoint.

**Bug classes by probability × payout (highest first, 2024-2026 VRP data):**

| Class | Signals that raise probability | Minimum to report | 2025 payout range |
|-------|-------------------------------|-------------------|-------------------|
| **BOLA / IDOR / Broken Access** | Multi-tenant SaaS, numeric/UUID IDs in URL or GraphQL, user-scoped resources | Another user's data confirmed read/write | $7,500–$101,010 |
| **SSRF → cloud metadata** | Webhook, URL-fetch, connector, PDF renderer, "import from URL" | GCP/AWS metadata reachable OR internal service data | $6,267–$101,010 |
| **Auth / OAuth / JWT** | SSO, redirect_uri params, JWT in cookies, PKCE, OAuth apps | Account takeover or privilege escalation | $3,133–$101,010 |
| **AI Prompt Injection** | AI assistant, LLM-powered features, chat endpoints | System prompt exfil, cross-session data leak, rogue tool call | $5,000–$50,000 |
| **Injection (SQL/SSTI/cmd)** | Search, filters, templates, exports, XML | Data exfil or RCE demonstrated | $3,133–$101,010 |
| **Business Logic** | Checkout, quotas, roles, multi-step workflows | Financial loss or unauthorized capability | varies |
| **Stored XSS** | User-content rendered to other users / admin panel | Admin session/data compromise | $3,133–$31,337 |
| **Subdomain Takeover** | Dangling CNAME to cloud service | Cookie domain sharing OR OAuth redirect match | $3,133–$31,337 |
| **Secrets in JS / repos** | JS bundles, source maps, CI logs, public repos | Active credential enabling access | $1,000–$31,337 |
| **Default Creds / Exposed Admin** | Grafana, ArgoCD, Kibana, Actuator — test/staging | Authenticated access to sensitive data | $1,000–$31,337 |

**SSRF → GCP metadata — the critical constraint:**
GCP IMDS requires `Metadata-Flavor: Google` header. Classic blind SSRF alone won't
extract tokens. Confirmed bypass paths:
- **CRLF injection** into SSRF URL to smuggle the header
- **Redirect-based**: app follows 302, redirect target controls response headers
- **DNS rebinding**: domain resolves to public IP at validation, IMDS at request time
- **IPv6 encoding**: `http://[::ffff:169.254.169.254]/computeMetadata/v1/`
- **URL parser confusion**: `http://metadata.google.internal@trusted-host/`

**OAuth/OIDC attack priority order (PKCE adoption per RFC 9700 March 2025):**
1. `redirect_uri` path traversal: `/callback/../../../attacker-path`
2. Subdomain wildcard + takeover chain: `*.example.com` → dangling DNS → capture auth code
3. Prefix bypass: `https://legit.com.attacker.com` passes naive prefix check
4. Open redirect chain: `redirect_uri=https://target.com/redir?next=https://attacker.com`
5. PKCE downgrade: initiate flow without `code_challenge` — if server issues code, it's vulnerable
6. State CSRF: missing/predictable `state` → force victim to link attacker's OAuth identity

**BOLA automation (Hadrian-style):**
- Extract OpenAPI/GraphQL schema from JS or path probe
- Create two test accounts at different privilege levels
- For every endpoint: send request A's token with B's resource ID
- 200 with B's data = confirmed BOLA (Critical / High)

**For CNAPP / security product targets specifically:**
1. Webhook/connector SSRF → internal metadata → cloud creds (chain all three)
2. GraphQL cross-tenant IDOR → another tenant's cloud asset data
3. CLI binary strings → internal endpoint discovery → unauthenticated access
4. OAuth/SSO flows → redirect_uri bypass → account takeover
5. Developer RDE environments → relaxed auth → internal API exposure
6. **AI features** → prompt injection → system prompt exfil or rogue tool calls (AI VRP)

### 3c. Explicitly Skip

Do not spend time on signals that fall into CLAUDE.md Section 3 unless you have
already identified a confirmed chain link to Medium+ impact. Log a one-line note
("Dropped: CSP dev artifact — no exploitation path") and move on.

**Output:** `results/<target>/03-vulns/candidates.jsonl`
```json
{
  "id": "C001",
  "target": "webhook.us1.app.wiz.io",
  "class": "SSRF",
  "evidence": "POST /api/webhook accepts arbitrary URL; server-side request confirmed via OOB DNS",
  "confidence": "HIGH",
  "impact": "Server makes request to attacker URL; testing metadata endpoint next",
  "chain_with": null,
  "status": "PURSUING"
}
```

---

## Phase 4 — Verification, PoC & Chaining

**Goal:** Convert candidates to **proven** vulnerabilities with minimal, safe PoCs.

**Do:**
- Reproduce from a clean state (fresh session/account/IP).
- **Minimize the PoC** — the smallest request/steps that demonstrate the bug.
- **Prove impact safely** — read-only proof, OOB interaction, your own test
  account data only. No destruction, no real-user data, no mass exploitation.
- **Chain** — ask of every confirmed bug: *what does this unlock?*
  - Confirmed SSRF → probe cloud metadata → extract credentials → confirm active
  - Confirmed IDOR → demonstrate reading data that belongs to another tenant
  - Confirmed subdomain takeover → verify cookie domain sharing OR OAuth chain
- **Score impact:** CVSS 3.1 vector + business context.

**Verification standard:**
- Reproduced at least twice from a clean state.
- If you cannot reproduce it twice, it is **not verified** — downgrade to
  candidate and re-investigate.
- Every claim in the impact section must be backed by a specific artifact
  (request/response, screenshot, DNS/HTTP interaction log).

**Evidence collection (mandatory — CLAUDE.md §9 #8):**

A finding cannot be submitted without ALL of the following captured during Phase 4:

1. Researcher metadata: date, exact time (UTC), external IP (`curl ifconfig.me`), tool + version
2. Verbatim copy-pasteable reproduction command (curl, script, or numbered UI steps)
3. Verbatim HTTP response body (pasted, not described — the actual bytes)
4. HTTP status code + response size from the actual test
5. Before/after differential (expected secure behavior vs. observed insecure behavior)
6. At least one screenshot or terminal capture showing the finding
7. SHA256 hash of key evidence files for integrity

For repeated-descriptor / deprecated-endpoint bugs: confirm the vulnerability is in
the *logic* (access control, configuration), not just the API path. A namespace change
(`ui-object-info-api/` → `aura://RecordUiController/`) that still succeeds proves the
root cause was never patched — document the before/after descriptor comparison explicitly.

See `results/<target>/REPORTING-STANDARDS.md` for the per-program evidence template.

**Output:** `results/<target>/04-verified/` → one folder per confirmed bug with
PoC, sanitized evidence, CVSS vector, impact note, and evidence checklist (all 7 items).

---

## Phase 5 — Triage, Severity & Pre-Submission Gate

**Goal:** Decide what is worth reporting. Apply the submission gate ruthlessly.

### Severity Scoring

CVSS 3.1 base score + business context adjustment:

| Score | Label | Report? |
|-------|-------|---------|
| 9.0-10.0 | Critical | Yes — immediately |
| 7.0-8.9 | High | Yes — immediately |
| 4.0-6.9 | Medium | Yes — if impact story is strong |
| 2.0-3.9 | Low | Only if confirmed chain to Medium+ |
| 0.1-1.9 | Informational | **Never standalone** |

### Pre-Submission Gate (all must pass)

Before writing the report:

- [ ] Attacker gain is **concrete and specific** (not "could potentially...")
- [ ] Behavior is **not documented as intended** (checked docs + changelog)
- [ ] Vendor would **actually fix this** (requires a code/config change)
- [ ] Not in CLAUDE.md Section 3 Hard Rejection List (or fully chained past it)
- [ ] CVSS ≥ 4.0 OR confirmed chain to CVSS ≥ 4.0
- [ ] Not a known duplicate (checked program known-issues + own results/)
- [ ] Reproducible from clean state, PoC exists
- [ ] Google VRP tier is confirmed for the target host

If any box is unchecked: **do not write the report**. Either fix the gap or
drop the finding.

### Deduplication

1. Check the program's known-issues / Hall of Fame for the same class + target.
2. Check your own `results/<target>/findings/` for overlapping class/endpoint.
3. Search public CVEs and advisories for the same root cause.
4. Search HackerOne/Bugcrowd disclosed reports for this target.

**Speed rule:** If your finding passes all gates, submit **today**. In competitive
programs, first valid report wins. Do not wait for a "better" PoC if the current
one clearly demonstrates impact.

---

## Phase 6 — Reporting

**Goal:** A report that a triager rewards in under 5 minutes.

**Evidence gate (run before writing the report):**

Verify every item in the Phase 4 evidence checklist is captured. A report without
verbatim curl output, a reproduction command a triager can copy-paste, and at least
one terminal screenshot will be flagged as AI-generated prose and closed as Spam.
This is not optional — it is the minimum bar since the M018 Spam closure (2026-06-23).

**Anatomy of a winning report:**

1. **Title:** `[Class] [Impact] via [Location]` — one line, specific.
   - Good: `Cross-Tenant Cloud Asset Access via Unauthenticated GraphQL projects() Query`
   - Bad: `Security Issue in API`

2. **Summary:** 2-3 sentences. What, where, why it matters.

3. **Severity:** CVSS 3.1 vector + string + business impact sentence.

4. **Steps to reproduce:** Numbered, copy-pasteable, from a clean state.
   Every step must be executable by someone who has never seen the app.

5. **Proof:** Minimal request/response or screenshot. Sanitize any real user PII.

6. **Impact:** Concrete attacker capability. "An attacker can read any customer's
   cloud asset inventory" is concrete. "An attacker could potentially access
   sensitive information" is not.

7. **Remediation:** Specific fix tied to root cause. One sentence minimum.

8. **References:** CWE, OWASP, relevant CVEs.

**Report anti-patterns that get downgraded:**
- Overstating severity ("This is Critical because it *could* be chained with...")
  when the chain is unconfirmed.
- Vague impact ("sensitive information could be accessed").
- Missing reproduction steps or evidence.
- Reporting a behavior the vendor documented as intentional.
- Attaching overly large files, unrelated screenshots, or raw tool output.

---

## The Intelligence Loop

```
observe → hypothesize → qualify (kill/pursue) → test → verify → chain → report
              ↑                                                          |
              └──────────── re-plan if new surface discovered ──────────┘
```

After each phase, re-plan: new assets reshape the surface; a leaked hostname
reopens recon; a confirmed IDOR suggests testing the same pattern across every
object type. Maintain `results/<target>/HUNT-LOG.md` for every decision.

---

## Automated Workflow — `deep-recon-orchestrator.py v4`

The script implements this methodology end-to-end. Claude is called at two points:

**1. Per-finding triage** (immediate — when score ≥ 3 detected during Phase 3):
- Input: finding type + evidence + paths summary
- Output: PURSUE/DROP decision + exact curl verify command
- Candidate written to `candidates.jsonl` immediately on PURSUE/REPORT_NOW

**2. Cluster synthesis** (after all hosts probed):
- Input: all live host summaries ranked by score
- Output: ranked finding list + top_action + dead_ends
- REPORT_NOW findings get auto-generated triager-grade report drafts

**Output files per cluster:**
```
results/<cluster>/
  HUNT-LOG.md            — timestamped session decisions
  MANUAL-VERIFY.md       — step-by-step curl commands for every PURSUE lead
  02-surface/
    deep-recon.md        — full recon report with Claude analysis
    claude-analysis.json — raw Claude cluster synthesis JSON
  03-candidates/
    candidates.jsonl     — all PURSUE/REPORT_NOW findings (gitignored)
    recon-raw.json       — raw per-host probe data (gitignored)
  04-verified/
    DRAFT-*.md           — auto-generated report drafts for REPORT_NOW
```

**Attack modules map to methodology phases:**

| Module | Phase | Bug class | Min to pursue |
|--------|-------|-----------|---------------|
| argocd | P3 | Default creds / exposed admin | Any 200 on unauth API endpoint |
| firebase | P3 | Active credential | `valid: true` from identitytoolkit |
| graphql | P3 | BOLA/IDOR | Introspection open + mutations found |
| cors | P3 | Auth bypass / data theft | `credentials: true` reflected |
| jwt | P3 | Auth bypass | Weak secret confirmed OR alg:none |
| takeover | P3 | Subdomain takeover | Fingerprint hit + cookie/OAuth check |
| host_header | P3 | Cache poisoning | Evil host reflected in response |
| ssrf_params | P3 | SSRF | URL-accepting param found → OOB test |
| oauth | P3 | Account takeover | `redirect_uri` bypass → evil.com in Location |
| method_ovr | P3 | Auth bypass | 200/204 on override vs base |
| openapi | P3 | BOLA/IDOR | 200 on documented endpoint + ID probe |
| mass_assign | P3 | Privilege escalation | Server accepts role/admin fields |
| path_trav | P3 | LFI / file read | `root:x:0:0` in response |
| gcs_bucket | P3 | Exposed storage | List or write access confirmed |
| ai_injection | P3 | AI VRP | System prompt or cross-session data in response |

---

## Bug-Class Quick Reference (payout-weighted)

| Class | Where to look | Minimum to report |
|-------|---------------|-------------------|
| IDOR / BOLA / broken access | Object IDs, multi-tenant APIs, GraphQL | Another user's data confirmed read/write |
| SSRF | Webhooks, connectors, URL fetch, renderers | Metadata or internal service reached |
| Auth / OAuth / JWT | Login, reset, SSO, token endpoints | Account takeover or privilege escalation |
| Injection (SQL/SSTI/cmd) | Search, filters, templates, exports | Data exfil or RCE demonstrated |
| Business logic | Checkout, transfer, quota, workflow | Financial loss or unauth capability |
| Stored XSS | User content → other users / admin | Session compromise in sensitive context |
| Subdomain takeover | Dangling CNAME | Shared cookie domain OR OAuth redirect confirmed |
| Secrets exposure | JS, git, CI, backups | Active credential enabling access |
| Default creds / exposed admin | Grafana, Jenkins, staging dashboards | Authenticated access to sensitive data |
| Path traversal / file read | Upload, download, archive | Sensitive file confirmed read |

---

## Google VRP — Specific Known Rejection Patterns

These are **consistently rejected or downgraded** by Google VRP triagers:

| Finding | Typical disposition |
|---------|---------------------|
| Missing HSTS / X-Frame-Options | Informational — won't fix |
| CSP weakness with no exploit path | Informational — won't fix |
| SPF/DMARC missing on subdomain | Informational |
| TLS 1.0/1.1 support | Informational unless downgrade proven |
| CORS on endpoint with no sensitive data | Informational |
| Self-XSS | N/A — not a vulnerability |
| CSRF on logout | Won't fix |
| Open redirect to owned domain | Won't fix |
| Rate limit absent on non-sensitive endpoint | Won't fix |
| Stack trace / error message | Informational unless exploitable data |
| Subdomain takeover on dead host (no cookies, no OAuth) | Low / won't fix |
| Clickjacking on non-sensitive page | Won't fix |
| Password complexity policy | By design |
| No 2FA requirement | By design |
| Punycode / homograph phishing | By design |
| HTTP methods allowed (OPTIONS, TRACE) | By design |
| Publicly readable Swagger with no secrets | By design |

**What Google VRP consistently pays for:**
- Cross-tenant data access in acquired products (IDOR/BOLA)
- SSRF reaching cloud metadata or internal services
- Authentication bypass / account takeover
- RCE or command injection
- SQL injection with data exfil
- OAuth flow vulnerabilities leading to token theft
- Stored XSS reaching admin/authenticated-privileged context
- Subdomain takeover with confirmed cookie sharing or OAuth redirect
- Active credential leaks (API keys, JWT secrets, cloud access keys)
- Broken authorization on sensitive admin/billing/security functions

---

## Field Operations — Hard-Won Lessons (campaign 2026-06)

These are codified from real engagements. They override optimism. Read before
every Google-VRP-style session.

### FO-1. Target Expected-Value ranking (pick targets in this order)
Mature, well-resourced programs harden their *reachable* surface; easy bugs are
long gone. Empirically this campaign, every mature Google consumer/acquisition
surface came back hardened, intended, migrated, or wound-down; the only confirmed
valid bug came from a **soft VDP** (UNICEF). Therefore rank candidate targets:

1. **Soft VDP / smaller program / NGO / gov** — highest conversion for solo
   remote testing. Default here unless a fresh angle exists elsewhere.
2. **Recently-acquired or recently-shipped product/feature** — fresh, less-reviewed
   code. Look for 2024–2026 launches, new subdomains, new API versions.
3. **Self-service multi-tenant SaaS with email/Google signup** — IDOR/BOLA surface
   reachable with two test accounts + curl.
4. **Mature consumer/core product unauth surface** — LOWEST EV. Only touch with a
   specific, fresh hypothesis; do not breadth-scan it expecting easy wins.

### FO-2. The catch-all 200 control (kill false positives instantly)
Before reporting ANY "exposure" (`/.git/config`, `/.env`, `/server-status`, an
admin path) returning 200: **request a guaranteed-bogus path** (e.g.
`/zzz-<rand>-doesnotexist`) with the same method. If the bogus path ALSO returns
200 with the same/similar body, the host is an **IAP login page, SPA router, or
LB catch-all** — every 200 is the same page, NOT a real file. Confirmed false-
positive sources this campaign: `internal.photomath.com` (Google IAP login),
`www.elastifile.com` (Cloud marketing SPA), `forum.waze.com` (Discourse/GFE
catch-all). Only a body that is *actually* the artifact (`[core]` for git,
`KEY=VALUE` for .env) counts.

### FO-3. Negative-test validity gate (never record a false "secure")
Before concluding "no IDOR / properly authorized," PROVE your own auth worked:
the **baseline self-read must succeed** (e.g. `A reads A's own object = 200`). A
`401/403` on a cross-account request means NOTHING if your own baseline is also
`401` — that's a rejected/expired token, not enforced authorization. This nearly
produced a false "Nest is secure" verdict until the baseline-200 check exposed a
malformed `Authorization` header. Always: baseline-200 first, THEN interpret the
cross-account result.

### FO-4. Non-root mobile interception playbook (Android + Termux, no PC)
- **Websites are interceptable; pinned native apps are not (on ARM/Termux).**
- WEB app: `pip install mitmproxy` (use `python-cryptography` prebuilt) →
  `mitmdump -s addon.py -p 8080` → Android Wi-Fi proxy `127.0.0.1:8080` (DHCP, not
  Static; clear the "Bypass proxy for" field or Save stays greyed; saved networks
  require re-entering the Wi-Fi password to enable Save) → install CA via
  `http://mitm.it` (Settings → Encryption & credentials → Install a CA cert).
  Chrome trusts user CAs for *browsing*, so this decrypts website API calls.
- NATIVE app with cert pinning: **`apk-mitm` is ARM-incompatible and Termux has no
  `apktool` package — on-device patching is a DEAD END.** Needs a PC (run apk-mitm
  on x64, copy patched APK back) or a rooted device. Do not burn time on it.
- Migrated APIs (e.g. `api.fitbit.com`) now sit behind Google's gateway and need
  restricted-scope Google OAuth — effectively unreachable for a quick hunt.

### FO-5. Token-capture → curl-replay (authenticated IDOR without a proxy per-request)
1. mitmdump addon prints the live `Authorization` header + object IDs as you browse.
2. Save the token to a FILE (`cat > tok.txt <<'EOF' … EOF`) — never inline a
   1000+ char token in a shell var (paste mangling, `read -p` unsupported on
   Termux). Auto-prepend the scheme (`Basic `/`Bearer `) in the script.
3. Replay with `curl -H "Authorization: <scheme> <token>"`, varying the object ID.
4. Tokens are short-lived (~50 min) — capture fresh right before the test; if the
   baseline self-read 401s, the token expired, recapture.

### FO-6. Live-app vs migrated-husk fingerprint (do this first, save hours)
Many acquisitions are dead shells. Flag a husk when the homepage: redirects to
`*.google.com` / `store.google.com`; says "use the <X> app" with App/Play badges;
is a Google Sites page with a closed Google Form; returns the same catch-all 200
everywhere; or 404/500/502 on the app subdomain. A LIVE target has a real SPA
build stamp (e.g. Nest `build 5.87.0-20260429`), a real auth API returning clean
`401 {"error":...}` (not HTML) on protected endpoints, and distinct responses per
path. Only invest authenticated effort in confirmed-live targets.

### FO-7. Honest-negative discipline
Record clean negatives in `results/<target>/` with the evidence (codes, baseline
proof). A rigorous "no bug here, and here's why" is professional output and stops
the next session re-walking dead ground. Never upgrade a negative into a
speculative report. Zero rejected reports beats one rejected report.

---

## Submission Discipline — Report-Quality Post-Mortem (the rejection lessons)

Codified after a run of real closes: 1 Spam ("AI-generated content"), 2 N/A
("names not contents" / "insufficient impact"), 2 WAI ("intended behavior"), 1
Won't-Fix. Every one shared the same root causes. These rules are non-negotiable
before ANY submission. Overclaiming and low-boundary reports don't just get
rejected — Spam/N/A closes **damage your platform reputation/signal** and make
every future report read skeptically.

### FO-8. The Impact Ledger — headline severity MUST equal PROVEN impact
Before writing a title, fill this in with ONLY what you demonstrated:
- **What sensitive data did I actually read?** (bytes, not field names, not a hash)
- **What access/credential/token did I actually obtain and could use?**
- **Whose data was it?** (another user's = boundary crossed; my own / my own OOB
  server / metadata = NOT crossed)
The title and CVSS come from this ledger, never from what *would* be possible.
Killed us: an "Authentication Bypass exposing financial data" title backed by a
PHP crash → closed **Spam**. If your evidence is a weird error, the finding is
"verbose error / anomaly", not "auth bypass". **Claim exactly what you proved.**

### FO-9. Boundary-Cross Proof Gate — precondition ≠ finding
A misconfiguration, a reachable endpoint, a dangling CNAME, an SSRF that hits your
own server, IMDS *root* returning non-sensitive bytes, or a schema/field-name dump
is a **precondition**, not a vulnerability. You MUST demonstrate the boundary
cross with real evidence:
- IDOR/BOLA → the actual record of ANOTHER account (redacted), with baseline-200
  proving your auth worked (FO-3).
- SSRF → the actual sensitive internal response/credential read (not "reachable").
- Subdomain takeover → you CLAIMED it and served a benign canary you screenshotted
  (`DEPLOYMENT_NOT_FOUND` alone does NOT prove claimability — modern Vercel/Netlify
  block claiming domains still bound to another team).
- Auth bypass → the actual protected data returned by the unauthenticated request
  (a *different error* only proves a different code path, not a bypass).
Killed us: Salesforce "873 fields" (names, `getItems`/`searchRecords` returned
empty = no records) → N/A; Cameyo `/about` diagnostics → Won't-Fix; VT SSRF root
(no creds) → capped Low. If the boundary isn't crossed, **do not submit.**

### FO-10. Plain human voice — kill the AI-report tells
Triagers now auto-flag AI-generated reports as Spam. Remove every tell:
- **No** "VERDICT block", "differential table", "smoking gun", "Executive Summary".
- **No** CVSS self-scoring argued up to High/Critical — state facts; let the
  triager assign severity.
- **No** speculative escalation chains ("one header from Critical", "if the handler
  passes to executeScript", "would expose data if the bug were fixed", "systemic",
  "race-condition oracle").
- **No** wall-of-tables/emoji/bold-everything formatting.
Write it as a human: "I sent this request with no cookie. I got this response.
Here is the actual data it exposed. Here is why that's a problem." Short, factual,
first-person, real terminal output. AI may assist drafting; you must manually
verify every claim and strip the tells before sending.

**AMENDMENT, 2026-08-27 — this rule was written too absolutely.**
The AppSheet systemic-SSRF report (525815004 / 525815219) opens with a literal
**"EXECUTIVE SUMMARY"**, contains a **differential table** of prior fixes, and uses the word
**"systemic"** throughout — every tell this rule bans. It was raised to **P2**.

So the causal claim in the original rule is wrong. Formatting is not what gets reports
auto-closed as Spam. **What gets closed is unverified claims dressed in confident
formatting** — a speculative chain, a self-argued CVSS, or an escalation that was never
demonstrated, presented as though it had been. The AppSheet report survives its own
formatting because every element under the headings is a *thing that was actually tested*:
three named surfaces, four network clients, real OOB hits, real GCP-origin IPs, dated runs.

Restated correctly:

> **Every claim must be verified, and the formatting must not imply more than was verified.**
> Structure is fine — a table of what you tested and what happened is genuinely useful to a
> triager. The tell that kills a report is the gap between what the presentation asserts and
> what the evidence shows.

M018 (closed as Spam) failed the *evidence* test, not the *formatting* test. Do not spend
effort stripping headings; spend it deleting sentences you cannot prove.

### FO-11. The Submit/Drop gate (run before every submission)
Answer in ONE sentence: **"What does an attacker concretely GET?"**
- Answer is *another user's data / a usable credential / code execution / a proven
  auth bypass / cross-tenant access* → PROCEED (with FO-8/9/10 satisfied).
- Answer is *a hostname / version / connection count / trace ID / my own OOB
  request / field names / a precondition / "it would be possible if…"* → **DROP.
  Do not submit.** These are informational and burn your signal.
One verified High beats ten polished informational rejections — and beats the
reputation damage they cause.

### FO-12. Don't argue rejections; run ONE decisive test instead
N/A / WAI / Spam close: do NOT re-argue with the same evidence (it cements the
label and, on a Spam close, worsens standing). Either accept it, OR run the single
decisive NEW test that would cross the boundary (FO-9) — and only re-engage if that
test produces real, new, boundary-crossing proof. Never "schedule a live demo" or
append more of the same. A good rebuttal (rare) addresses the triager's exact
stated standard with NEW evidence and honest limits — see the VT link-local
clarification that earned a reopen; contrast the Cameyo "race-condition oracle"
appeal that stayed rejected.

### FO-13. Severity track ≠ reward track — pre-set expectations on hygiene finds
A "Fixed" from the product team is an **engineering** signal ("worth cleaning up"),
NOT a **reward** signal ("exposed real risk in a system we operate"). The two panels
answer different questions and routinely disagree. Before writing ANY report whose
root cause is *infrastructure hygiene* — dangling DNS, a stale/sandbox endpoint, an
orphaned host that merely resolves through the vendor's edge — set the honest
expectation up front: this class is frequently **valid-but-credit-only**, even when
it superficially reads as "unauthenticated admin access on a Tier-1 asset."
- **Tier describes a domain's *potential* sensitivity, not a finding's severity.**
  The data actually at risk is what counts. An admin panel over an empty sandbox
  (placeholder text, `/api/roles` → `[]`, no real records) is a hygiene problem,
  not a data breach — say so yourself before the panel does.
- **Two-layer reasoning still matters** even on hygiene finds: check whether the
  backend independently enforces authz (not just the login form). It makes the
  finding complete regardless of the reward outcome.
- **Appeals need a NEW concrete fact, not louder adjectives** (ties to FO-12).
  Restating "brand/phishing potential" in stronger words is speculative secondary
  impact; it won't (and shouldn't) move a credit-only decision.
Reference case: `rip.photomath.net` exposed IAM frontend (Google VRP issue
**509594209**, reported 2026-05-05) — default creds + any-password login (CWE-287)
+ unauth `GET /api/roles` → `200 []`, triaged **P2/S2**, accepted in ~1 day, marked
**Fixed** ~9 days later (endpoint decommissioned → NXDOMAIN), reward panel
**Honorable Mention / credit-only** (#9), appeal (#10) sent back (#11) and **upheld**
(#12, 2026-06-02). Panel's verbatim rationale: *"not located within a Google
application, but the result of stale DNS records… did not affect a system under our
direct operational control."* Correctly not rewarded: non-prod sandbox, root cause =
stale DNS not an app vuln, and the appeal's strongest new argument was a **speculative
brand/phishing vector** (#10 pt 2) — adjectives, not a new concrete fact (FO-12).
Calibrating that gap honestly *before* submitting is the skill — and writing it up
honestly afterward (see the published `security-writeups` post) builds more signal
than a padded "critical" would have.


### FO-14. Test-target OWNERSHIP is a Phase 0 gate — scope ≠ tenancy
An in-scope *product* is not the same as an in-scope *tenant*. Before demonstrating anything
against a hosted multi-tenant service (Looker Cloud, Wiz, any per-customer SaaS instance),
**prove the instance is ours** — a provisioning email, an admin login, an entry in our own
cloud console. If none of those exist, it is somebody's production tenant and their data is
not ours to touch, even when the *vulnerability* is genuinely in the vendor's product.

Warning signs that a "target" is actually a stranger's tenant:
- The repro step says **"locate an instance"** rather than "the instance I provisioned"
- The error page addresses you as a non-admin (*"contact your administrator"*)
- No provisioning record anywhere in your mail or console
- The host is still live long after any trial you might have created would have expired
- Per-customer dedicated infrastructure (dedicated LB, customer-specific region)

**Reference case — Looker XFF allowlist bypass (509911655, 2026-05):** a genuine ingress flaw
(client-supplied `X-Forwarded-For` trusted for access-control decisions on Google-operated
`cloud.looker.com`) was demonstrated against `09a2ceda-…cloud.looker.com`, a tenant that was
**never provisioned by us**. The PoC obtained that customer's session cookies and ~1 MB of
their `swagger.json`. Right finding, wrong target. Correct response: **stop all traffic,
disclose the scope error voluntarily in the report thread, offer to re-validate against a
vendor-designated instance, expect the report to close.** Voluntary disclosure of a scope
error is treated very differently from one a triager discovers.

The cost of this gate is one minute. The cost of skipping it is unauthorized access to a real
company's production environment.


### FO-15. Systemic framing can rescue a class that is WAI in isolation
A behaviour that a triager will close as **intended** when shown once can become a genuine
finding when shown as a **pattern of missing control across independent surfaces** — provided
the pattern is demonstrated, not asserted.

**The AppSheet case (525815004 / 525815219, P2, 2026-08).** A connector that fetches a
user-supplied URL and forwards user-supplied credentials to it is *intended behaviour*. It is
on this file's own Hard Rejection List, and a prior AppSheet SSRF report closed exactly that
way. The same underlying behaviour, reframed, drew **P2**:

| Weak framing (closes as WAI) | Systemic framing (drew P2) |
|---|---|
| "This connector fetches a URL I supplied" | "The connector *framework* has **no centralized egress filter**" |
| One surface | **Three independent surfaces**, four distinct network clients, HTTP **and** raw TCP |
| No history | **Two prior point-fixes** (2021 webhook, ~$6,267; ~2022–24 Apigee) that never generalised |
| Implicit ask | "Every unreviewed connector is a new instance of the same root cause" |

The argument stops being *"this feature behaved as designed"* and becomes *"you have fixed
this three times without building the shared control, so the next one is open by default."*
That is a claim about architecture, and it is much harder to close as intended.

**Requirements — all four, or it is padding:**
1. **Multiple surfaces actually tested.** Named, dated, with evidence per surface. Not "and
   presumably others".
2. **Prior fixes documented.** Public advisories, changelogs, previous VRP IDs. The history is
   what proves the point-fix pattern.
3. **A distinct root cause named** — the *missing shared control*, not the individual symptom.
4. **Each surface independently reproducible.** If one is shaky the whole pattern argument
   collapses with it.

**The limit — and this matters more than the technique.** Systemic framing defeats the
**"intended behaviour"** objection. It does **not** defeat the **impact** bar (§2, FO-8/9/11).
The AppSheet report reached P2 while its requests still only arrived at *our own* server, with
no internal data read — so the fix is likely and the reward is genuinely uncertain. Two
different questions:

- *"Will they fix it?"* — systemic framing moves this a great deal.
- *"What did the attacker actually GET?"* — systemic framing moves this **not at all**.

Use it to rescue a real missing control from a lazy WAI close. Never use it to inflate a
finding with no demonstrated impact into one — that is the padding FO-10 exists to prevent.
