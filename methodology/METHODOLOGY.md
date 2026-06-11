# The Methodology — An Intelligent, Agentic Bug Bounty Hunting Playbook

> "Amateurs scan. Professionals map. Elites *understand* the target, then strike
> where understanding reveals weakness." 

This document is the brain of the system. It defines **how to think**, **what to
do in each phase**, **which tool to reach for**, and **how the agent reasons**
about what it finds. It is written to be executed by an autonomous Claude Code
agent on a Raspberry Pi 5, but it reads as a human playbook too.

---

## Guiding Philosophy

Three ideas separate elite hunters from scanner-runners:

1. **Attack surface is the product of recon × understanding.** You cannot exploit
   what you have not discovered, and you cannot prioritize what you do not
   understand. Recon maximizes *what exists*; understanding maximizes *what
   matters*.
2. **Automation is for breadth; cognition is for depth.** Let tools enumerate
   thousands of hosts and fire templated checks. Reserve human/agent reasoning
   for business logic, access control, state machines, and **chaining** — the
   classes of bugs no scanner will ever find.
3. **A bug is a hypothesis until it is reproduced.** Treat every signal as a lead
   to be verified, minimized, and impact-proven before it earns the word "bug."

The agent's job is to run breadth automatically, then apply cognition to the
output: *which 2% of this surface is worth a human-grade look, and why?*

---

## Phase 0 — Scope, Authorization & Recon Planning

**Goal:** Establish an unambiguous legal boundary and a hunting plan.

**Do:**
- Parse the program brief into `config/scope.yaml`:
  - `in_scope`: domains, wildcards, IP ranges, apps, mobile, API hosts.
  - `out_of_scope`: explicitly excluded assets and **forbidden test types**.
  - `rules`: rate limits, required headers, allowed payload classes, disclosure.
- Classify the target archetype — this steers everything downstream:
  - *Wildcard / large-surface* (`*.example.com`) → recon-heavy, asset sprawl.
  - *Single web app* → depth-heavy, logic/authz focus.
  - *API program* → schema discovery, object-level authorization (BOLA/IDOR).
  - *Mobile + backend* → static analysis of the app, then its API.
- Write a one-paragraph **hunt thesis**: where do you *expect* the bugs to be,
  and why? (e.g. "Recent acquisition → integration seams → SSO/authz gaps.")

**Agent reasoning:** Refuse to proceed if scope is empty/ambiguous. Pick the
archetype and write the thesis to `results/<target>/00-plan.md`.

---

## Phase 1 — Asset Discovery (find everything they own)

**Goal:** Enumerate the full footprint. Most criticals live on assets the target
forgot they had.

**Techniques & tools (all ARM64-native):**
- **Seed expansion:** root domains → ASN lookup (`amass intel`, `asnmap`) → CIDR
  ranges → reverse-DNS.
- **Subdomain enumeration (passive):** `subfinder`, `amass enum -passive`,
  `github-subdomains`, certificate transparency (`crt.sh`), `gau`/`waybackurls`
  for historical hosts.
- **Subdomain enumeration (active):** `dnsx` resolution, `puredns`/`shuffledns`
  bruteforce with a quality wordlist, permutation (`gotator`/`altdns`).
- **Cloud & SaaS:** S3/GCS/Azure bucket discovery, exposed dashboards, leaked
  credentials in public repos (`trufflehog`, `gitleaks` on org repos *if in
  scope*).
- **Acquisitions & related orgs:** map corporate structure; new acquisitions are
  goldmines (unintegrated security posture).

**Output:** `results/<target>/01-assets/` → `subdomains.txt`, `resolved.txt`,
`cidrs.txt`, `cloud.txt`.

**Agent reasoning:** Dedup, resolve, and **classify**. Flag the *anomalous*:
`dev-`, `staging-`, `internal-`, `legacy-`, `old-`, `test-`, `vpn-`, `admin-`,
`jenkins-`, `git-`, `api-` prefixes. These get priority in Phase 3.

---

## Phase 2 — Attack-Surface Mapping (find every input & endpoint)

**Goal:** Turn a list of hosts into a map of *interactable surface*: live
services, technologies, endpoints, parameters, and APIs.

**Techniques & tools:**
- **Probing:** `httpx` — status, title, tech (`-td`), CDN, TLS, response hash.
  Cluster by response similarity to find the unique apps among thousands of hosts.
- **Port & service scan:** `naabu` (top ports, then full on interesting hosts) →
  service ID. Be rate-aware on the Pi.
- **Tech fingerprinting:** `httpx -td` + Wappalyzer signatures → map to known CVEs
  and default-cred opportunities.
- **Content discovery:** `ffuf`/`feroxbuster` with smart wordlists (raft, target-
  specific). Discover admin panels, backups (`.bak`, `.old`, `.zip`), VCS dirs
  (`.git`, `.svn`), config files, API docs (`/swagger`, `/openapi.json`,
  `/graphql`).
- **Crawling & JS analysis:** `katana`/`hakrawler` for endpoints; extract JS,
  then mine it with `linkfinder`/regex for hidden routes, API keys, internal
  hostnames, and feature flags. **JS is where modern apps leak their attack
  surface.**
- **Parameter discovery:** `arjun`/`x8` + historical params from `gau`. Build the
  parameter inventory that fuzzing will target.
- **API discovery:** OpenAPI/Swagger/GraphQL introspection; reconstruct the API
  model (objects, IDs, verbs) — the foundation for IDOR/BOLA hunting.

**Output:** `results/<target>/02-surface/` → `live.txt`, `tech.json`,
`endpoints.txt`, `params.json`, `js-findings.md`, `apis.md`.

**Agent reasoning:** This is the first big cognition step. From the map, produce a
**ranked target list** (`02-surface/priority.md`) answering: *which endpoints
handle auth, money, files, user data, or admin functions?* Those rank highest.

---

## Phase 3 — Vulnerability Discovery (generate candidate bugs)

**Goal:** Produce a prioritized list of *candidate* vulnerabilities. Breadth via
automation; depth via reasoning.

### 3a. Automated breadth
- **`nuclei`** with curated templates (CVEs, misconfigs, exposures, default
  creds, takeovers). Tune severity and rate for the Pi. This catches the
  low-hanging and the known-CVE fruit fast.
- **Subdomain takeover:** `nuclei` takeover templates + `subjack`/`dnsx` CNAME
  checks against dangling cloud resources.
- **Secrets/exposures:** exposed `.env`, `.git`, backups, directory listings,
  debug endpoints, stack traces.

### 3b. Manual/agentic depth (where the real bounties are)
Walk each high-priority target through the bug-class checklist:

- **Broken Access Control / IDOR / BOLA** — the #1 source of high-value bounties.
  Enumerate object IDs, swap them across accounts, test horizontal & vertical
  privilege escalation, force-browse admin routes, tamper with roles/tenant IDs.
- **Authentication & session** — weak reset flows, JWT flaws (`alg:none`, weak
  secret, `kid` injection), OAuth misconfig (redirect_uri, state, account
  linking), MFA bypass, session fixation.
- **Injection** — SQLi, NoSQLi, command, template (SSTI), LDAP, header injection.
  Use OOB confirmation where blind.
- **SSRF** — cloud-metadata reach (169.254.169.254), internal port scanning,
  webhook/URL features, PDF/image renderers, "fetch from URL" anywhere.
- **Business logic** — race conditions (coupon/refund/transfer), price/quantity
  tampering, workflow step-skipping, mass assignment, insufficient
  rate-limiting on sensitive actions.
- **XSS / client-side** — reflected/stored/DOM, postMessage abuse, prototype
  pollution, CSPi gaps. Prioritize stored & those that reach authenticated/admin
  context.
- **CSRF / CORS** — state-changing requests without protection, permissive ACAO
  with credentials.
- **File handling** — unrestricted upload, path traversal, XXE, ZIP-slip,
  image/PDF processing bugs.
- **Misconfig & exposure** — verbose errors, debug modes, default creds, exposed
  admin/CI/monitoring (Jenkins, Grafana, Kibana, Actuator).

**Output:** `results/<target>/03-candidates/candidates.jsonl` — one record per
lead with `{target, class, evidence, confidence, why_it_matters}`.

**Agent reasoning:** For each high-priority endpoint, the agent picks the 2–3
*most plausible* bug classes given the tech/behavior and tests those first.
Don't shotgun every class at every endpoint — **hypothesize, then test**.

---

## Phase 4 — Verification, PoC & Chaining

**Goal:** Convert candidates into **proven** vulnerabilities with minimal,
safe PoCs.

**Do:**
- Reproduce from a clean state (fresh session/account) to rule out
  scanner-induced false positives.
- **Minimize the PoC** — the smallest request/steps that demonstrate the bug.
- **Prove impact safely** — read-only proof, OOB interaction, your-own-account
  data only. No destruction, no real-user data, no mass exploitation.
- **Chain** — ask of every confirmed bug: *what does this unlock?* Combine
  info-leaks + IDOR + weak authz into a single high/critical narrative.
- Score impact: CVSS 3.1 vector + business context (what data/funds/control is
  at risk).

**Output:** `results/<target>/04-verified/` → one folder per confirmed bug with
PoC, request/response evidence (sanitized), and impact note.

**Agent reasoning:** Be skeptical of your own hits. If you cannot reproduce it
twice, it is not verified. Downgrade honestly.

---

## Phase 5 — Triage, Severity & Deduplication

**Goal:** Decide what is worth reporting and in what order.

**Do:**
- **Severity:** CVSS 3.1 base + temporal/business adjustment. Map to the
  program's reward tiers.
- **Dedup:**
  - Against the program's known-issues / out-of-scope-known list.
  - Against your own `results/` history (don't re-report).
  - Against public CVEs/changelogs (is this a known, already-patched-elsewhere
    issue?).
- **Prioritize:** report highest-impact + cleanest-PoC first. Speed matters for
  duplicates — first valid report wins.

**Output:** `results/<target>/05-triage/triage.md` — ranked table with
severity, dedup status, and report-readiness.

---

## Phase 6 — Reporting

**Goal:** Communicate the bug so a triager can reproduce and reward it in minutes.

**A great report has:**
1. **Title** — bug class + impact + location, one line.
2. **Summary** — what, where, why it matters, in 2–3 sentences.
3. **Severity** — CVSS vector + business impact.
4. **Steps to reproduce** — numbered, copy-pasteable, from a clean state.
5. **Proof** — minimal request/response or screenshots (sanitized).
6. **Impact** — concrete attacker capability and affected users/data.
7. **Remediation** — specific, actionable fix tied to root cause.
8. **References** — CWE, OWASP, relevant docs.

Use `templates/report.md`. Generate via `/report`.

**Agent reasoning:** Write for a busy triager. Clarity and reproducibility are
worth more than length. Never include unsanitized secrets/PII.

---

## The Intelligence Loop (what makes this *agentic*)

```
            ┌─────────────────────────────────────────────┐
            │  observe → hypothesize → test → learn → adapt │
            └─────────────────────────────────────────────┘
```

After each phase the agent **re-plans**: new assets reshape the surface map; a
leaked internal hostname reopens recon; a confirmed IDOR suggests testing the
same pattern across every object type. The hunt is not linear — it is a loop that
tightens around the most promising lead. The agent maintains a living
`results/<target>/HUNT-LOG.md` recording every decision, so the loop survives
context resets and Pi reboots.

---

## Bug-Class Quick Reference (priority-ordered by typical bounty value)

| Class | Where to look | Why it pays |
|-------|---------------|-------------|
| Broken Access Control / IDOR / BOLA | Any object-id endpoint, multi-tenant apps | Direct data access, high severity, scanner-blind |
| SSRF | URL-fetch features, webhooks, renderers | Cloud metadata → full compromise |
| Auth/OAuth/JWT flaws | Login, reset, SSO, token handling | Account takeover |
| Injection (SQLi/SSTI/cmd) | Search, filters, templates, exports | RCE / data exfil |
| Business logic & race conditions | Checkout, refund, transfer, quotas | Financial impact, scanner-blind |
| Subdomain takeover | Dangling DNS → cloud | Easy, clean, common |
| Stored XSS (to admin/authn ctx) | User-content rendered to staff | Session/admin compromise |
| Secrets & exposures | `.git`, `.env`, JS, backups, CI | Direct keys → lateral movement |
