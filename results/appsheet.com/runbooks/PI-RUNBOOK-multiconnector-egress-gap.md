# Pi Runbook — Multi-Connector SSRF Egress-Gap Test (AppSheet / Google VRP)

**Target:** `*.appsheet.com` (Google VRP, AppSheet, TIER0)
**Run from:** Raspberry Pi (`192.168.10.118`) + authenticated AppSheet browser session
**Objective:** Show AppSheet's SSRF mitigation is **per-feature, not centralized** — i.e.,
multiple user-controllable server-side-fetch surfaces (beyond the OData connector in F002)
issue unfiltered outbound requests from GCP. Proving the gap across **≥2 surfaces** elevates
F002 from a single SSRF into a **systemic egress-control gap** report.

> **Why this is the high-impact play:** the 2021 AppSheet webhook SSRF was point-fixed in the
> webhook path. No IP-level egress filter was generalized. F002 already proves the OData path
> still reaches `169.254.169.254` at TCP. If REST/image/PDF/other connectors also fetch
> attacker URLs from GCP, that is one root cause across many features — a stronger finding.

---

## 0. The single rule that governs every step

**Prove the fetch reaches your server from GCP, capture what leaks, then STOP.**
You are demonstrating a *primitive*, not exploiting it.

### HARD STOPS — do not cross (out of bounds for our methodology + VRP rules)
- ❌ No requests pointed at internal/cloud services to read their data:
  no `169.254.169.254` token reads, no `metadata.google.internal`, no RFC1918 hosts,
  no `localhost`/`127.0.0.1` service interaction.
- ❌ No redirect chaining **into** internal ranges (IMDS, k8s, internal APIs).
- ❌ No internal port scanning / sweeping.
- ❌ No reading or modifying data belonging to other tenants/users.
- ❌ No DoS, no automated mass requests, no high-volume fuzzing.

### IN-BOUNDS — what you ARE doing
- ✅ Point a connector URL at **your own OOB listener**; confirm a **GCP-origin** HTTP hit.
- ✅ Capture leaked request headers (`Authorization`, `Traceparent`, etc.).
- ✅ Characterize the client's redirect behavior using **your own benign HTTP endpoint**
  (never an internal address) — see §7.
- ✅ Optionally observe the *reachability error signature* for a link-local address
  **without sending any internal payload** — passive, single request, no escalation (§7.2).
  This mirrors evidence already captured in F002; treat as optional.
- ✅ Only attacker-owned credentials/servers; only an app **you own**.

If a step would require reading a response from an internal service to "prove" anything —
**stop and write it up as reachability**. Let Google confirm escalation.

---

## 1. Scope gate (run first, every session)

```bash
cd ~/bug-bounty   # repo root on the Pi
./scripts/scope-check.sh appsheet.com
./scripts/scope-check.sh api.appsheet.com
# Each must print IN-SCOPE before proceeding. If empty/!=IN-SCOPE, abort.
```

---

## 2. Lab setup

### 2.1 OOB listeners (two: one HTTPS, one plain HTTP)

You need two distinct canary endpoints:
- **L1 (HTTPS)** — the URL you put in connector fields (AppSheet enforces HTTPS client-side).
- **L2 (HTTP)** — the **benign** redirect destination for the cross-scheme test (§7.1).
  L2 is *your* server on plain HTTP — NOT an internal address.

```bash
# Terminal A — primary HTTPS canary (interactsh has valid TLS)
interactsh-client -server oast.pro -v 2>&1 | tee ~/oob_L1.log &
sleep 3
L1=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob_L1.log | head -1)
echo "L1 (HTTPS canary): https://$L1"

# Terminal B — benign HTTP redirect target (your own VPS or ngrok http, NOT internal)
#   Easiest: a second interactsh session, used over http://
interactsh-client -server oast.pro -v 2>&1 | tee ~/oob_L2.log &
sleep 3
L2=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob_L2.log | head -1)
echo "L2 (HTTP redirect target): http://$L2"
```

> If you control a small VPS, run a logging server there for richer captures
> (full headers + body). `results/appsheet.com` already references
> `scripts/appsheet-ssrf-probe.sh --setup` which can stand one up.

### 2.2 Account & app
- Log into AppSheet with a **free** account (sufficient for connector Test buttons).
- Create a throwaway app **you own** for the data/image/PDF surfaces (T3–T5).
- Note: webhook/automation surfaces (T6) require Core+ paid plan — skip unless you have one.

### 2.3 GCP IP attribution helper
A hit only counts if it originates from **Google/GCP** (proves server-side, not your browser).

```bash
# attribute.sh <ip>
ip=$1
whois "$ip" 2>/dev/null | grep -iE 'OrgName|netname|org-name' | head -2
# PASS if Google LLC / Google Cloud / AS15169. FAIL if it's your own egress IP.
```

---

## 3. Evidence schema (capture this for EVERY test)

Append one row per test to `results/appsheet.com/runbooks/egress-test-log.md`:

| Field | How to get it |
|-------|---------------|
| `test_id` | T1…T7 |
| `surface` | connector/feature name |
| `payload_url` | the L1 URL you entered |
| `trigger` | button/action that fired it |
| `oob_hit` | yes/no (from `~/oob_L1.log`) |
| `src_ip` | source IP of the HTTP interaction |
| `src_org` | `attribute.sh <src_ip>` result (must be Google/GCP) |
| `method+path` | e.g. `GET /$metadata` |
| `leaked_headers` | `Authorization`, `Traceparent`, cookies, tokens, UA |
| `client_fingerprint` | `User-Agent` / library string (identifies the .NET/HTTP stack) |
| `redirect_followed` | from §7.1 (yes/no/n-a) |
| `verdict` | EGRESS-GAP / FILTERED / NO-FETCH |
| `timestamp_utc` | when the hit landed |

---

## 4. The reusable egress-probe pattern (apply to each surface)

For every surface below:
1. **Baseline reachability:** put `https://$L1/probe-T<n>` in the URL field; trigger.
2. **Watch:** `tail -f ~/oob_L1.log` for an HTTP interaction.
3. **Attribute:** run `attribute.sh` on the source IP → must be Google/GCP.
4. **Record:** fill the evidence row. Note every leaked header verbatim.
5. **STOP** at confirmation. Do **not** then point the field at anything internal.

Verdict logic:
- GCP-origin HTTP hit → **EGRESS-GAP** (server fetches arbitrary attacker URL).
- Instant client-side error / no network → **FILTERED** (note the error string).
- Field accepted but no OOB hit and no error → **NO-FETCH** (likely client-side only;
  re-test by completing the flow, e.g. actually saving/using the source).

---

## 5. Per-surface playbook

> Each `path` segment (`/probe-T1`, etc.) tags the hit so you know which surface fired.

### T1 — OData data connector (baseline / regression of F002)
- **Where:** Account → *Add OData connection information* → OData Service Root URL.
- **Payload:** `https://$L1/probe-T1` · Username `canary` · Password `canary-T1` · **Test**.
- **Expect:** GCP-origin `GET /probe-T1/$metadata`, `Authorization: Basic …`, `Traceparent: …`.
- **Purpose:** confirm F002 still live + serves as the positive control for the rig.

### T2 — Apigee / REST-style data source
- **Where:** App → Data → Add data source → **Apigee** (or any "API"/REST source type your
  account exposes). Enter the service/base URL.
- **Payload:** `https://$L1/probe-T2` → Test/Authorize/Save.
- **Expect:** GCP-origin hit. Record whether credentials/headers are attached.
- **Note:** if the type validates the host against an allowlist (e.g. `*.apigee.net`),
  record the rejection string — that's a *good* sign the control exists here; contrast with T1.

### T3 — Image / file URL column (server-side media fetch)
- **Where:** in your app, add a column of type **Image** (or **Thumbnail**/**File**) whose
  value is a URL. Set a row's value to `https://$L1/probe-T3.png`.
- **Trigger:** open the app view that renders the image, or trigger a sync/thumbnail job;
  also try an **email/notification** that embeds the image.
- **Expect:** if AppSheet proxies/caches images server-side, a GCP-origin `GET /probe-T3.png`.
- **Why it matters:** image proxies are classic blind-SSRF vectors and a *different* HTTP
  client than the OData one.

### T4 — PDF / report / email template with remote resource
- **Where:** Automation/report or email template (Google Doc template or HTML email body).
- **Payload:** embed `<img src="https://$L1/probe-T4.png">` (and/or a remote CSS/stylesheet
  ref) in the template; generate the PDF/report or send the email to **yourself**.
- **Expect:** GCP-origin fetch when the template is rendered server-side.
- **Note:** rendering engines (headless browser / PDF lib) are high-value SSRF surfaces.

### T5 — Other URL-bearing connectors (Salesforce / Smartsheet / Cloud SQL host, etc.)
- **Where:** Data → Add data source → each remaining type that accepts a host/instance URL.
- **Payload:** `https://$L1/probe-T5-<type>` → Test/Save.
- **Expect / record:** GCP-origin hit vs. host-allowlist rejection — per type. This builds the
  matrix showing which surfaces are filtered vs. open (the systemic-gap evidence).

### T6 — Webhook automation task (PAID PLAN ONLY — regression of the 2021 fix)
- **Where:** Automation → Bot → Task → **Call a webhook**. URL = `https://$L1/probe-T6`.
- **Trigger:** the bot's event (e.g. row add).
- **Expect:** GCP-origin POST. **This path was fixed in 2021** — if it now reaches your server
  *and* (via §7.1) follows redirects, that is a **regression**: report immediately, high value.
- Skip if you have no Core+ plan (free plan does not execute bots — confirmed in HUNT-LOG).

### T7 — REST API connector test endpoint (unauthenticated staging tie-in)
- Optional: from the Pi (no browser), re-confirm F001 staging auth-bypass with the two-curl
  diff, and check whether any staging connector/test endpoint also fetches `https://$L1/probe-T7`.
- Keep unauthenticated, zero-UUID; do not enumerate real apps.

---

## 6. In-bounds escalation characterization

### 6.1 Cross-scheme redirect test — against YOUR OWN benign HTTP endpoint (NOT internal)
This determines whether a surface's HTTP client would follow HTTPS→HTTP redirects (the
property that made the 2021 webhook bug reach IMDS) — **without ever touching Google internal
infrastructure**. You redirect to **L2 (your benign HTTP canary)**, never to `169.254.x`.

```bash
# Make L1 respond with a 302 to the benign HTTP endpoint L2.
# (On your VPS logging server; or configure interactsh response rules.)
#   L1: 302 Found  →  Location: http://$L2/redirected
```
- Re-run the surface's Test pointing at `https://$L1/redir`.
- **If L2 (HTTP) receives the hit** → the client follows cross-scheme redirects. This is the
  dangerous property. **Do NOT then aim it at IMDS.** Report it as: *"client follows HTTPS→HTTP
  redirects; combined with confirmed link-local TCP reachability (F002 §3), an attacker could
  reach IMDS — escalation to be validated by Google."* That sentence is your Critical hook,
  proven entirely with benign endpoints.
- **If only L1 logs the 302 and L2 never fires** → redirect blocked (like the OData client).
  Record as an incidental control, not a deliberate egress filter.

### 6.2 OPTIONAL — link-local reachability *signature* only (no payload, no escalation)
Mirrors F002 §3. A **single** request to `https://169.254.169.254` characterizes the error:
- *"SSL connection could not be established"* → TCP reached, TLS failed (reachable).
- *"must be established using HTTPS"* / instant block → not reached.

**Constraints:** one request, HTTPS only (no `http://` to IMDS), **no path** to any metadata
endpoint, no redirect, no retry, no token. You are reading *your own* error message, not the
metadata service's response. If uncomfortable, skip — §6.1 already establishes the escalation
property cleanly. **Never** request `…/computeMetadata/…` or any IMDS path.

---

## 7. Decision matrix → what to file

Tally verdicts across T1–T7:

| Observed | Report to file |
|----------|----------------|
| Only T1 = EGRESS-GAP | Submit **F002** as-is (single OData SSRF). |
| **≥2 surfaces = EGRESS-GAP** | Submit a **consolidated "Systemic SSRF egress-control gap"** report: list each affected surface + GCP-origin evidence; root cause = no centralized egress filter; reference 2021 fix as un-generalized. F002 becomes one instance. **Highest bounty path.** |
| Any surface follows cross-scheme redirect (§6.1) | Add an **escalation section**: link-local reachable + redirect-following client = IMDS reachable in practice; request Google validation. Likely Critical. |
| T6 webhook reaches your server | **Regression of the 2021 fix** — flag prominently; high severity. |
| A surface leaks third-party/victim creds (T1 Basic, OAuth tokens) | Add **credential-exfiltration** impact (CWE-200) per surface. |
| Surface is host-allowlisted (rejection string) | Record as **negative control** — strengthens the "some paths filtered, others not" systemic argument. |

Then hand off to the report writer:
```
Use the report-writer agent / `report` skill with the egress-test-log.md matrix
+ per-surface OOB evidence to draft the consolidated VRP report.
```

---

## 8. Cleanup & teardown
- Delete the throwaway app and all test connectors/data sources.
- Stop OOB listeners: `kill %1 %2` (or the interactsh PIDs).
- Remove canary URLs from any saved templates/automations.
- Archive `~/oob_L1.log`, `~/oob_L2.log`, and `egress-test-log.md` into
  `results/appsheet.com/evidence/` and commit.

---

## 9. Evidence-log template (create on first run)

```markdown
# Egress-Gap Test Log — AppSheet (Pi)
| test_id | surface | payload_url | oob_hit | src_ip | src_org | method+path | leaked_headers | client_fp | redirect_followed | verdict | ts_utc |
|---------|---------|-------------|---------|--------|---------|-------------|----------------|-----------|-------------------|---------|--------|
| T1 | OData | https://L1/probe-T1 | | | | | | | | | |
| T2 | Apigee/REST | https://L1/probe-T2 | | | | | | | | | |
| T3 | Image column | https://L1/probe-T3.png | | | | | | | | | |
| T4 | PDF/email tmpl | https://L1/probe-T4.png | | | | | | | | | |
| T5 | Other connectors | https://L1/probe-T5-* | | | | | | | | | |
| T6 | Webhook (paid) | https://L1/probe-T6 | | | | | | | | | |
| T7 | Staging/REST | https://L1/probe-T7 | | | | | | | | | |
```

---

## 10. One-glance checklist
- [ ] Scope gate passed
- [ ] Two OOB listeners up (L1 https, L2 http-benign)
- [ ] Own throwaway app created
- [ ] T1 OData reconfirmed (positive control)
- [ ] T2–T5 run, each row logged with GCP attribution
- [ ] §6.1 redirect test (benign L2 only) per fetching surface
- [ ] Decision matrix evaluated
- [ ] No internal address ever targeted; no internal data read
- [ ] Cleanup done; evidence committed
