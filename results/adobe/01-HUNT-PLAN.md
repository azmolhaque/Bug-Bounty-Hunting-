# Adobe — hunt plan

Read `00-PROGRAM.md` first. Two facts drive everything here:

1. **Tier 3 (AI) pays 1.5–3× every other tier**, and its assets are the newest code in the estate.
2. **1,078 reports in 90 days.** Duplicate risk, not difficulty, is the thing that will kill us.

Those point the same way: hunt the newest AI surfaces, where the payout is highest and the
trodden ground is thinnest.

---

## PRIMARY TARGET — Acrobat PDF Spaces

`acrobat.adobe.com` · Tier 3 (AI) **and** Tier 1 (Acrobat Web) — non-AI bugs found here still pay Tier 1.

**What it is, in Adobe's words:** *"PDF Spaces allow you to add multiple files and links, get
AI-powered insights, and organize your research in one conversational knowledge hub. It uses the
added files and links to generate summaries, answer questions, and surface key insights."*

**Why this and not the other nine AI assets:**

| Property | Why it matters |
|---|---|
| Ingests **user-supplied links** | The XPIA delivery vector is a *product feature*. We control the served bytes completely — no smuggling required |
| Ingests **user-supplied files** | Second independent delivery channel |
| **"Spaces"** = a sharing container | Sharing semantics ⇒ a cross-tenant boundary, which is our strongest class |
| Feeds Create Podcast and Create Presentations | One injection, three output pipelines to test |
| Newest feature in the Acrobat estate | Thinnest duplicate risk |
| Dual-tier asset | An authorization bug here pays Tier 1 even if it isn't "AI" |

---

## The PDF Spaces permission model (from Adobe's public documentation, 2026-08-27)

**No requests were made to any Adobe asset to obtain this.**

| Access level | Who can reach the Space |
|---|---|
| **Private** | Invited collaborators only |
| **Organization** | Anyone in the owner's organisation |
| **Public** | **Anyone with the link — no sign-in required** |

| Role | Capability |
|---|---|
| Viewer | Read files |
| Reviewer | Read + comment |
| **Contributor** | **Add, update or delete content — *including files added by the owner*** |

### ⚠️ GATE — verify before committing the engagement

PDF Spaces is marketed under **Acrobat Studio**, which is a paid product. **Confirm on day one
that a free Adobe account can create a Space, add a link, and use AI Assistant.** If it is
paywalled, this target is unreachable for us and we switch to **Express AI Assistant**
(`new.express.adobe.com`), which is free-tier. Do not spend a session discovering this.

### The sentence worth the whole engagement

> *"when the link access level is set to Anyone with the link, users can only be assigned Viewer
> or Reviewer permissions, as **Contributor permissions are not supported** for public access links."*

A **stated restriction**. Restrictions enforced in the UI and forgotten in the backend are among
the most reliable findings available. **H6 below tests exactly this.**

### What the model changes about H1

The original H1 assumed we must persuade a victim to add our link. We do not:
**a Contributor can add links to someone else's Space.** The realistic chain is therefore

> low-privileged collaborator adds an attacker link → the **owner's** AI Assistant ingests it →
> injection executes in the **owner's** context → exfiltration via the sink from Phase 0

That is a legitimate, low-privilege, remote attack — not a social-engineering premise.

---

## H6 — public-link role restriction bypass  ⭐⭐ NEW, and the sharpest test we have

> **Assign `Contributor` to a public ("anyone with the link") Space through the API, and have an
> unauthenticated request then add, modify or delete content.**

Why this is the best-shaped hypothesis in the plan:

- The restriction is **documented**, so intended behaviour is unambiguous — no "working as
  designed" argument is available to the triager.
- The boundary is **binary**: either an unauthenticated request mutated the Space or it did not.
- Impact is concrete: **unauthenticated write/delete on another user's content.** Adobe's own
  CVSS table puts I:H authorization failures at 7.5, and `PR:N` (public self-signup / guest)
  keeps privileges-required at None.
- It needs **no AI reasoning at all**, so none of the AI-specific exclusions apply.
- It chains straight into H1: a public Contributor can add the malicious link.

**Procedure:** create a Space as A → set access to *anyone with the link* → capture the
share/permission API call from DevTools → replay it with `Contributor` substituted → then, from a
**signed-out** browser or plain `curl`, attempt add / update / delete.

**Gates:** (0A) a public Viewer link works read-only as documented · (0B) the UI genuinely refuses
to offer Contributor for a public link · (0C) an invalid role string is rejected — if the API
accepts arbitrary role values, the "bypass" is just unvalidated input and needs re-framing.

**Not a finding:** the API accepting the role but the capability not actually working. The proof
is a **mutation performed by an unauthenticated request**, not a 200 on the permission call.

---

## PHASE 0 — capability probes. **RUN THESE BEFORE ANY PAYLOAD.**

> **The lesson from the Google AI VRP campaign** (`results/google-vrp/AI-VRP-1-HUNT-LOG.md`):
> we ran three full injection campaigns before verifying an exfiltration sink existed. Never again.
> **Establish what the system *can* do before testing what it *should not*.**

Each probe is asked plainly, as a normal user would. No adversarial framing — we are measuring
capability, not guardrails.

| # | Probe | Question answered |
|---|---|---|
| P1 | Does assistant output render **markdown images**? | Auto-fetched `![](https://host/x.png)` is the classic zero-click exfiltration channel |
| P2 | Does it render **clickable links**, and are they auto-fetched or previewed? | One-click exfil channel; unfurling = zero-click |
| P3 | When given a URL, does the **server** fetch it or the browser? | Server-side fetch ⇒ SSRF surface as well as injection delivery |
| P4 | What is the fetching **User-Agent and source IP**? | Confirms server-side fetch; identifies the egress path |
| P5 | Does it follow **redirects**? To internal addresses? | SSRF escalation path (their SSRF ceiling is 8.6 when internal is reached) |
| P6 | Can it read content from a document **not in the current Space**? | The retrieval boundary — ask directly first, before trying to cross it |
| P7 | What **tools** does the assistant have? Ask it plainly | Agentic surface enumeration |
| P8 | Are ingested **file metadata fields** (EXIF/IPTC/XMP, PDF `/Info`) read into context? | Adobe's own XPIA example is metadata-based |

**Instrumentation:** every probe URL is unique — `https://<oob-host>/<probe-id>` — so a hit is
attributable to exactly one probe. Log the requesting IP, User-Agent and timing.

**If P1–P5 all come back negative, there is no exfiltration sink**, and no amount of injection
work will produce a reportable finding on this asset. Say so, log it, and move to the next asset
rather than running campaigns into a wall.

---

## H1 — XPIA via ingested link → boundary crossing  ⭐ primary

> **A Space ingests an attacker-controlled URL. The page content instructs the assistant to
> retrieve data the requesting user should not have, and to emit it through the sink found in
> Phase 0.**

Delivery is legitimate product behaviour: the victim adds a link, or we share a Space containing
one. What must be proven is **the boundary crossing**, not the injection.

**Targets worth reaching, in order of value:**
1. Content of another user's document (cross-tenant read)
2. The system prompt / internal policy text (explicitly named as in-scope disclosure)
3. Credentials or tokens present in the assistant's context
4. An authenticated action taken on the victim's behalf (unauthorised tool use)

**Not a finding (their exclusions, verbatim):** prompt influence with no backend impact ·
role-play · model deviation · anything where the assistant merely *says* something unusual.

---

## H2 — cross-Space / cross-tenant retrieval boundary  ⭐ strongest class fit

> **Account B's assistant returns content from a document that only Account A holds and never shared.**

This is the H3/H5 methodology from Looker Studio and Exoscale, applied to a RAG retriever.

- **Gate 0A** — B's assistant reads B's own document → returns B's canary
- **Gate 0B** — B opens A's Space URL directly in the browser → denied
- **Gate 0C (FO-2)** — a syntactically valid but non-existent Space/document ID → record it. If
  that returns content, the retriever is a catch-all and every hit is a false positive
- **Cross** — B's session, A's Space or document identifier. **Proof is A's canary in B's response.**

Axes: Space ID · document ID · a shared Space that was later unshared (revocation) · a document
removed from a Space but still in the index · Podcast/Presentation generated from a Space the
requester can no longer read.

> **Revocation is the sleeper.** RAG indexes are frequently built once and not re-checked when
> sharing changes. "Access removed but still retrievable" is a clean, demonstrable, high-impact bug.

---

## H3 — injection survival into generated artifacts

> **Content injected into a source document changes the generated Presentation, Podcast or summary
> in a way that crosses a boundary** — e.g. an artifact that exfiltrates on open, or that carries
> content the requester lacks rights to.

Three output pipelines share one ingestion path. A sanitiser applied to chat output is often
absent from the artifact generator.

---

## H4 — server-side fetch as SSRF (non-AI, Tier 1)

If P3/P4 show Adobe's **servers** fetch "added links", that is a server-side fetch primitive on a
Tier 1 asset independent of any AI framing.

- Their ceiling: **5.8** if nothing sensitive is reached, **8.6** if a sensitive internal endpoint is.
- **FO-9 applies with force:** an OOB ping to our own host is a *precondition*, not a finding.
  Our own Google VRP history (VirusTotal SSRF → "Intended behavior") is the cautionary case.
  Only a sensitive internal resource actually read makes this reportable.

---

## H5 — Express AI Assistant, agentic tool abuse

`new.express.adobe.com` (Tier 2 asset, Tier 3 AI). Secondary. Run after Acrobat, reusing the
Phase 0 probe set. Note `express.adobe.com` and `express-embed.adobe.com` are **out of scope** —
only `new.express.adobe.com`.

---

## Deliberately NOT hunting

| Skipped | Why |
|---|---|
| Photoshop · Acrobat desktop · legacy Creative Cloud | A decade of hunting. Duplicate death |
| **Firefly backend API ACLs** | Explicitly out of scope |
| **Firefly job IDORs** | Out of scope — UUID4, 72 h TTL |
| **IMS OAuth**, Learning Manager custom roles/social/OAuth, ColdFusion XXE | Temporarily out of scope |
| `express.adobe.com`, `express-embed.adobe.com`, `www.behance.net`, `*.adobesign.com` | Out of scope |
| Rate limits, races, concurrency on Acrobat Web | Explicitly excluded absent tangible impact |
| Everything on the Hard Rejection List (CLAUDE.md §3) | Adobe's exclusion list matches it almost line for line |

---

## Sequence

| Session | Work | Gate to continue |
|---|---|---|
| **0 (pre-1 Sep)** | Read Intigriti scope on day one. Create accounts A and B with the **correct** alias. **Confirm PDF Spaces works on a free account.** Map the sharing UI as an ordinary user. OOB host already built | Scope confirmed · accounts eligible · **Spaces reachable free** |
| **1** | **H6 public-link role bypass** — gates first, then the substitution | Needs no AI, no sink, binary result. Run it first |
| **2** | Phase 0 capability probes P1–P8 | A sink exists (P1–P5) **or** the retrieval boundary looks testable (P6) |
| **3** | H2 cross-tenant retrieval — gates first, then the cross | A canary crosses, or a clean negative |
| **4** | H1 XPIA via a Contributor-added link, to the sink from session 2 | Boundary crossed, or drop |

**H6 moved ahead of the AI work deliberately.** It requires no exfiltration sink, no model
behaviour, and none of the AI exclusions apply to it. If the sink probes come back empty, H6 is
still live — so it must not depend on them.

**Timebox: 4 sessions**, as agreed. No confirmed boundary crossing by session 4 → reassess the
asset, not the methodology.

---

## Before writing any report

1. **Duplicate check.** Adobe's rules are severe: same vulnerability *or* same impact chain, on
   any endpoint or flow, is a duplicate. Search their hacktivity and public writeups for the class
   **before** investing in a write-up.
2. **Their CVSS ceiling, not ours.** Cross-tenant IDOR reading PII tops out at **7.5 High** in
   their scheme. In Tier 3 that is **$1,500–7,500**. Do not argue for Critical — FO-10 and FO-13.
3. **Testing IP address is mandatory** for payout and Safe Harbour. Record `curl ifconfig.me`
   at the start of every session.
4. Full evidence checklist per CLAUDE.md §9.8.
