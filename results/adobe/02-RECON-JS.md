# Adobe Acrobat Web — unauthenticated JS recon, 2026-08-27

Researcher `gorib` · testing IP **180.148.212.32** · Raspberry Pi 5.
All requests were **GET on static assets** under the in-scope Tier 1 asset `*.acrobat.adobe.com`,
sequential with 2 s delays. No fuzzing, no scanning, no authentication.

---

## How the surface was obtained

`https://acrobat.adobe.com/` unauthenticated is only a login page — but it ships the **complete
micro-frontend manifest**: 88 "dropin" modules with exact versions, plus `<base href="/home/" />`.
Bundles are origin-absolute and **served without authentication**.

```
/dc-web-mcp/4.7.7_1.49.0/bootstrap.js                          200   4,509 b
/dc-web-mcp/4.7.7_1.49.0/web-mcp-chunk.js                      200 544,924 b
/dc-knowledge-workspace-dropin/4.34.0_6.1549.2/bootstrap.js    200 107,766 b
/dc-ask-ai-dropin/4.1.0_4.1.0/bootstrap.js                     200  27,394 b
/dc-ai-playground/4.10.0_1.57.0/bootstrap.js                   200 131,798 b
/dc-artifacts-dropin/4.44.0_1.513.2/bootstrap.js               200   8,161 b
https://documentcloud.adobe.com/dc-discovery/versionManifest.js 200 676,983 b
```

Reading an application's shipped client code is not a finding — it is Phase 2 mapping. Recorded
because it produced the hypotheses below.

---

## Finding 1 — `dc-web-mcp`: a full MCP client in Acrobat Web ⭐⭐⭐

Adobe's AI scope names MCP explicitly: *"Compromised MCP Servers, Context poisoning via MCP,
Tool Response Manipulation, MCP Protocol Exploits, **Unauthorized MCP Server Discovery**"* with
desired impact *"data exposure, unauthorized tool execution, **cross-tenant access**"*.

Confirmed in the bundle:

| Capability | Evidence | Why it matters |
|---|---|---|
| Tool listing / invocation | `tools/list`, `tools/call`, `notifications/tools/list_changed` | The agentic surface Adobe asks about |
| **Sampling** | `sampling/createMessage`, `toolChoice`, `stopReason`, `maxTokens` | An MCP **server** can drive the **client's** LLM. Server-controlled prompt into the user's model |
| **URL elicitation** | `UrlElicitationRequiredError`, `elicitations` | A server can require the client to open a URL — redirect / exfil / phishing primitive |
| Task store | `this._taskStore.getTask(e.params.taskId, t.sessionId)` | Retrieval keyed by **taskId + sessionId** — an authorization boundary worth testing |
| Error surface | `class McpError`, `cn.InvalidParams`, `cn.UrlElicitationRequired` | Distinguishable failure modes = a clean oracle |

**Questions to answer first (in order):**
1. **Can a user point Acrobat Web at an arbitrary MCP server?** If yes, we control a server that
   registers tools, uses sampling against the victim's model, and elicits URL opens. If no,
   which servers are permitted and how is that list obtained (*"Unauthorized MCP Server
   Discovery"* is literally in their wanted list)?
2. **Is `sessionId` enforced on `getTask`, or only passed?** A `taskId` from another session
   returning data is cross-session access.
3. **Where does URL elicitation land** — is the target validated, or will it open any origin?
4. **Does sampling output re-enter the document context** (a server-to-model injection path)?

## Finding 2 — anonymous PDF Space creation

```
window.open(`${l}/link/spaces/create-new-space/?context=anonGeneratePdfSpace`, "_self")
KW_ANON_CREATE: "dc-web-kw-anon-create"      KW_ANON_GENERATE_PDF_SPACE: "anonGeneratePdfSpace"
KW_AVALON_ANON: "dc-web-kw-avalon-anon"      KW_AVALON_ANON_CREATE: "dc-web-kw-avalon-anon-cr"
SIGN_IN_NUDGE_ANON_SPACE: "signInNudgeInAnonCreatedSpace"
anonCreationMonetizationCheck
```

**Spaces can be created without signing in.** This resolves the Acrobat-Studio paywall gate —
an unauthenticated entry point exists — and opens its own questions:

- Who **owns** an anonymous Space, and what identifier binds it?
- On sign-in, how is it **claimed**? Can a *different* account claim someone's anonymous Space?
  (`signInNudgeInAnonCreatedSpace` implies a claim flow exists.)
- Do anonymous Spaces have the same sharing model, and can one be set **public + Contributor**?
- Is `anonCreationMonetizationCheck` the only limit on anonymous generation?

The claim flow is the sharpest question: an unauthenticated-created object later bound to an
identity is a classic ownership-assignment bug.

## Finding 3 — internal vocabulary

PDF Spaces is internally **"knowledge workspace" (`kw`) / "collections"**:

```
kw.collection.asset_count · kw.collection.user_role · kw.collection.network_rtt
knowledge-workspace-share-entry · dc-edit-shared-spaces · external-workspaces
/link/spaces/create-new-space/ · /pdf-spaces · /presentations/${id} · "collection"
SHARE_SPACE="share_space" · ADD_FILES="add_files" · CREATE_NEW_COLLECTION="createNewCollection"
```

`kw.collection.user_role` is the field H6 targets.

**Vocabulary mismatch worth noting:** documentation says roles are *Viewer / Reviewer /
Contributor*; the code carries `"editor"` and `"viewer"`. A mapping layer between UI labels and
wire values is a classic place for a role the UI never offers to be accepted by the API.

## Finding 4 — generation pipelines not in the published AI asset list

```
PODCAST="podcast" · PRESENTATION="presentation" · AVALON="avalon"
INTERACTIVE_REPORT="interactive-report" · CREATE_DESIGNS="create-designs"
```

Adobe's Tier 3 list names Create Presentations and Create Podcast. **`avalon`,
`interactive-report` and `create-designs` are not listed.** Newer pipelines on the same
ingestion path — thinner duplicate ground, but confirm scope coverage before reporting.

Also present: a `webSearch` feature flag — directly relevant to capability probes P3/P5
(does the assistant fetch URLs server-side?).

## Finding 5 — staging is edge-blocked (closed)

```
https://stage.acrobat.adobe.com   403 Access Denied (Akamai)
https://dev.acrobat.adobe.com     403 Access Denied (Akamai)
```

Both match the in-scope wildcard `*.acrobat.adobe.com` and are referenced from production code
(`/link/workspaces/create-project`, `/link/workspaces/kw-eval-mode`), but are restricted at the
edge — almost certainly an IP allowlist. **One probe each, negative, closed.** Do not re-probe.

> Note `dc.stage.acrobat.com` and `dc.dev.dexilab.acrobat.com` are **`acrobat.com`**, a domain
> *not* in the scope list. **Out of scope — do not touch.**

**Deferred hypothesis:** the Looker P2 (509911655) was exactly this shape — an edge trusting a
client-supplied header for an access decision. Testing whether this Akamai ACL can be influenced
by request headers is in-scope and involves no customer data. Low priority, and only after the
MCP and Spaces work.

---

## Revised hypothesis order

| # | Hypothesis | Why |
|---|---|---|
| **H7** | **MCP: arbitrary server connection, sampling abuse, URL elicitation, `getTask` session boundary** | Tier 3 AI, explicitly requested by Adobe, newest code, almost certainly unhunted |
| **H8** | **Anonymous Space ownership / claim flow** | Unauthenticated entry point; ownership assignment bugs are high-impact and easy to prove |
| H6 | Public-link role restriction bypass (`editor` vs Contributor) | Documented restriction; binary result |
| H1/H2/H3 | XPIA delivery, cross-tenant retrieval, artifact pipelines | Need the Phase 0 sink probes first |

**No account has been created yet.** Nothing above required one — which is itself the useful
result: two new hypotheses came out of static assets alone.
