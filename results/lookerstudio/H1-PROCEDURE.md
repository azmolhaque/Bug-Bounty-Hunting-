# Looker Studio H1 — Cross-tenant owner-credential retention on Copy ("Sticky Credential")

**Target:** `lookerstudio.google.com` (Google VRP, IN-SCOPE, confirmed 2026-07-10).
**Class:** Broken cross-tenant isolation via retained data-source credentials.
**Impact if confirmed:** account B reads account A's PRIVATE data (a Google Sheet /
BigQuery dataset B was never granted) by copying A's report and repointing the
data source, which still executes under A's retained credentials. High.
**Testability:** pure browser, two free Google accounts (A, B). No curl/proxy needed
for the core test.

---

## The boundary we must actually cross (FO-9)

This is only a finding if **B ends up looking at bytes B has no permission to read.**
The precondition (a copied report keeps working) is NOT the finding. The finding is:
after the copy, B **repoints** the data source to *another* private resource of A's
that B cannot open directly, and Looker Studio returns A's rows from it. If the copy
forces B to supply B's own credentials, or the repoint fails / returns B-only data,
it is **secure → drop it** (do not narrativize the retention alone as a bug).

We prove the cross using **A's OWN second private resource** as the victim data — so
no third party is ever touched, and "B can't access it" is verifiable by us.

---

## Canary design (so proof is unambiguous)

Two private Google Sheets owned by **A**, neither shared with B:

- **Sheet-A1 "ls-h1-report-source"** — the report is built on this.
  Row data (a column of cells): `A1CANARY-11111`, `A1CANARY-22222`.
- **Sheet-A2 "ls-h1-victim-secret"** — the resource B must NOT be able to read.
  Row data: `A2SECRET-90909`, `A2SECRET-80808`.

If B ever sees `A2SECRET-90909` inside Looker Studio, the cross-tenant read is proven.
(Pick fresh random-ish strings when you run; keep them out of git.)

---

## PHASE 0 — validity gate (FO-3). Do this FIRST, screenshot it.

Log in as **B** and try to open **Sheet-A2** directly by its URL.
Expected: **"You need access" / request-access page.** Screenshot it.
> This is the baseline that makes the whole test valid: it proves B genuinely
> cannot read A2 on its own. Without this screenshot, a later "B saw A2" is
> meaningless. If B CAN open A2 directly, stop — the sheet isn't actually private.

---

## PHASE 1 — Account A: build the owner-credentials report

1. As **A**, create the two private Sheets above. Do **not** share either with B.
2. `lookerstudio.google.com` → **Create → Data source → Google Sheets** → pick
   **Sheet-A1**. Connect.
3. On the data-source screen, set **Data credentials = Owner's credentials**
   (Resource → Data credentials → *Owner's credentials* → "viewers see data as owner").
   This is the setting the whole class depends on. Save.
4. **Create Report** from it; add a **Table** chart showing the A1 column so you see
   `A1CANARY-11111` render. Save.
5. Make the report reachable by B. Two sub-cases — test **both** if possible:
   - (a) **Share → Anyone with the link → Viewer**, then **allow "Make a copy"**
     (report Share settings → don't restrict download/copy); or
   - (b) **Share directly to B's email as Viewer**, copy allowed.
   Record the report URL.

---

## PHASE 2 — Account B: copy and test retention

6. Log in as **B**. Open A's report URL. Confirm it renders `A1CANARY-11111`
   (viewers-as-owner working — expected, not yet a bug).
7. **More (⋮) → Make a copy.** In the copy dialog Looker Studio lists the data
   source and asks how to map it. **Watch this dialog closely — it is the crux:**
   - If it **forces B to choose B's own Google Sheet / re-authorize** → likely
     secure (credential reset on copy). Note it; continue to step 8 to confirm.
   - If it lets B keep "Original data source" / copies without asking B to auth →
     retention suspected.
8. Open B's **copy**. Does the table still render `A1CANARY-11111` **without B ever
   authorizing A1**? Screenshot.
   - Renders → creds retained. Proceed to the decisive step 9.
   - Empty / "credentials needed" / asks B to log in as owner → secure so far.

---

## PHASE 3 — the decisive cross-tenant read (this is the finding or the drop)

9. In **B's copy**, edit the data source (Resource → Manage added data sources →
   **Edit**, or the field panel → data source → Edit). Attempt to **repoint** it to
   **Sheet-A2** — the victim secret B cannot open:
   - Google Sheets connector: change the selected spreadsheet/URL to Sheet-A2's URL,
     or change the range/tab to A2's tab if same-file tabs are the pivot.
   - If the connector won't take a raw URL, try: duplicate the data source inside the
     copy, or edit the underlying sheet id in the data-source config.
10. Refresh the table. **Decisive outcomes:**
    - Table shows **`A2SECRET-90909`** → **CONFIRMED cross-tenant read.** B just read
      A's private Sheet-A2 (which Phase 0 proved B cannot open) via A's retained
      owner credentials. Screenshot the rendered secret **and** the data-source config
      showing it points at A2. This is the report.
    - "Credentials needed" / access error / B is asked to authorize / only B-owned
      data works → **secure. Drop H1** (retention without repoint is not a bug; do not
      submit). Move to H2/H3.

---

## PHASE 4 — variant (only if step 9 is blocked but retention held at step 8)

If the Sheets connector pins the credential to the *specific* spreadsheet (so repoint
resets auth), retry the whole flow with a connector where the credential is broader
than one object:
- **BigQuery** owner-credentials data source (credential = A's BQ/project access, not
  one table). Repoint the copy's SQL/table to **another dataset A owns but B doesn't**.
  This matches Tenable TRA-2025 most closely and is higher impact — but needs A to have
  a GCP project with two datasets. Do this only if the free Sheets path is inconclusive.

---

## Evidence checklist (CLAUDE.md §9.8 — complete BEFORE any submit)

- [ ] Phase 0 screenshot: B gets "You need access" on Sheet-A2 (validity baseline)
- [ ] date/time + external IP (`curl ifconfig.me`) at test time
- [ ] Screenshot: B's copied report rendering `A2SECRET-90909`
- [ ] Screenshot: the copy's data-source config pointing at Sheet-A2
- [ ] The copy dialog behavior (did it reset creds or not) — screenshot
- [ ] Both accounts are ours (A, B); Sheet-A2 never shared with B; no third-party data
- [ ] before/after differential: expected (copy resets creds / B blocked) vs observed
- [ ] first-person, human-voice writeup — plain terminal/screens, no AI-report tells (FO-10)

## Drop conditions (say so honestly, do not force it)

- Copy flow forces B to supply B's own credentials → intended isolation, secure.
- Retention holds but repoint always re-auths / only serves B-owned data → not a
  cross-tenant read; retention alone is not submittable (FO-9/FO-11).
- Behavior matches Looker Studio documentation on "Owner's credentials + copy" →
  intended (Submission Quality Bar #2). Check the docs before writing anything.
