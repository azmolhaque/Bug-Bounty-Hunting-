# Looker Studio H3 — cross-tenant IDOR on report / datasource objects

**Target:** `lookerstudio.google.com` (Google VRP, IN-SCOPE, verified 2026-07-10).
**Class:** Broken object-level authorization (BOLA/IDOR) on the internal RPC API.
**Rig:** laptop + Chrome DevTools. Two Google accounts, already set up:
- **A** = `kaseym484@gmail.com`
- **B** = `azmolhaque95@gmail.com`

**Why this one:** the single report in this portfolio that drew P2 and is being taken seriously
(Looker XFF allowlist bypass) is a *control bypass proven by a differential* — not the hygiene
class. H3 has the same shape: either B's session returns A's private object, or it doesn't.
There is no informative middle state to mistake for success.

---

## The boundary that must be crossed (FO-9)

A finding exists **only** if:

> **B's authenticated session, sent to Looker Studio's internal API with the object ID of a
> report or data source that A has NEVER shared with B, returns A's content** — the canary
> string, field names, or rows that exist only inside A's object.

**Not a finding:** the endpoint existing; object IDs being UUIDs; an inconsistent 403; an error
that differs in wording; metadata with no content. Those are preconditions (FO-8/9/11), and they
are exactly what closed VT, AppSheet, Wiz F001 and Photomath.

---

## PHASE 0 — build clean objects and prove the boundary

⚠️ **Do not reuse the H1 objects.** A's report `68285b28-…` was *shared with B* during the H1
test, so B legitimately has access — it cannot demonstrate anything. Start fresh.

1. **As A**, create a **new report**, never shared with anyone:
   - Data source: a new private Sheet `ls-h3-src-<canary>` with header `secret` and a row
     containing `H3SECRET-<canary>`
   - Name the report `ls-h3-private-<canary>`
   - **Do not open the Share dialog at all**
   - Record its **report ID** from the URL (`/reporting/<REPORT_ID>/page/…`)
2. **As B**, create a **separate** report on B's own Sheet, so B has a legitimate object of the
   same type. Record **B's report ID**.
3. Fresh canaries, ≥8 chars, random, no English words. Keep out of git.

### The three gates — screenshot each

| Gate | Test | Expected |
|---|---|---|
| **0A — boundary exists** | B opens A's report URL in the browser | *"Can't access report"* / access denied, **with B's email visible in frame** |
| **0B — query shape valid** | B's session + **B's own** report ID via the internal API | **200 + B's data** — proves the request is well-formed, so a later 403 means *authz*, not a malformed call |
| **0C — catch-all control (FO-2)** | B's session + a **garbage** ID (`00000000-0000-0000-0000-000000000000`) | should error. If garbage returns 200 with content, the API is a catch-all and every "hit" is a false positive — **stop and re-baseline** |

Gate 0B is the one people skip and it is the one that makes the negative meaningful.

---

## PHASE 1 — capture the internal API shape (as B)

Looker Studio's SPA talks over `batchexecute`-style RPC, not a clean REST API. Capture a real
request rather than hand-writing one.

1. In **B's** browser, open B's own report. **DevTools → Network → Fetch/XHR**
2. Filter for `batchexecute` / `datastudio` / `reporting`
3. Interact (reload the report, refresh data, open the data-source panel) to generate traffic
4. Find a request whose **response body contains B's canary or field names** — that is the
   object-read call. This is the one that matters.
5. **Copy as cURL** (right-click → Copy → Copy as cURL). Do not retype it.
6. Locate **B's report ID inside the request body** — that is the single parameter we will swap.

> Cookie-authenticated, so the copied cURL carries B's session. If you start getting redirects
> to a login page, the session expired — **re-capture. A login redirect is not a negative
> result.**

---

## PHASE 2 — the decisive swap

Take the working cURL from Phase 1 and change **one thing**: B's report ID → **A's** report ID.
Nothing else. Same cookies, same headers, same body structure.

```bash
# B's session, A's private object ID
curl -s -i '<PASTED-URL-FROM-DEVTOOLS>' \
  -H 'Cookie: <B-SESSION-COOKIES>' \
  ... \
  --data-raw '<BODY WITH A_REPORT_ID SUBSTITUTED>' | tee /tmp/h3-cross.txt

grep -c 'H3SECRET-<canary>' /tmp/h3-cross.txt
```

### Reading the result

| Response | Meaning | Action |
|---|---|---|
| **200 containing `H3SECRET-<canary>`** | **CONFIRMED cross-tenant read.** B holds data from an object A never shared | **Stop. Collect evidence.** |
| 200 with A's **field/column names** but no rows | Partial — metadata only. **Not submittable alone** (schema enumeration without record access is on the Hard Rejection List, cf. Salesforce "873 fields" → N/A). Note it, keep testing object types |
| 403 / 401 / error / empty | Correctly isolated | Log the negative, move to the next object type |
| Login redirect | Session expired — **not a result.** Re-capture |
| Garbage ID also returns 200 + content | Catch-all → all hits invalid (FO-2) | Re-baseline |

**The proof is the canary, not the status code.** A 200 whose body contains a string that exists
only inside A's object is unambiguous. A 200 with an empty payload is not a finding.

### Object types to try, highest impact first
1. **Data source** object ID (carries the connection config — highest value)
2. **Report** object ID
3. **Embed / share** object ID, if the app exposes one
4. Any **explore / query** endpoint that takes an object ID directly

---

## Drop conditions — state plainly, do not force

- Every object type returns 403/error across accounts → **isolated. H3 is dead.** Log it, move on.
- Only field names / metadata cross, no record data → **not submittable** on its own.
- The "cross" turns out to involve an object A shared with B at some point → **void, not negative.**
- Behaviour matches documented Looker Studio sharing/embed features → intended (Quality Bar #2).
  **Read the docs before writing anything.**

---

## Evidence checklist (CLAUDE.md §9.8 — complete BEFORE any submit)

- [ ] 0A screenshot: B denied on A's report **with B's email in frame**
- [ ] 0B: B's session reading B's own object → 200 + data (query shape valid)
- [ ] 0C: garbage-ID control response recorded
- [ ] Date/time + external IP (`curl ifconfig.me`)
- [ ] **The decisive request and response verbatim**, with **A's canary visible in B's response**
- [ ] HTTP status + response size
- [ ] Differential: expected (403/isolated) vs observed (200 + A's data)
- [ ] Both accounts are ours; **no third-party object ID was ever requested**
- [ ] Session cookies **redacted** in the report
- [ ] First-person plain voice, real terminal output (FO-10)

---

## Safety

- **Read-only.** No mutations against A's objects from B's session, even if they appear possible.
  Reading proves the isolation break; writing is destructive testing on a live multi-tenant service.
- **Only ever use object IDs from our own two accounts.** Never enumerate or guess IDs — a guessed
  UUID could belong to a real user, and reading a stranger's report is a live data breach, not a
  lab result.
- If any response contains data belonging to a **third party**: stop, do not save it, and report
  that fact immediately.
