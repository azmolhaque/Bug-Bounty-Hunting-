# Adobe — test accounts

**No passwords in this file, ever** (CLAUDE.md §7). Credentials live in the operator's Google Keep.

| Role | Adobe e-mail | Display name | Purpose |
|---|---|---|---|
| **A** — victim / owner | `azmolhaque95@wearehackerone.com` | Tester H1 | Owns documents and Spaces. The account impact is demonstrated *against* |
| **B** — attacker / collaborator | `azmolhaque95+b@wearehackerone.com` | Tester H1b | Low-privilege collaborator; second tenant for cross-account tests |

Both created 2026-08-27. HackerOne handle: **`azmolhaque95`**.

## Eligibility

Adobe requires accounts registered with the HackerOne alias:
*"DO use HackerOne's email aliases feature `[username]@wearehackerone.com` when registering your
account… This is a required step to be eligible for bounty."*

**Plus-addressing works on the alias** — `azmolhaque95+b@wearehackerone.com` receives mail and
verified successfully. So **both** accounts are bounty-eligible, not just A. Worth reusing on any
future programme that mandates a platform alias but needs multiple test identities.

### ⚠️ Forwarded mail lands in Gmail Spam by default

Mail arrives from `mail-forwarder@wearehackerone.com` (Reply-To preserved) and Gmail classified
it as spam on first delivery. **Fixed** with a filter on
`from:mail-forwarder@wearehackerone.com` → *Never send it to Spam*.

**Why this matters beyond convenience.** H7a's whole proof is *"the document arrived at an address
we control."* A spam-filtered notification would read as "the attack was blocked" when it in fact
succeeded — a false negative indistinguishable from a real one. Same failure mode as the Gemini
campaign, where we could not separate "defended" from "never delivered."

Apply the same filter to Adobe's senders before H7a, and **check Spam before recording any
negative result that depends on receiving mail.**

### Exfiltration target ≠ account address

Adobe's alias requirement covers **account registration** only — *"when registering your account"*.
The recipient inside a test can be any address we own. For H7a use a **plain Gmail address**
(e.g. `azmolhaque95+adobeexfil@gmail.com`) so delivery is direct and unambiguous, with no
forwarder in the path to muddy a negative.

## Operating rules

- **Separate browser profiles** for A and B — or one normal window and one private window. A
  shared cookie jar silently signs one account out and turns a "cross-account" result into an
  artefact of using the same session twice.
- **Confirm which identity you are** before every decisive request: check the avatar/profile,
  screenshot it, and include that frame in evidence. The Exoscale lesson — an entire batch of
  results was run against the wrong key before the `key=` fingerprint caught it.
- **Testing IP: `180.148.212.32`** — Adobe requires it for bounty payment and Safe Harbour
  coverage. Same network for everything; re-check with `curl ifconfig.me` each session.
- Every asset identifier used must come from **A's or B's own account**. Never guessed,
  never enumerated (FO-14).

## Canary discipline

Each document carries a unique marker so a cross-account read is unambiguous:

```
A's docs:  A-<canary>-<n>
B's docs:  B-<canary>-<n>
```

8 random lowercase alphanumerics, no dictionary words, fresh per run, kept out of git.
