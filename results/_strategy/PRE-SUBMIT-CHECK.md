# Pre-submission check — run this before every report, without exception

Added 2026-10-08 after `571371934` closed Won't Fix in three minutes on a rule that was already
written down in `config/scope-google.yaml` and was never applied to the finding.

---

## The one question that closed it

**Does the attack require the attacker to already hold an identifier they cannot obtain or predict?**

```
a GUID            Tesla T04       parked
a booking number  Marriott M025   parked
a password        G-F001          parked
a token string    G-F002          SUBMITTED. Closed in three minutes.
```

If the answer is yes, the report closes however good the evidence is. An unguessable identifier is a
password, and needing one means the attack has no entry point.

**Ask it first. Before the controls, before the write-up, before the screenshots.**

## The rest of the check

```
1. Does the attack need an identifier the attacker cannot get?        -> STOP
2. What does the attacker GET, in one sentence?
   metadata / a hostname / a precondition / your own OOB hit          -> STOP
3. Is this on the program's published non-qualifying list?            -> STOP
4. Can the vendor say "that is our design"?
   Is there a sibling behaviour proving otherwise?       no           -> probably STOP
5. Would the vendor change code to fix it?               no           -> STOP
6. Have I argued the strongest objection AGAINST my own finding,
   in writing, before submitting?                        no           -> do it now
```

Point 6 is what caught the reCAPTCHA claim before submission. Point 1 is what nobody ran.

## The deeper error, stated plainly

Every technical claim in `571371934` was verified with a control and a sentinel. Ten false findings
were caught that way across two days. None of that discipline was ever pointed at the question of
whether the finding was **eligible**.

Verification discipline answers *"is this true?"*. It does not answer *"does this qualify?"*. They
are separate checks and the second one is cheaper, faster, and decides the outcome.
