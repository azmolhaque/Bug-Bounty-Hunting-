# Draft — scope disclosure for issue 509911655 (Looker XFF IP-allowlist bypass)

**Status: CONFIRMED — SEND.** Operator confirmed 2026-08-25 that the tenant was
**discovered via subdomain enumeration of `cloud.looker.com`**, not provisioned by us.
Combined with the absent provisioning email, the "locate a Looker tenant" repro wording, the
non-admin block page, and live dedicated eu-west-1 infrastructure 3.5 months on, ownership is
settled. `DRAFT-509911655-status-ping.md` is now VOID — do not send it.

**Root cause of the error:** `*.looker.com` is in the scope file, so subdomain enumeration
returned this host alongside genuine Google assets. Enumeration output does not distinguish
"vendor infrastructure" from "a customer's private tenant" — they are indistinguishable
hostnames. The scope file governs which *product* may be tested, never whose *tenant* the
data belongs to. See FO-14.

---

## Why this is the right action

Evidence that `09a2ceda-8736-4308-941f-1fa63a87f960.cloud.looker.com` is a third party's tenant:

| Signal | Finding |
|---|---|
| Gmail search `09a2ceda` | Only hit is our own buganizer thread. **No provisioning email.** |
| Gmail search `looker instance provisioned` | Nothing relevant |
| Our own report's repro step | *"**Locate** a Looker tenant with an active IP Allowlist"* — found, not provisioned |
| The block page seen | *"contact your **Looker admin**"* — the message shown to non-admins |
| DNS (passive) | CNAME → dedicated AWS ELB `…eu-west-1.elb.amazonaws.com`, **still live 3.5 months later** — a trial would have been deprovisioned |
| **Operator recollection (decisive)** | **Host was found by subdomain enumeration of `cloud.looker.com`** — i.e. discovered, never provisioned |

**What was accessed on that instance:** the `/login` response (200, with session cookies issued
to us), and `/api/4.0/swagger.json` (~1021 KB of live API schema). Both were attached to the
VRP report, so Google already holds them.

**The vulnerability itself remains legitimate.** `cloud.looker.com` is Google-operated, and an
ingress trusting client-supplied `X-Forwarded-For` for access-control decisions is a real flaw
in Google's product. The error is the **test target**, not the finding: it was demonstrated
against a customer's live instance instead of one we control. VRP rules require testing against
your own accounts/instances.

Disclosing voluntarily is both the honest action and the lower-risk one — a P2 report sitting in
a queue where a triager may check tenant ownership themselves is a much worse discovery path.

---

## Draft comment

> Hi team,
>
> I need to correct the record on this report, proactively.
>
> While reviewing my own testing, I established that the instance I used to demonstrate this
> issue — `09a2ceda-8736-4308-941f-1fa63a87f960.cloud.looker.com` — was **not** an instance I
> provisioned or control, and I did not have authorization from its owner to test it. I had
> treated it as an in-scope Looker Cloud endpoint, but I should have demonstrated the behaviour
> against an instance of my own. That was my mistake.
>
> For your assessment, what I accessed on that instance was limited to: the `/login` response
> (HTTP 200, with session cookies issued to my request), and `/api/4.0/swagger.json`. Both are
> attached to this report. I have not shared them with anyone, have not used them for any
> further access, and I have deleted my local copies. I have sent no further traffic to that
> host and will not.
>
> The underlying issue I reported — the ingress accepting a client-supplied `X-Forwarded-For`
> value for IP-allowlist decisions — I still believe is worth evaluating, but it should be
> validated against a Google-controlled test instance rather than my PoC. I'm happy to re-run
> it against an instance you designate, or to withdraw the report entirely if you'd prefer.
>
> Apologies for the error, and please let me know how you'd like me to proceed.
>
> Md. Azmol Haque Rony

---

## Notes on the draft
- **First person, factual, no drama.** State the error, state what was touched, state what was
  done about it, offer the fix. No lengthy apology, no excuses.
- **Do not** argue the severity or ask about a reward in this comment. This is not the moment.
- **Only claim what is true.** Before sending, actually delete the local PoC artifacts
  (`looker_poc_schema_disclosure.txt`, `looker_poc_ui_exposure.txt`, the jpeg/mp4) so the
  sentence about deletion is accurate.
- Expect the report to be closed or withdrawn. That is the correct outcome and it is worth it.

## Lesson to carry into the methodology
**Test-target ownership is a Phase 0 gate, not an afterthought.** Before demonstrating any
finding against a hosted multi-tenant product, prove the instance is ours — a provisioning
record, an admin login, a console entry. "It's an in-scope domain" is not the same as "this
tenant is mine." The scope file governs *which product* may be tested; it says nothing about
*whose tenant* the data belongs to.
