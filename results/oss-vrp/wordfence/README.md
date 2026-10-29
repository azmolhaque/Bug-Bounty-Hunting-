# Wordfence Bug Bounty — the two Site Kit findings, re-aimed

Both findings were built for Google's OSS VRP. That channel closed under us:
Google paused OSS VRP product-vulnerability intake on 2026-10-01, and report 01
came back `Won't fix (Infeasible)` on 2026-10-30 for that reason and no other —
the technical question was never reached. Report 02 was held rather than filed
into the same wall. See `results/google/MVRP-DECISIONS.md`, 2026-10-30.

Wordfence is the re-aim. Site Kit has 3M+ active installations, and Wordfence
already triages this plugin — they scored CVE-2026-10753 at 2.7.

    02-csrf-module-activation.md    send FIRST
    01-missing-authorization.md     send second, with the declaration intact

**The order changed, and the reason is Wordfence's own terms:** *"the
Vulnerability must not be previously disclosed elsewhere to qualify for a
reward."*

* **02 has never been submitted anywhere.** It was written for Google's OSS VRP
  and deliberately not filed. It is unambiguously clean, so it goes first.
* **01 was filed to Google's OSS VRP** (issue 579506120, closed without the
  technical question being reached). Google is the vendor *and* runs a reward
  programme, so whether that counts as "disclosed elsewhere" is genuinely
  ambiguous — it is not public, and no assessment was made. That is Wordfence's
  call to make, not ours to quietly decide, which is why the disclosure-status
  section in 01 states it plainly. Expect it may be credit-only rather than
  rewarded.

On technical merit 01 is the stronger of the two — the vendor fixed the same
pattern under CVE-2026-10753 and the Site Goals datapoints reintroduce it — but
merit is not what decides the order here.

## Check these on the phone before submitting

I could not reach `wordfence.com` or `patchstack.com` from the session —
outbound DNS for both is outside the allowed domains — so the current intake
rules are unverified by me. Three things to confirm on their site:

1. **The exclusivity clause, read in full**, on
   `/threat-intel/bug-bounty-program/terms-and-conditions/` — specifically
   whether a submission to the vendor's own reward programme, closed without
   assessment and never made public, counts as "previously disclosed
   elsewhere". This decides whether 01 can be rewarded or is credit-only. If
   the terms are unclear, ask them before submitting 01; 02 is unaffected
   either way.
2. **Eligibility for a 3M-install plugin.** Wordfence gates which software a
   researcher may submit for by researcher tier. If Site Kit is above your
   current tier, the submission will bounce; check before writing it up.
3. **That 1.190.0 is still the current release.** Both reports state the
   affected range as ending at 1.190.0 "current at submission". If Site Kit has
   shipped since, re-check whether either issue is still present and update the
   range — a report that claims an affected range including a version that
   already fixed it is a fast rejection. `api.wordpress.org` is outside this
   session's allowed domains, so I could not confirm it from here.
4. **Both at once, or one at a time.** Some programmes queue per researcher.
5. **Their own vulnerability database for Site Kit**, as a last dedup pass.
   What we already know is in the reports: CVE-2026-62139 is a CSRF in a
   *different* function, and CVE-2026-10753 is the authz pattern 01
   reintroduces. Neither is ours.

## Exclusivity — this matters

Once either report is in the Wordfence queue:

* do **not** also submit it to Patchstack,
* do **not** open a public GitHub issue on `google/site-kit-wp` about it, even
  though Google's close invited exactly that,
* do **not** post the PoC anywhere public.

Wordfence coordinates with the vendor and assigns the CVE themselves, and
public disclosure or a parallel submission voids eligibility. If Wordfence
rejects a report, the public-issue route is still there afterwards.

## What to expect, honestly

Wordfence pays per validated submission rather than from a shared pool, which
suits two reports better than Patchstack's contribution-share model. The
amounts for this class are modest: their January 2026 monthly report shows 18
missing-authorization submissions totalling $1,240, about $69 each, and an
overall average of roughly $210 per submission. The ceiling they advertise
($31,200) is for RCE-class findings in popular plugins, not for these.

The real returns here are the CVE and the credit on two findings in a Google
plugin with 3M installs. Treat the money as incidental.

## What is in each file

Field-by-field for their intake form: software/slug/affected versions, title in
their advisory style, CWE, required privileges, CVSS 3.1 vector, description
with the code paths quoted, step-by-step PoC, the recorded terminal output, the
controls, suggested remediation, an explicit scope-of-claim section, the test
environment, and the disclosure status.

The disclosure-status section in each one states plainly that the finding went
to Google's OSS VRP, what came back, and why that is not a technical verdict.
Do not remove it — a programme that later finds an issue-tracker reference to a
report you did not mention has every reason to distrust the rest.

## Evidence that goes with them

    ../poc/evidence.txt          the 01 transcript
    ../poc/evidence-csrf.txt     the 02 transcript
    ../poc/poc.php               sets the lab site up
    ../poc/poc3.php              the 01 controlled comparison
    ../attachments/01-site-goals-authz/   bundle, if they want attachments
    ../attachments/02-golinks-csrf/       bundle, if they want attachments

The terminal screenshot already on the phone (`evidence-terminal.png`) is
labelled as a transcript rather than a live run, which is what
`scripts/show-sitekit-evidence.sh` prints on screen. Keep that label.
