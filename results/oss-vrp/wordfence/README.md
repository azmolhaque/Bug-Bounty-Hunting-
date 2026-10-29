# Wordfence Bug Bounty — the two Site Kit findings, re-aimed

Both findings were built for Google's OSS VRP. That channel closed under us:
Google paused OSS VRP product-vulnerability intake on 2026-10-01, and report 01
came back `Won't fix (Infeasible)` on 2026-10-30 for that reason and no other —
the technical question was never reached. Report 02 was held rather than filed
into the same wall. See `results/google/MVRP-DECISIONS.md`, 2026-10-30.

Wordfence is the re-aim. Site Kit has 3M+ active installations, and Wordfence
already triages this plugin — they scored CVE-2026-10753 at 2.7.

    01-missing-authorization.md     send first
    02-csrf-module-activation.md    send second

01 first: it carries the stronger precedent, because the vendor fixed the same
pattern under CVE-2026-10753 and the Site Goals datapoints reintroduce it.

## Check these on the phone before submitting

I could not reach `wordfence.com` or `patchstack.com` from the session —
outbound DNS for both is outside the allowed domains — so the current intake
rules are unverified by me. Three things to confirm on their site:

1. **Eligibility for a 3M-install plugin.** Wordfence gates which software a
   researcher may submit for by researcher tier. If Site Kit is above your
   current tier, the submission will bounce; check before writing it up.
2. **Both at once, or one at a time.** Some programmes queue per researcher.
3. **Their own vulnerability database for Site Kit**, as a last dedup pass.
   What we already know is in the reports: CVE-2026-62139 is a CSRF in a
   *different* function, and CVE-2026-10753 is the authz pattern this one
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
