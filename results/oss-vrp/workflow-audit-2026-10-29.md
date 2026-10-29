# OSS VRP — GitHub Actions audit across the OT0 repositories

2026-10-29. 153 workflow files, 13 of the 26 OT0 repositories (tink-java has
no workflows; the rest of OT0 is fuchsia, go, bazel and friends, included).

Why this class. Google's OSS VRP pays for supply-chain compromise, and a
workflow with a privileged trigger that runs attacker-controlled code is
exactly that: one pull request or one comment, and you hold a token with write
access to a repository the world depends on. Workflows also get less review
than code, which is the only reason a careful reader can still beat a scanner
here.

## What was looked for

* `pull_request_target`, `workflow_run`, `issue_comment` — triggers that run
  with the base repository's secrets rather than the fork's
* any of those combined with `actions/checkout` of an attacker-controlled ref
* `${{ github.event.* }}` interpolated into a `run:` block rather than passed
  through `env:`

## What was found

29 workflows use `pull_request_target`, 3 use `workflow_run`, 4 trigger on
`issue_comment`. Four of them put attacker-controlled input somewhere that
matters. All four are guarded, and the guards were read rather than assumed:

**`bazelbuild/bazel-central-registry` — `update_requirements.yml`**
`pull_request_target` + `checkout ref: ${{ github.head_ref }}` +
`token: secrets.BCR_PR_REVIEW_HELPER_TOKEN`, then `bazel run
//tools:requirements.update`, which executes BUILD files from the checked-out
tree. The job-level `if` requires `github.event.pull_request.user.login ==
'dependabot[bot]'`. Dependabot pushes its branches to the repository itself
rather than to a fork, so the tree is not attacker-controlled, and the login
cannot be spoofed (GitHub does not allow brackets in usernames). Holds —
though it is one deleted line away from arbitrary code execution with a token
that can push to the registry.

**`angular/angular` — `benchmark-compare.yml`**
`issue_comment` + checkout of the commenter's PR head, which is attacker code
by construction, followed by `pnpm install` and a Bazel run. The first step is
`TheModdingInquisition/actions-team-membership` pinned to a commit, with
`exit: true`. Its source at that commit wraps everything in a try/catch whose
handler calls `core.setFailed`, and a non-member also reaches `setFailed`, so
it **fails closed**: an API error or a missing permission fails the job rather
than letting the checkout proceed. The workflow carries
`permissions: read-all`, pins every action to a SHA, and passes
`github.event.comment.body` through `env:` with a comment explaining why.
Holds.

**`bazelbuild/bazel` — `cherry-picker.yml`** and **`flutter/flutter`
revert.yml / easy-cp.yml** pass issue titles, bodies and PR titles into steps,
but through `env:` and into actions rather than into shell. `revert.yml` and
`easy-cp.yml` check out `master`, not the PR. Hold.

## The one real gap, and why it is not reportable

`bazelbuild/bazel-central-registry` — `skip_check.yml` triggers on
`issue_comment` with the only condition being
`startsWith(github.event.comment.body, '@bazel-io skip_check ')`, and the
action it runs, `bcr-pr-reviewer`'s `runSkipCheck`, **never looks at who
commented**. Any GitHub account can therefore add one of three labels to any
BCR pull request:

    @bazel-io skip_check unstable_url        -> skip-url-stability-check
    @bazel-io skip_check compatibility_level -> skip-compatibility-level-check
    @bazel-io skip_check incompatible_flags  -> skip-incompatible-flags-test

The asymmetry inside the same file is what made this worth chasing: the
neighbouring `handleReviewCommand` carries an explicit comment reasoning about
why anyone may trigger it, and `runSkipCheck` has neither reasoning nor check.

Followed through to the end, in `bazelbuild/continuous-integration`:
`bcr_presubmit.py` reads the labels from `BUILDKITE_PULL_REQUEST_LABELS` and
turns them into `--skip_validation=` flags for `//tools:bcr_validation`, and
`should_wait_bcr_maintainer_review()` decides whether to insert the Buildkite
block step *"Wait on BCR maintainer review"*. So the shape of the thing is: an
unauthenticated comment reaching into a supply-chain review gate.

It stops short on two facts, both checked:

1. The block step comes from `NEED_BCR_MAINTAINER_REVIEW` (exit 42), and the
   only two sites that return it are in `verify_presubmit_yml_change` — a new
   module, or a presubmit.yml that differs too much. That validation is
   skipped by `--skip_validation=presubmit_yml`, which is added for
   `PRESUBMIT_AUTO_RUN_LABELS = {"presubmit-auto-run", "CI:run"}`. **Neither
   label is settable through the comment.** The three that are settable report
   `FAILED`, not `NEED_REVIEW`, so skipping them clears a hard CI failure and
   does not remove a human gate.
2. The escape hatch is documented, by the failure message itself:
   "please add a comment to your BCR PR with the text `@bazel-io skip_check
   unstable_url` and this check will be skipped." § 2 criterion 2 asks whether
   the vendor's own design explains the behaviour. Here it is printed in the
   error text.

Integrity is unaffected either way: `verify_source_archive_url_integrity` is a
separate validation and is not skippable, and module maintainers are read from
`ref: 'main'` with the immutable numeric `github_user_id`, so a submitter
cannot declare themselves maintainer in their own pull request.

**Dropped.** What an attacker gets is a reliability check skipped on somebody
else's pull request, through the mechanism the maintainers advertise for
exactly that. Worth one sentence to the project as a hardening note if we ever
have another reason to write to them, and not worth a VRP report.

Closed: the OT0 workflow surface.
