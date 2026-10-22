# issuetracker.google.com — TIER0, cross-account testing

Tested with two accounts both belonging to the researcher: A
(azmolhaque95@, owner of issue 576322789) and B (cindrasec@, no access).
Nobody else's data was touched and no issue IDs were guessed.

### 2026-10-22 — authorization holds on all three surfaces tested

**Issue content.** B opening issuetracker.google.com/issues/576322789 gets
"Access is denied to this issue". Underneath: getIssue 403,
updates?currentTrackerId= 403, and the issue fetch itself 403.

**Access relations.** One request stood out because it returned 200 where
everything else returned 403:

    /action/user_access?relations=admin,writer,appender,reader
      &resourceNames=issues/576322789,...

That looked like it might name who can reach the issue — which for a VRP
report means the reporter and the Google engineers on it. It does not. The
body is the bare envelope:

    )]}'
    [["b.UserAccessBatchResponse"]]

No records. The 200 says the request was well-formed, not that anything was
returned. Worth noting as a pattern: a 200 among 403s is worth opening, and
usually turns out to be an empty envelope.

**Attachments.** The obvious gap on a tracker is files served from a separate
origin that does not re-check the issue ACL. It does re-check. The same URL,
three ways:

    A, the owner      200, file renders
    B, other account  403
    logged out        403

The path carries two long opaque tokens, which on some systems act as a
capability — have the link, have the file. Not here: the ACL is evaluated per
request and the token alone buys nothing.

No finding. Recording it so this ground is not dug twice.

Still untested on this host, in rough order of promise:
- search leakage: does a distinctive string from A's private issue surface to
  B through the IssueTracker search box or the Autocomplete endpoint
- hotlist and bookmark writes against an issue B cannot read
- retrieve_similar_issues, which returned 401 even for A
