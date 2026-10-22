# Acquisitions — hunting log

### 2026-10-22 — first sweep over the acquisition tiers

Built the target set from Google's own tier protobuf after finding that
scope.yaml, the hand-maintained list, was missing 84 of the 195 TIER0/TIER1
hosts. Phase 1 (liveness) then found 55 answering hosts, up from 35.

Phase 2 probed twelve login/administration paths per host against a
per-host baseline from a path that cannot exist. Twenty hosts answered
differently somewhere. Most of the differences were hollow — a SPA returning
the same shell for every path, or a 404 body whose length changes because it
echoes the path.

Two leads looked real and both closed:

**looker-opensource-components.looker.com** — an S3 bucket behind CloudFront,
serving under a TIER1 hostname, with public object listing. Dropped: all 43
objects are open-source dependencies (jersey, junit, mariadb-java-client,
jruby, certifi) plus an index.html. Nothing sensitive, so the listing is the
informational class. Write access would have changed that — a bucket serving
components under looker.com is a supply-chain surface — but CloudFront sits in
front and swallows query strings (?acl returned the cached listing, Age 841),
and the S3 REST endpoint is not a hostname in scope. Not testable in scope,
and not worth reporting on what is testable.

**feed-moderation.fitbit.com** — an Ember moderation console that serves its
shell unauthenticated. Its CSP named the backend:
feed-moderation.site-ops.fitbit.com. That host is OUT-OF-SCOPE under both
scope files, so it was not touched. The console shell on its own proves
nothing; the API behind it is where an answer would be, and that API is off
limits.

Parked with reasons, not pursued:
- www.pring.jp/admin returns 401 where everything else is 404. An admin panel
  behind HTTP auth on a money-transfer product. Guessing credentials there is
  not a line worth stepping over, and a 401 alone is not reportable.
- advantage.mandiant.com answers every path with the same 58203-byte shell.
- myaccount.nest.com and friends: 404s whose length varies with the path.

No finding today from this axis.
