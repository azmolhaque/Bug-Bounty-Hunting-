# Target filter, rewritten after four programs ended the same way

**Date:** 2026-10-08. Written after Tesla, Marriott, Shopify and Google all stopped at the same step.

---

## The pattern, stated plainly

```
Tesla T04       needed a customer's InstallationGUID
Marriott M025   needed a real confirmation number
Shopify         20 surfaces, tenant boundary sound, nothing a free account could cross
Google/Fitbit   credential found, but every grant still needed the victim's own secret
```

Four different programs. **One shared cause: there was no boundary a free account could reach
across.** The method was never the problem — twenty-three surfaces were closed with controls and
sentinels, and ten false findings were caught before they became reports. The target selection was
the problem, every time.

## What actually has to be true

The old four criteria were right but incomplete, and in the wrong order. Cheapest signal first — the
expensive lesson of 2026-10-07, when liveness was checked before access model and a dead product and
a paid allowlist were both discovered last.

```
1. Program age under ~18 months          one glance. Old programs have no easy classes left.
2. Pays money, not points or swag        one glance.
3. Free self-serve signup, no sales call one page load. This killed signals.area120.com.
4. USERS SHARE THINGS WITH OTHER USERS   <-- the new one, and the one that decides everything
5. We mint the object ids ourselves      so no identifier wall (Tesla, Marriott)
6. Impact lands on the target's own data not a third party's quota (Tesla F001)
```

### Why 4 is the one that matters

A cross-user vulnerability needs a cross-user boundary. If a product has no feature where one user's
data reaches another user, there is no boundary to break, and IDOR, broken access control and
privilege escalation are all unreachable no matter how good the testing is.

Fitbit has essentially no user-to-user sharing. Neither did Signals. Shopify's sharing is between a
merchant and their own staff, which is why the staff-role surface was the only promising one there —
and it held.

**Ask of any candidate: "what does one user hand to another user?"** If the answer is nothing, walk
away before creating an account.

## Product shapes that pass criterion 4

```
collaboration / workspaces      documents, boards, projects shared by link or invite
comments and mentions           one user's text rendered in another user's view
file sharing                    uploads served to other accounts
team / org / seat models        roles, permissions, invitations, guest access
public profiles and feeds       content authored by one account, displayed to others
marketplaces                    buyer and seller as separate tenants on one object
calendars and scheduling        invitations crossing account boundaries
support desks                   requester, agent and end-user as distinct roles
```

Anything with **invitations, roles, or shared links** is worth a look. Anything that is a
single-user data silo is not, however big the company.

## Where to look, in order

```
Intigriti   app.intigriti.com/programs    -> sort by newest. European, far thinner crowds
                                             than HackerOne for comparable payouts.
Bugcrowd    bugcrowd.com/engagements      -> filter: Bug Bounty + Public. Check "Managed by
                                             Bugcrowd" and the payout range on the card.
HackerOne   hackerone.com/directory/programs
                                          -> filter Bounty + Public, sort by launch date.
                                             Read "Average bounty" and "Reports resolved":
                                             few resolved + recent launch = untrodden.
```

### The thirty-second check per candidate

```
age < 18 months?            no  -> next
pays money?                 no  -> next
free signup, no sales call? no  -> next
users share with users?     no  -> next   <-- most candidates die here, and that is the point
```

Four glances. No account, no scanning, no tooling. Only a candidate that survives all four is worth
creating an account for.

## What to carry forward unchanged

The method is not the thing to change. Keep every bit of it:

- positive control, negative baseline, **sentinel** before believing any result
- a canary path or hostname on every target, because blanket rules look like findings
- print variable lengths before using them; three runs were silently invalidated without it
- build the control INTO the scanner, so a broken scanner announces itself
- ask "what does the attacker actually GET?" before investing hours, not after
- state limits as tested bounds rather than leaving them implied

That discipline caught ten would-be findings in two days, three of them caused by my own tooling. It
is the reason nothing weak was submitted.
