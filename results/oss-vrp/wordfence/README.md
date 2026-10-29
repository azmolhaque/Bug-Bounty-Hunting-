# Wordfence — closed. Do not submit either report here.

Read the programme's own terms on 2026-10-30, from the pages themselves rather
than from search results. **Both findings are out of scope, and Wordfence will
not even assign a CVE.** Three independent disqualifications, any one of which
is enough:

### 1. The asset is excluded

The Out-Of-Scope Asset List names, verbatim:

> **All Google Products**
> Bug Bounty Program: `https://bughunters.google.com/`
> Software: `https://profiles.wordpress.org/google/`

Site Kit is published from that profile. The rule behind it is stated plainly:
*"Software, services, and developers that maintain a publicly published bug
bounty or responsible disclosure program, managed directly by the developer,
are considered out-of-scope."* Google runs its own, so its plugins are theirs to
receive.

### 2. Both vulnerability classes are excluded by name

From "Explicitly Out of Scope Vulnerabilities":

* **Cross-Site Request Forgery** — finding 02 is exactly this.
* **Missing Authorization** — finding 01 is exactly this.

### 3. Finding 01's privilege level is excluded twice over

* *"Any Vulnerability requiring mid-level authentication to exploit. This
  includes **Contributor** and Author roles, along with any other role that
  needs to be granted by an administrator (i.e. not a common default
  registration role)."*
* *"Vulnerabilities that can only be exploited by an administrator explicitly
  granting access to a lower-privileged user where the likelihood of an
  administrator granting access is minimal or the administrator is granting
  access to functionality and features that can be abused."* — Dashboard
  Sharing is precisely that.

### And there is no CVE-only consolation

> *"We no longer assign CVE IDs to any vulnerabilities found in the out of scope
> list above and they will not be eligible for a bounty through our bug bounty
> program."*

The Terms do open a separate door for independent researchers — *"Independent
Researchers do not need to participate in the Program in order to report
Vulnerabilities to Company or request a CVE ID"* — and the submission form is
in any case gated ("Vulnerability submissions are currently limited to approved
researchers"). But the sentence above closes that door for anything on the
out-of-scope list, which both of these are.

### What submitting anyway would cost

Out-of-scope submissions count against the researcher, and this account is a
New Researcher: five out-of-scope reports in seven days restricts submissions,
ten blocks them, and thirty can mean a permanent ban. Two reports with no
possible reward and no possible CVE, spent on the throttle ladder, for nothing.

---

## How this recommendation was wrong

I proposed Wordfence on 2026-10-30 without having read these terms —
`wordfence.com` is outside this session's allowed domains, so I reasoned from
search snippets plus the fact that Wordfence had scored CVE-2026-10753. That
inference does not hold: Wordfence scores every WordPress vulnerability that
reaches its database whatever the source, which says nothing about whether it
accepts submissions for that software. The terms were the authority and I
should have treated the gap as a blocker rather than reasoning around it.

Worth keeping as a rule: for any new platform, read its out-of-scope asset list
and its out-of-scope vulnerability class list **before** writing the report, not
after.

## What the two files here are still good for

`01-missing-authorization.md` and `02-csrf-module-activation.md` are accurate,
source-verified write-ups — every specific in them was checked against
`8cf47de` on 2026-10-30, and five errors from the earlier drafts were corrected
in the process. They remain the basis for upstream disclosure, which is the
remaining route for these two findings and which Google's own closing comment
invited:

> *"You can report this directly by opening a public GitHub issue on the Site
> Kit repository."*

The better first door is the channel `SECURITY.md` names, since both issues are
unfixed. No money either way; a fix and a credit, and Google is its own CNA if
it chooses to assign.

See `results/google/MVRP-DECISIONS.md`, 2026-10-30, for where the paying work
actually is.
