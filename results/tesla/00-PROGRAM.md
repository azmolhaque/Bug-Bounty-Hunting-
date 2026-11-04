# Tesla — Bugcrowd, program card

Read from the brief on 2026-10-04. Everything below is quoted or derived from the page,
not remembered.

## The numbers

```
Started            Aug 04, 2015
Vulnerabilities    983 rewarded
Validation         75% of submissions resolved within 4 days (last 3 months)
Average payout     $1,312.24 (last 3 months, skewed by vehicle targets)
Researchers        528 recently joined this engagement
Scope rating       4 / 4
Safe harbor        partial
```

**Web (non-vehicle) reward chart — this is the realistic tier:**

```
P1  $3,000 – 10,000     P2  $500 – 4,000     P3  $200 – 700     P4  $100     P5  $0
```

Vehicle targets pay $20k–$100k and need a car we do not have. Energy hardware needs a Powerwall.
Both also require hardware research registration. **Not available — do not plan around them.**

## Evidence the web side is live right now

```
2 Oct 2026   $500   accepted on *.tesla.com
1 Oct 2026   $700   accepted on *.tesla.cn
30 Sep 2026  accepted (private)
```

Three accepted web submissions in the last week. This is the reason to look at all.

## Scope

| Target | Note |
|---|---|
| `*.tesla.com` | tagged Varnish +3. The most-hunted surface on the list |
| `*.tesla.cn` | tagged Akamai, Cloudflare, **Drupal** +5. A $700 accept on 1 Oct |
| `*.tesla.services` | tagged only "Website Testing" — no CDN, no known issues listed |
| `*.teslamotors.com` | legacy brand domain |
| `*.solarcity.com` | 2016 acquisition |
| `*.teslainsuranceservices.com` | separate business line |
| Official iOS / Android apps | mobile |
| "Any host verified to be owned by Tesla Motors Inc. (domains/IP space/etc.)" | open-ended — rewards recon |

**Focus area, verbatim:** *"Tesla's public facing web applications"* and *"Vulnerabilities in other
applications owned by Tesla"*.

## Out of scope — hosts

```
employeefeedback.tesla.com      energysupport.tesla.com      engage.tesla.com
*.engage.tesla.com              feedback.tesla.com           feedback.teslamotors.com
ir.tesla.com                    ir.teslamotors.com           mkto.teslamotors.com
shop.eu.teslamotors.com         service.tesla.com/docs/*     service.tesla.cn/docs/*
Any domains from acquisitions, such as maxwell.com
Any other third-party websites hosted by non-Tesla entities
Superchargers and related infrastructure
```

## Out of scope — classes

This list is, almost line for line, our own Hard Rejection List. It is quoted here so no time is
wasted rediscovering it:

WAF bypass · open redirects / missing interstitial · internal IP disclosure · accessible
**non-sensitive** files and directories (README.TXT, CHANGES.TXT, robots.txt, .gitignore, WSDL,
pprof) · social engineering · self-XSS · text injection · email spoofing (SPF/DKIM/DMARC) ·
descriptive errors and stack traces and path disclosure · fingerprinting / banner disclosure ·
clickjacking · CSRF that does not affect account integrity · missing Secure / HttpOnly flags ·
lack of rate limiting · login brute force / lockout / password strength · HTTPS mixed content ·
username / e-mail enumeration by brute force or error messages · missing security headers ·
TLS/SSL issues · DoS · out-of-date software · known-vulnerable component without proof of
exploitation · physical attacks · relay / RollJam · Autopilot environment modification ·
**Tesla account MFA issues**

## What that leaves — and one explicit hint

Not excluded, therefore in play: **broken access control / IDOR**, XSS that is not self-XSS,
SSRF, injection, exposure of **sensitive** files or data, subdomain takeover, and authentication
logic.

And one line in the brief points straight at a class:

> *"Username / email enumeration by brute forcing / error messages ... **Exceptional cases may
> still be in scope (e.g. ability to enumerate email addresses via incrementing a numeric
> parameter)**"*

They reject enumeration by brute force but **accept it when it is driven by an incrementing
numeric parameter** — which is an IDOR in everything but name. That is the operator's strongest
class after Personio.

## Rules of engagement, enforced in our scripts

- **No brute force, no DoS** without prior written approval — so: single-threaded, 0.5s between
  requests, GET only during recon, no wordlist fuzzing of paths.
- **Do not access or modify data that is not ours.** If another customer's data ever comes back,
  stop immediately and contact Tesla before anything else. No post-exploitation.
- Tesla may order testing stopped at any time; comply immediately.
- Accounts must be registered with **`<username>@bugcrowdninja.com`**.
- Do not spam order / contact forms.
- **Identity verification on Bugcrowd is required before any submission can be filed.** Do this
  before testing, not after finding something.

## Strategy

`tesla.com` has been hunted since 2015 by, on current numbers, hundreds of researchers. Starting
there repeats the Personio error — picking the surface everyone else already swept.

The ranking for a solo researcher with a terminal is by **neglect**, not by size:

1. `*.tesla.services` — no CDN tag, no known-issue tags. Small and unglamorous.
2. `*.solarcity.com` — a 2016 acquisition; acquisitions are where forgotten infrastructure lives.
3. `*.teslainsuranceservices.com` — separate business, separate team, fewer eyes.
4. `*.tesla.cn` — a $700 accept on 1 Oct; language and geography keep most researchers away.
5. `*.teslamotors.com` — legacy brand.
6. `*.tesla.com` — last, and only on hosts that are not the marketing site.
