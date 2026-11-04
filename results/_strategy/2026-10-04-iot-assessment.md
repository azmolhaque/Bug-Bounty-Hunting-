# Should we hunt IoT? — assessment, 2026-10-04

Prompted by the operator's Bugcrowd search: `category=bug_bounty&target_categories=iot,hardware`.

## The programmes on offer

| Programme | Range | Device needed to test anything? |
|---|---|---|
| Tesla | $100 – $100,000 | a car, for anything that pays |
| Sophos | $100 – $80,000 | appliance / firmware |
| AXIS OS | $500 – $40,000 (to $50k) | firmware reversing; images are public but this is expert static analysis |
| Square | Points – $18,000 | not really IoT; fintech, payment flows |
| Cisco Networking | $100 – $10,000 | hardware |
| Dell Products | — | hardware |
| HPE Networking | $300 – $5,000 | hardware |
| Xfinity Home & xFi | Points – $5,500 | must be a Comcast subscriber (US) |
| Bitdefender Box v2 | $200 – $5,000 | discontinued box |
| Wyze | $50 – $5,000 | **account is free; cloud + app in scope** |
| Arlo Cash Rewards | $25 – $4,500 | **account is free; web portal `my.arlo.com`** |
| iRobot | $100 – $4,500 | account free, but nothing to act on without a robot |
| Upwork | $120 – $5,000 | not IoT — matched the search by accident |

## The real question is not "is IoT good", it is "what can this operator test"

Available equipment: one Android phone — Termux, Kiwi, DevTools. No laptop, no bench, no UART
adapter, no logic analyser, no soldering iron, and no budget for devices. Classic IoT hunting
(buy device → dump firmware → find RCE) is capital- and lab-intensive. **It is not available.**

But most IoT programmes' *scope* is mostly cloud API, web portal and mobile app, not the silicon.
That part is reachable from a phone, and it is where the auth bugs live: "can I view, control, or
share someone else's camera / robot / thermostat" is an authorization question, which is now the
operator's strongest skill — 240 clean requests of practice on Personio.

Two further points in IoT's favour, both of which answer the Personio post-mortem directly:

1. **Two accounts are free and instant** (two e-mail addresses). On Personio the cross-tenant axis
   — the EUR 3,000 item — was never reached because a second tenant could not be provisioned.
2. **Consumer IoT clouds have delegation features** — guest access, family sharing, temporary
   access links, "share this camera". Delegation is under-specified far more often than core CRUD,
   and it is exactly the shape that pays.

## The thing that kills it, and it is decisive

**An account with no device has nothing in it.**

No camera, no robot, no thermostat means no object to share, no object to request, no object to
IDOR. Testing would be against two empty accounts — which is precisely the failure mode that
invalidated Coveo phase 1 (FO-19): absence of data read as evidence of enforcement. Personio was
chosen partly *because* its trial arrives "preloaded with realistic user data". An empty IoT
account is the opposite of that.

The cheapest route past this is one Wyze cam (~USD 30) or a used Arlo. That is money the operator
does not have today, plus shipping to Bangladesh.

## Verdict

**Not now, and not because IoT is a bad category — because the one thing that makes it work is the
one thing currently out of reach.** Picking it anyway would repeat the Personio error in a new
costume: choosing a target on the payout table and plausibility rather than on whether a finding
can actually be produced.

**If a device ever is affordable, the ranking is Arlo first, Wyze second**: both have free accounts,
a cloud API in scope, a web surface testable from Kiwi + curl, sharing features, and a low enough
floor ($25 / $50) that a Low still pays. Everything else on that list needs hardware the operator
will not have.

### The ten-minute check to run before committing to any of them

1. Can an account be created with **no device**, and does the web portal load?
2. Is the **cloud API / web portal** explicitly in scope, or is scope only firmware/hardware?
3. Does the programme page show **when targets were last added**? Prefer recently added surface.
4. Does the product have a **sharing / guest / family** feature? If not, the best class is gone.

Gate 1 and gate 2 both have to pass, or there is nothing to do.
