# CSP Development Artifact (ws://localhost:3000) in Production — www.wiz.io

**Status:** DRAFT — awaiting full CSP dump from Pi (ACTION C)
**Target:** wiz.io (Google VRP TIER1)
**Discovered:** 2026-06-11
**Severity:** Low — CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N → **3.1**
**Chain potential:** If win-test.wiz.io or other takeover-able hosts appear in CSP → escalates F001 to Critical

---

## Summary

The production `Content-Security-Policy` header on `www.wiz.io` includes
`ws://localhost:3000` in its `connect-src` directive. This is a Webpack development
server hot-reload WebSocket URL that was copied from a development environment into
production without cleanup. It weakens the CSP by:

1. Permitting WebSocket connections to `localhost:3000` from any page on `www.wiz.io`
   (exploitable via DNS rebinding in some browser/network configurations).
2. Revealing Wiz's internal frontend development stack (Webpack dev server on port 3000).

A fully separate and more severe chain issue exists if any other `*.wiz.io` subdomain
claimable via takeover (e.g. `win-test.wiz.io` — see F001) appears in the same CSP.
That would allow an attacker who claims the subdomain to load arbitrary scripts/resources
from their origin into www.wiz.io pages, bypassing the CSP entirely.

---

## Evidence

From `curl -sI https://www.wiz.io/ | grep content-security-policy`:

```
content-security-policy: ... connect-src 'self' ... ws://localhost:3000 ...
```

---

## Impact

**Without chaining:**
- CSP policy weakened — `ws://localhost:3000` is an unintended allowance
- DNS rebinding: an attacker on the same LAN/network as a Wiz employee visiting www.wiz.io
  could potentially rebind `localhost` to an attacker-controlled IP and receive WebSocket
  messages — low-probability, requires LAN position
- Information disclosure: confirms Webpack dev server on port 3000

**With F001 chain (win-test.wiz.io in CSP → CSP bypass):**
- If `win-test.wiz.io` or `*.wiz.io` wildcard appears in `script-src`, `connect-src`,
  `frame-src`, or `default-src`, an attacker who claims `win-test.wiz.io` can:
  - Inject arbitrary JavaScript into www.wiz.io pages (via `script-src` bypass)
  - Exfiltrate data to their origin (via `connect-src` bypass)
  - Embed malicious iframes (via `frame-src` bypass)
  - This upgrades F001 from High (8.2) to Critical (9.3+)

---

## Steps to Reproduce

```bash
curl -sI "https://www.wiz.io/" | grep -i "content-security-policy" | tr ';' '\n' | grep "connect-src"
```

Expected output contains `ws://localhost:3000`.

---

## Remediation

- Remove `ws://localhost:3000` from the production CSP `connect-src` directive
- Audit all CSP directives for other development/staging artifacts
- Verify no `*.wiz.io` wildcard or specific claimable subdomains appear in CSP allow lists
- Use CSP nonce-based approach for script-src to eliminate wildcard host allowances

---

## Pending Validation

- [ ] Run ACTION C on Pi: dump full CSP from www.wiz.io and app.wiz.io
- [ ] Check if win-test.wiz.io appears in any CSP directive → if yes, escalate to Critical chain
- [ ] Check if *.wiz.io or *.vercel.app wildcard appears in CSP
