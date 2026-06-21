# Hunt Log — tenor.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1
**Started:** 2026-06-21
**Status:** RECON — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- tenor.com    # TIER1, acquired 2018
```

**SCOPE NOTE:** Only `tenor.com` apex is explicitly listed. Per acquisition-domain rules,
unlisted subdomains default to TIER4. Key implication: `api.tenor.com` and `www.tenor.com`
are technically OOS unless the Google VRP rules treat the listed apex as covering direct
subdomains. Probe `tenor.com` itself first; if real API surface exists at apex level (e.g.,
`tenor.com/api/...`), that is clearly in scope.

The GIF developer API (`tenor.googleapis.com`) is served through `googleapis.com` which is
explicitly TIER4 in scope.yaml — do NOT probe it.

---

## Pre-Recon Hypothesis

| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | `tenor.com` API paths | GIF platform — upload, search, embed endpoints | SSRF (URL import), IDOR (GIF/user ID), stored XSS |
| 2 | Upload endpoint | Animated GIF processing — URL-based import = SSRF | SSRF |
| 3 | Content delivery | Cross-account GIF access, unlisted content | IDOR |

---

## Session 1 — 2026-06-21 (QUEUED)

Quick viability check: is tenor.com a live web app or a redirect?

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| (none yet) | — | — | Recon pending |
