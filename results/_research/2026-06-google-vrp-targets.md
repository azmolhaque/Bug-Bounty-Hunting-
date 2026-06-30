# Google VRP target intelligence (deep-research, 2026-06-30)

Synthesis was cut by a weekly token limit; below merges the CONFIRMED (2-3 votes)
claims + the source-grounded UNVERIFIED (0-0, limit-hit, NOT refuted) leads.
Genuinely REFUTED (0-3): "YouTube IDOR is the top class" and "Gemini Trifecta is
fully patched/dead" — both false, so AI/Gemini is still live and YouTube-IDOR is
not the play.

## What's productive on Google VRP right now (2025-2026), web-reachable
- **Looker Studio** (lookerstudio.google.com) — Tenable "LeakyLooker": 9 cross-
  tenant vulns incl. a **0-click SQLi via column aliases concatenated into live
  BigQuery SQL**, and a **"Sticky Credential"** flaw where Copy-Report retained the
  original owner's stored DB credentials. Free, web, multi-tenant, data-source
  connectors. PATTERN: user-controlled fields -> SQL/data-source; credential
  handling on copy/share; cross-tenant report/data access.
- **Google IDX / Firebase Studio** (idx.google.com / firebase studio) — fresh web
  IDE; **$22,500 XSS** (2025). Web-reachable XSS/postMessage surface.
- **Cloud Theia notebooks** — postMessage XSS ($3,133).
- **Gemini / AI features** — prompt-injection -> data exfiltration; class LIVE (the
  "it's all patched" claim was refuted). But Google's bar: pure prompt injection
  often = abuse, not vuln, unless it crosses a privacy/authz boundary with data
  exfil. Web-reachable (gemini.google.com, aistudio.google.com).
- **Apigee** — recurring writeups incl. 2024 sandbox-escape (unverified count).
- **GCP** — most-represented area historically (Cloud Shell RCE/XSS/token, IDOR).

## Best fit for THIS hunter (phone + browser + curl, no app RE) — ranked
1. **Looker Studio** — web, free, multi-tenant, documented recurring patterns
   (column-alias SQLi, Sticky-Credential on copy, cross-tenant report/data access).
   Testable with 2 free Google accounts + browser mitmproxy + curl. TOP PICK.
2. **Firebase Studio / IDX** — web IDE, XSS/postMessage; fresh, browser-testable.
3. **Gemini / AI Studio** — prompt-injection->exfil; web-reachable but fuzzier bar.

## Sources
- github.com/xdavidhu/awesome-google-vrp-writeups (writeups.csv)
- tenable.com "Gemini Trifecta" + "LeakyLooker" / "LookOut" Looker research
