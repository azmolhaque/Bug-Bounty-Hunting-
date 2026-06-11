# [TITLE: Bug class + impact + location — one line]

> Example: "IDOR in /api/v1/invoices/{id} allows any authenticated user to read
> any organization's invoices (PII + financial data exposure)"

## Summary
<!-- What is the bug, where is it, and why does it matter? 2-3 sentences. -->

## Severity
- **Rating:** [Critical | High | Medium | Low | Info]
- **CVSS 3.1:** `[CVSS:3.1/AV:N/AC:L/PR:.../UI:.../S:.../C:.../I:.../A:...]` → score X.X
- **Business impact:** <!-- what data/funds/control is at risk, and for whom -->

## Affected asset(s)
- URL/endpoint: `https://...`
- Component/parameter: `...`
- In scope per `config/scope.yaml`: **yes**

## Steps to reproduce
<!-- Numbered, copy-pasteable, from a CLEAN state (fresh session/account). A
     triager should reproduce this in under 5 minutes using only these steps. -->
1.
2.
3.

## Proof
<!-- Minimal request/response or screenshots. SANITIZED — no real secrets,
     tokens, cookies, or third-party PII. Use your own test accounts only. -->
```http
[minimal proof-of-concept request/response]
```

## Impact
<!-- Concrete attacker capability: what can they do, to whom, at what scale?
     If chained with other issues, describe the chain. -->

## Remediation
<!-- Specific, actionable fix tied to the ROOT CAUSE, not just the symptom. -->

## References
- CWE-XXX:
- OWASP:
- Other:

---
<!-- Internal (do not submit): dedup status, discovery method, related findings -->
- Dedup status: [novel | possible-dup | known]
- Discovered via: [phase / tool / reasoning]
- Related findings:
