# Pi Runbook — Apigee /sign_up redirect_uri Bypass Verification
**Date:** 2026-06-20
**Lead:** APG-L001
**Priority:** HIGH — runs on Pi, not cloud (cloud egress blocked for login.apigee.com)

---

## Objective
Determine whether `POST /apigee_create_account_request` validates `redirect_uri`
against client `unifiedui`'s registered allowlist, or accepts arbitrary URIs.

If validation is ABSENT at POST time:
→ Write report. OAuth authorization code delivered to attacker URI = full management console takeover.

If validation is PRESENT at POST time:
→ Drop APG-L001. Note that GET-level injection is harmless.

---

## Step 1 — Run the comparison test

```bash
bash scripts/apigee_signup_verify.sh
```

The script will:
1. POST with `redirect_uri=https://example.com` (attacker-controlled)
2. POST with `redirect_uri=https://console.apigee.com/oauthCallback` (registered)
3. Grep both responses for error/success/redirect indicators
4. Diff the response sizes

---

## Step 2 — Interpret results

### Scenario A — NO validation (lead confirmed)
Both responses are identical (same HTML structure, same size ±50 bytes).
Neither contains text like `invalid_redirect_uri`, `redirect_uri not allowed`, or similar.

**Action:** Escalate to report. See APG-L001 candidate file.

### Scenario B — Validation PRESENT
Responses differ: the external redirect_uri returns an error page/JSON like:
```
{"error":"invalid_redirect_uri","error_description":"..."}
```
or HTTP 400/302 to a UAA error page.

**Action:** Drop APG-L001. Record response snippet in HUNT-LOG.

### Scenario C — Both fail on email domain
Both return the same "invalid email" / "check your email" HTML because
`@example.invalid` is not a real domain. This is inconclusive.

**Action:** Retry with `@gmail.com` test accounts (use disposable emails).
  - Attacker email: `apigee.bounty.test.aaa@gmail.com`
  - Baseline email: `apigee.bounty.test.bbb@gmail.com`
  Use accounts you control (not real accounts of others). Do NOT actually
  complete OAuth flow — just compare the POST responses for redirect behavior.

---

## What to capture

Save to `results/apigee/03-candidates/APG-L001-post-responses.txt`:
```bash
echo "=== EXTERNAL ===" >> results/apigee/03-candidates/APG-L001-post-responses.txt
head -c 2000 /tmp/post_external.txt >> results/apigee/03-candidates/APG-L001-post-responses.txt
echo "=== REGISTERED ===" >> results/apigee/03-candidates/APG-L001-post-responses.txt
head -c 2000 /tmp/post_registered.txt >> results/apigee/03-candidates/APG-L001-post-responses.txt
```

Then commit and push:
```bash
git add results/apigee/
git commit -m "apigee: APG-L001 POST verification evidence"
git push
```

---

## Background (what we know)

**GET /sign_up injection confirmed:**
- `GET /sign_up?client_id=unifiedui&redirect_uri=https://example.com`
- Response reflects both params verbatim into hidden form fields:
  ```html
  <input type="hidden" name="client_id" value="unifiedui">
  <input type="hidden" name="redirect_uri" value="https://example.com">
  ```
- Form POSTs to `/apigee_create_account_request`

**client_id source:**
- Real client_id discovered from console.apigee.com → console.login.apigee.com redirect chain
- Registered redirect_uri: `https://console.apigee.com/oauthCallback`

**State JWT note:**
- console.apigee.com generates state JWT with `alg:none`
- JWT payload: `{"rfp":"<nonce>","target_link_uri":"https://console.apigee.com/edge"}`
- This protects `/oauth/authorize` directly but NOT the sign_up flow
