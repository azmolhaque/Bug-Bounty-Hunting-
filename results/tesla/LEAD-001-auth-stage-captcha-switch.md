# LEAD-001 — `?disable_captcha=true` disables hCaptcha on `auth-stage.tesla.com`

**Status: LEAD, not submitted.** Logged with full evidence so it can be raised the moment impact
is shown. Submitting it as it stands would almost certainly close as informational and cost
signal on the programme.

## How it was found

`auth-stage.tesla.com` and `auth.tesla.com` serve the **same application bundle**
(`/assets/index-28uodCcC.js`, identical hash) and differ only in a config file:

```
stage  /config-zq2pj5ur.js
prod   /config-c7hxwwp3.js
```

Same code, different configuration — so the configuration *is* the differential. Both files are
served publicly to anyone.

## The evidence

Tail of the **staging** config, verbatim:

```js
const { automationKey } = window.config.captcha.hcaptcha;
if (automationKey && new URLSearchParams(window.location.search).get("disable_captcha") === "true") {
    Object.entries(window.config.captcha.hcaptcha).forEach(([key]) => {
        window.config.captcha.hcaptcha[key] = window.config.captcha.hcaptcha.automationKey;
    })
}
```

With `?disable_captcha=true` in the URL, **every** hCaptcha sitekey — authorize challenge,
authorize passive, register, password-forgot and phone-change — is replaced by
`automationKey: "c8de4fa2-24ea-4f14-8076-c63ceb36b300"`, an hCaptcha automation key that passes
without human interaction.

**Production does not have it.** `cfg-prod.js` contains no `automationKey` and no
`disable_captcha` block; `grep -c disable_captcha` returns 0. Tesla kept the two apart correctly.

## Why it is not being submitted yet

Against our own §2 bar, the honest answer to *"what did the attacker actually GET?"* is: the
ability to make unlimited attempts against a **staging** login. Not an account, not another
user's data. That is a precondition (FO-8/9/11).

And Tesla's brief excludes, verbatim:

> *"Login or Forgot Password page brute force, account lockout not enforced, or insufficient
> password strength requirements"* · *"Lack of rate limiting"*

A triager can reasonably file a staging captcha bypass in that family. The counter-argument —
that this is not a *missing* control but an existing control **switched off by user-controlled
input** — is real, but it only carries weight if the thing behind the control is worth reaching.

## What would turn it into a report

Whether `auth-stage.tesla.com` authenticates against the **production identity store**.

One signal already points that way: every audience in the *staging* config names the
**production** host.

```
verifyEmailResource  https://auth.tesla.com/user/email/verify/
phoneChangeAudience  https://auth.tesla.com/user/phone/change/
emailChangeAudience  https://auth.tesla.com/user/email/change/
mfaAudience          https://auth.tesla.com/user/mfa/
mfaResetAudience     https://auth.tesla.com/user/mfa/reset/
passkeyAudience      https://auth.tesla.com/user/passkey/
```

These may be nothing more than audience identifier strings. But if staging sits on the same user
directory, then an uncaptcha'd registration / password-forgot / phone-change path against real
accounts is a different severity entirely.

Counter-signals in the same file suggest staging is fenced: `showEmailWhitelistWarning: true` and
`enableRegistrationEmailVerify: false` (production has it `true`).

**No brute force will be used to settle this.** The programme forbids it and the class is excluded.
If it is demonstrated at all it will be by showing the control is disabled, in one request, never
by exercising it.

## Other hosts the staging config disclosed

Not previously in the certificate-transparency set:

```
accounts-stage.tesla.com      preview.tesla.com      auth-stage.tesla.cn
sentry-api.ops.na.vn.cloud.tesla.com   (Sentry DSN, public by design — not a finding)
```

## Minor, recorded and dropped

Production config has `accountHomeURL: "http://accounts.tesla.com/?redirect=no"` — plaintext
scheme. It will redirect to HTTPS and HSTS covers it; "HTTPS mixed content" is out of scope.
Not a finding.
