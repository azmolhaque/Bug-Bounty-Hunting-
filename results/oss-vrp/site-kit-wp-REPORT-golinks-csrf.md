# Site Kit: one link activates a module on an administrator's site, and the site's Analytics tag goes back onto every page

**Project:** `google/site-kit-wp` (OT1 in the OSS VRP repository tier list)
**Version tested:** 1.190.0, commit `8cf47de`
**Tested on:** WordPress 6.9.11, PHP 8.3.6, 2026-10-29

## Summary

`Golinks::handle_go()` runs on `admin_action_googlesitekit_go` with no nonce
and no capability check of its own. One of the handlers it dispatches to,
`Email_Notice_Golink_Handler`, is not a redirect — it activates the
Analytics-4 module when the current user holds `googlesitekit_manage_options`.

So a page an administrator follows a link from can activate the module on
their site. On a site where Analytics-4 is configured but switched off, that
puts the site's Google Analytics tag back into every public page, and visitors
start being measured again, with no interaction beyond the one click.

I am claiming that and nothing more: the attacker does not choose the
measurement ID, does not read anything, and does not gain any access.

## Steps to reproduce

1. WordPress with Site Kit 1.190.0 set up and connected.
2. Analytics-4 configured with a measurement ID, then **deactivated** — the
   state a site is in after an administrator turns the module off but keeps
   its settings.
3. Confirm a visitor gets no tag: load the site logged out, there is no
   `googletagmanager.com/gtag/js` script.
4. As a logged-in administrator, follow:

   ```
   https://<site>/wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup
   ```

   No nonce, no POST, no form.
5. Analytics-4 is active, and a logged-out visitor now receives the gtag
   script and a `gtag("config", "G-…")` call.

The attacker's page only has to get the administrator to follow a link —
`window.location = '…'`, a redirect, or an ordinary anchor. WordPress sends no
`SameSite` attribute on its auth cookies, so browsers treat them as `Lax`:
they travel on a top-level navigation like this one, and not on a subresource,
so an `<img>` tag would not work. One click, not zero.

## Evidence

From `poc/evidence-csrf.txt`:

```
starting state: analytics-4 configured (measurement ID G-REPRO) but DEACTIVATED
  googlesitekit_active_modules = ["search-console"]
  analytics-4 measurementID    = G-REPRO

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

Control: the same link followed by a Contributor leaves
`googlesitekit_active_modules` at `["search-console"]`. The handler's
`user_can( …, MANAGE_OPTIONS )` check holds, so the victim has to be an
administrator.

Second control: following the link again while the module is already active
changes nothing — the activation branch is skipped, and only the notice
dismissal runs.

## Root cause

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

No `check_admin_referer()`, no nonce in the URL `Golinks::get_url()` builds.
`admin_action_*` fires from `wp-admin/admin.php`, which every admin page
includes, so this runs on a plain GET for any logged-in user.

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

`Email_Notices::GOLINK_NOTICE` is `'email-report-notice'` and
`Analytics_Setup_Email_Notice::ID` is `'analytics-setup'`.

The handler also dismisses whatever `notice_id` is passed, for any logged-in
user, with no check at all. That is the smaller half of the same missing
nonce.

## Impact

An administrator who follows one link from any page on the internet changes
what their site serves to every visitor: the Google Analytics tag is injected
and measurement resumes. The administrator is not asked, and the only visible
sign is the redirect that follows.

This matters most on a site that deliberately turned Analytics off — for a
consent or privacy reason, or while investigating something — because the
change silently undoes that decision for every visitor.

CVSS 3.1: `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = **4.3 (Medium)**.

What it is not: the attacker does not choose which measurement ID is injected
(it is the site's own), gains no access, and reads nothing. On a site where
Analytics-4 was never configured, activating it changes nothing a visitor can
see, and the request only dismisses a notice.

## Suggested fix

Put a nonce on the golink URL and verify it in `handle_go()`, or move the
module activation out of a GET handler. `Golinks::get_url()` is the one place
that builds these links, so adding `wp_nonce_url()` there and
`check_admin_referer()` in the handler covers every golink at once.

Notice dismissal should also not happen on an unauthenticated-shaped GET for
an arbitrary `notice_id`.

## Notes on the test environment

Local WordPress on SQLite (`sqlite-database-integration` v3.1.2), because the
machine has no MySQL. Site Kit's proxy credentials, a Search Console property
and the module owner's token were written directly, since an OAuth flow cannot
be completed offline. None of them is involved in the missing nonce: the same
request with those values present and Site Kit fully set up is what a real
site sees, and the control above shows a Contributor following the same link
changes nothing.
