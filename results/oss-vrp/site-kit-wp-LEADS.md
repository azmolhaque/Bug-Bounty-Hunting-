# google/site-kit-wp — two leads, neither submitted

Target: `google/site-kit-wp`, **OT1** in Google's OSS VRP repository tier list.
A WordPress plugin with millions of installs. Reviewed 2026-10-28 at commit
`8cf47de`.

Both of these are real and both would require a code change to fix. Neither
was submitted, because § 2 criterion 1 asks what the attacker actually GETS,
and in both cases the honest answer is "a configuration change", not account
access, data, execution or a privilege boundary crossed. They are written down
here so that if the impact argument ever changes — a new datapoint, a new
golink handler — the work does not have to be done again.

The rest of the review is in `results/google/MVRP-DECISIONS.md` under
2026-10-28: 62 of 62 REST routes carry a real permission callback, every
`$wpdb` call is prepared, there is no `wp_redirect()`, no `*_nopriv_` hook,
and Sign in with Google verifies `email_verified`, matches on the Google
`sub`, refuses an email shared by two accounts, and checks both an `Origin`
header and a `nonce` claim. That module is hardened past the usual standard.

---

## Lead 1 — state-changing GET with no nonce and no capability check

**Where.** `includes/Core/Golinks/Golinks.php`

```php
const ACTION_GO = 'googlesitekit_go';

public function register() {
    add_action( 'admin_action_' . self::ACTION_GO, array( $this, 'handle_go' ) );
}

public function handle_go() {
    $key = sanitize_key( (string) $this->context->input()->filter( INPUT_GET, 'to', FILTER_DEFAULT ) );
    ...
    $destination = $this->handlers[ $key ]->handle( $this->context );
    wp_safe_redirect( $destination );
}
```

No `check_admin_referer`, no `current_user_can`. `admin_action_*` fires from
`wp-admin/admin.php`, which every admin page includes, so this runs for any
logged-in user on a plain GET.

**Why that matters.** `Email_Notice_Golink_Handler::handle()`
(`includes/Core/Email_Reporting/Email_Notice_Golink_Handler.php`) is not a
redirect-only handler. It has two side effects:

```php
if ( Analytics_Setup_Email_Notice::ID === $notice_id
     && user_can( $user, Permissions::MANAGE_OPTIONS ) ) {
    if ( ! $this->modules->is_module_active( Analytics_4::MODULE_SLUG ) ) {
        $this->modules->activate_module( Analytics_4::MODULE_SLUG );
    }
    ...
}
$this->email_notices->dismiss_notice_for_user( $notice_id, $user );
```

so a page an administrator visits can activate a Site Kit module on their
site:

    GET /wp-admin/index.php?action=googlesitekit_go
          &to=email-report-notice
          &notice_id=analytics-setup

`Email_Notices::GOLINK_NOTICE` is `'email-report-notice'` and
`Analytics_Setup_Email_Notice::ID` is `'analytics-setup'`. The notice
dismissal happens for any logged-in user; the module activation needs the
victim to hold `MANAGE_OPTIONS`, which an administrator does.

**Why it was not submitted.** Activating a module is a configuration change.
No data is read, no account is reached, nothing executes. § 3 does not drop it
outright — it is state-changing, not a read-only CSRF — but § 2 criterion 1 is
not met.

**What would clear the bar.** Show that activation alone changes what the
public site serves — if analytics-4 already holds a measurement ID from an
earlier setup, activation may re-inject the tag for every visitor, and a
one-click CSRF that starts third-party tracking on someone's site is a
different argument. Test: configure analytics-4, deactivate the module, fire
the golink as the admin, and diff the public page source. If the tag comes
back, the finding is worth writing.

**The fix, if reported.** A nonce on the golink URL, or move the activation
out of a GET handler.

---

## Lead 2 — a write datapoint lowers its own permission below the route's

**Where.** `includes/Core/Modules/REST_Modules_Controller.php`

The `modules/(?P<slug>…)/data/(?P<datapoint>…)` route has two methods. The
EDITABLE one defaults to `$can_manage_options` (`MANAGE_OPTIONS` or `SETUP`).
Since 1.185.0 both methods route through:

```php
private function resolve_datapoint_permission( WP_REST_Request $request, callable $default_callback ) {
    ...
    if ( ! $datapoint instanceof Permission_Aware_Datapoint ) {
        return $default_callback( $request );
    }
    return $datapoint->permission_callback();   // replaces the default
}
```

Four datapoints implement `Permission_Aware_Datapoint`, and all four return
`current_user_can( Permissions::VIEW_DASHBOARD )`:

| file | line |
|---|---|
| `includes/Modules/Analytics_4/Datapoints/Site_Goals_Settings_Datapoint.php` | 69 |
| `includes/Modules/Analytics_4/Datapoints/Get_Benchmarking_Data.php` | 197 |
| `includes/Modules/Analytics_4/Datapoints/Get_Form_Metadata.php` | 291 |
| `includes/Modules/Reader_Revenue_Manager/Datapoints/User_Settings_Datapoint.php` | 85 |

Three of the datapoints built on them are writes. Two write per-user state
(`User_Setting`), which is defensible. **One writes a site-wide option:**

```php
// includes/Modules/Analytics_4/Datapoints/Remove_Site_Goals_Widget.php
return function () use ( $widget ) {
    return $this->site_goals_site_settings->remove_widget( $widget );
};
```

`Site_Goals_Site_Settings extends Setting` with
`OPTION = 'googlesitekit_analytics-4_site_goals_site_settings'` — one value
for the whole site, affecting every user's dashboard.

**Who holds VIEW_DASHBOARD.** `includes/Core/Permissions/Permissions.php`
maps it to the core capability `edit_posts` (line 160) and then requires
either an authenticated Site Kit user or `VIEW_SHARED_DASHBOARD` (lines 372,
445, 494), which a user gets when an administrator shares any module with
their role and they have dismissed the sharing splash. So a Contributor,
Author or Editor given **view-only** access through Dashboard Sharing can make
this call. Before 1.185.0 it required an administrator.

**Reproduction sketch** (needs a WordPress install, not yet run):

1. Site Kit set up; Dashboard Sharing on for, say, Contributor.
2. Sign in as that Contributor, dismiss the sharing splash.
3. `POST /wp-json/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget`
   with `{"data":{"widget":"ecommerce"}}` and a REST nonce.
   (`ALLOWED_WIDGETS = array( 'ecommerce', 'lead' )`.)
4. The widget is gone from every user's dashboard until the daily cron puts it
   back.

**Why it was not submitted.** The attacker gets a hidden dashboard widget.
Cross-user, persistent-ish, and genuinely an authorization flaw — but not data,
not access, not execution. Roughly CVSS 3.1 4.3
(`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`), and a triager would reasonably ask the
same question § 2 asks.

**What would clear the bar.** A `Permission_Aware_Datapoint` whose write
touches something that matters, or evidence that this option influences more
than the dashboard. The class is fully enumerated above — those four are all
of it as of this commit — so the way this becomes reportable is a new
datapoint, which makes it worth re-checking after a few releases.

**The fix, if reported.** A datapoint's own callback should narrow the route's
permission, never widen it: take the stricter of the two rather than replacing
one with the other.
