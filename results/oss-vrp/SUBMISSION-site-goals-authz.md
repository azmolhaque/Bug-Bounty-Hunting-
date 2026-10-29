# Ready-to-send text — Site Goals write reachable at VIEW_DASHBOARD

Send this one **first**. It has the stronger precedent: the project fixed the
identical pattern under CVE-2026-10753 in 1.176.0, and the Site Goals
datapoints reintroduce it.

Submit through <https://www.google.com/about/appsecurity/>, project
`google/site-kit-wp`.

---

**Researcher:** Md. Azmol Haque Rony (`cindrasec`)
**Date:** 2026-10-29
**Project:** `google/site-kit-wp` — Google OSS VRP

## Title

A view-only Dashboard Sharing user can write a site-wide Site Kit setting —
the pattern fixed under CVE-2026-10753, reintroduced by the Site Goals
datapoints

## Summary

In March 2026 Site Kit fixed CVE-2026-10753 — *"users with dashboard sharing
permissions (such as Editors) could modify email reporting settings restricted
to administrators"* — by changing the **write** half of
`core/site/data/email-reporting` from the dashboard-sharing capability to
`manage_options`. Commit `2bb4fb2878`, "Update editable route", one line:

```diff
-   'permission_callback' => $can_access,    // VIEW_SPLASH || VIEW_DASHBOARD
+   'permission_callback' => $can_manage,    // MANAGE_OPTIONS
```

Since 1.185.0 a datapoint can replace the route's permission check with its
own (`Permission_Aware_Datapoint`), and the Site Goals datapoints use that to
gate on `current_user_can( VIEW_DASHBOARD )` — the capability the CVE fix
moved away from. One of them, `Remove_Site_Goals_Widget` (1.190.0), writes a
**site-wide** option.

A user who was given view-only access through Dashboard Sharing can therefore
change `googlesitekit_analytics-4_site_goals_site_settings`, which decides
what the Site Goals section shows for every user of the site. Before 1.185.0
that write required `manage_options`, as the whole editable route still does.

I reproduced this on WordPress 6.9.11 with Site Kit 1.190.0 (commit
`8cf47de`), PHP 8.3.6, on 2026-10-29.

## Steps to reproduce

1. Site Kit set up and connected, Analytics-4 connected and owned by the
   administrator.
2. Settings → Dashboard Sharing: share Analytics-4 with the Contributor role.
   Leave management as "Owner" — nothing beyond viewing is granted.
3. Sign in as a Contributor and open the Site Kit dashboard once, so the
   sharing splash is dismissed.
4. As that Contributor, with their own cookies and REST nonce:

   ```
   curl -i -X POST 'https://<site>/?rest_route=/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' \
        -H 'Content-Type: application/json' \
        -H 'X-WP-Nonce: <their nonce>' \
        -b cookies.txt \
        --data '{"data":{"widget":"ecommerce"}}'
   ```

`ALLOWED_WIDGETS` is `array( 'ecommerce', 'lead' )`, so either works.

## Evidence

```
state before
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["ecommerce","lead"]}

response
  HTTP/1.1 200 OK
  Content-Type: application/json; charset=UTF-8
  {"activeWidgets":["lead"]}

state after
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["lead"]}
```

Controls on the same site, one variable changed at a time:

```
A. Dashboard Sharing OFF for every module
  subscriber                                  VIEW_DASHBOARD=false -> 403   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts)                    VIEW_DASHBOARD=false -> 403   activeWidgets ["ecommerce","lead"]

B. Dashboard Sharing ON: analytics-4 shared with 'contributor', view only
  subscriber                                  VIEW_DASHBOARD=false -> 403   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts), view-only share   VIEW_DASHBOARD=true  -> 200   activeWidgets ["lead"]
```

The only difference between the 403s and the 200 is the view grant.

## Where it is

`includes/Core/Modules/REST_Modules_Controller.php` — the editable half of
`modules/<slug>/data/<datapoint>` defaults to `$can_manage_options`, then
hands that default to:

```php
private function resolve_datapoint_permission( WP_REST_Request $request, callable $default_callback ) {
    …
    if ( ! $datapoint instanceof Permission_Aware_Datapoint ) {
        return $default_callback( $request );
    }
    return $datapoint->permission_callback();   // replaces the default outright
}
```

`includes/Modules/Analytics_4/Datapoints/Site_Goals_Settings_Datapoint.php:69`

```php
public function permission_callback() {
    return current_user_can( Permissions::VIEW_DASHBOARD );
}
```

`includes/Modules/Analytics_4/Datapoints/Remove_Site_Goals_Widget.php`

```php
return function () use ( $widget ) {
    return $this->site_goals_site_settings->remove_widget( $widget );
};
```

`Site_Goals_Site_Settings extends Setting`, with
`OPTION = 'googlesitekit_analytics-4_site_goals_site_settings'` — one value for
the whole site.

`VIEW_DASHBOARD` reaches a shared-role user through
`Permissions::check_view_dashboard_capability()`, which falls back to
`check_view_shared_dashboard_capability()` for a user who is not an
authenticated Site Kit user. That fallback asks only whether the user's role
appears in any module's `sharedRoles` and whether the splash is dismissed.

Four datapoints implement `Permission_Aware_Datapoint` and all four return
`current_user_can( VIEW_DASHBOARD )`. Two of the writes behind them are
per-user (`User_Setting`), which seems deliberate. `Remove_Site_Goals_Widget`
is the one that writes site-wide state.

## The test, raised here rather than left to be found

There is a test asserting this behaviour:

```php
// tests/phpunit/integration/Modules/Analytics_4/Datapoints/Remove_Site_Goals_WidgetTest.php
$this->assertTrue(
    $this->datapoint->is_shareable(),
    'The removal datapoint should be shareable, so a view-only user on a shared
     dashboard can remove a widget for every user of the site.'
);

public function test_permission_callback__allows_a_view_only_user() { … }
public function test_permission_callback__refuses_a_subscriber()   { … }
```

I withdrew this report once because of that test, and then found
CVE-2026-10753. The two do not sit together: the CVE fix says a write must not
be gated on the dashboard-sharing capability, and this test says a view-only
user may change a site-wide value. If Site Goals is a deliberate exception, I
would want to understand why a site-wide write is acceptable at
`VIEW_DASHBOARD` when a settings write was not — and if it is not an
exception, the test is encoding the bug rather than the design.

## Impact

A user given view-only access to module data changes a setting every user of
the site sees. It is bounded: the daily cron restores a removed widget when
its provider plugin is active and Site Kit finds its events, and the values
are limited to `ecommerce` and `lead`.

CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3 (Medium), which is
alongside CVE-2026-10753's own score for the same class.

No other user's data is readable through it and nothing executes. I checked
whether it goes further and it does not: a grant on one module does not reach
another module's datapoints (`Module::get_oauth_client_for_datapoint()`
requires `READ_SHARED_MODULE_DATA` for that module, and without it the call
ends at `missing_required_scopes`); `core/modules/data/sharing-settings`
refuses the same user with 403, so the grant cannot be widened; and the
per-user settings sanitiser drops unknown keys.

## Suggested fix

The same shape as `2bb4fb2878`: a datapoint's own permission callback should
narrow the route's permission, never widen it — take the stricter of the two
rather than replacing one with the other. Failing that,
`Remove_Site_Goals_Widget` writes site-wide state and should require
`Permissions::MANAGE_OPTIONS` like the rest of the editable route, with
`VIEW_DASHBOARD` kept for the datapoints that write per-user settings.

## Test environment

Local WordPress on SQLite (`sqlite-database-integration` v3.1.2), since the
machine has no MySQL. Site Kit's proxy credentials, a Search Console property
and the module owner's token were written directly, because an OAuth flow
cannot be completed offline. All three sit after the permission check this
report is about, and with Dashboard Sharing switched off and everything else
identical the same Contributor gets 403.

---

## Before sending

* [ ] your handle and the date at the top
* [ ] a screenshot of the terminal showing the before/after
* [ ] attach `poc/evidence.txt` and `poc/poc3.php`
* [ ] send separately from the Golinks CSRF report — different root causes,
      and a weaker one alongside drags the other down
