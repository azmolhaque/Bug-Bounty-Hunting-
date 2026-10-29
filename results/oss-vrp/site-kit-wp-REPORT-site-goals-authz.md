# Site Kit: a view-only Dashboard Sharing user can change a site-wide setting

**Project:** `google/site-kit-wp` (OT1 in the OSS VRP repository tier list)
**Version tested:** 1.190.0, commit `8cf47de`
**Tested on:** WordPress 6.9.11, PHP 8.3.6, 2026-10-29

## Summary

Site Kit's Dashboard Sharing lets an administrator give other roles **view**
access to module data. A user who only has that view grant can send one POST
to the Analytics-4 `remove-site-goals-widget` datapoint and change
`googlesitekit_analytics-4_site_goals_site_settings`, which is a site-wide
option. The widget they remove disappears from the Site Goals section for
every user of the site, not just for themselves.

Before 1.185.0 every write through `modules/<slug>/data/<datapoint>` required
`googlesitekit_manage_options`. That release added
`Permission_Aware_Datapoint`, which lets a datapoint replace the route's
permission check with its own, and the Site Goals datapoints replace it with
`googlesitekit_view_dashboard` — a capability a shared-role user holds.

I have only shown what is in the evidence below: the option changes. I have
not found a way to turn this into reading or writing anything else.

## Who can do this

Any user who:

* holds `edit_posts` (Contributor and above), and
* has a role that the administrator added to `sharedRoles` for any module —
  **the view grant is enough, `management` can stay `owner`**, and
* has dismissed the shared-dashboard splash, which happens on their first
  visit to the shared dashboard.

A Subscriber cannot do it. A Contributor on a site with Dashboard Sharing
switched off cannot do it. Both are shown as controls below.

## Steps to reproduce

1. WordPress with Site Kit 1.190.0, set up and connected, Analytics-4
   connected and owned by the administrator.
2. Site Kit → Settings → Dashboard Sharing: share Analytics-4 with the
   Contributor role. Leave management as "Owner" — do not grant them anything
   beyond viewing.
3. Sign in as a Contributor and open the Site Kit dashboard once, so the
   splash is dismissed.
4. Confirm the Site Goals widgets the administrator has active:

   ```
   googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["ecommerce","lead"]}
   ```

5. As that Contributor, with their own cookies and their own REST nonce:

   ```
   curl -i -X POST 'https://<site>/?rest_route=/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' \
        -H 'Content-Type: application/json' \
        -H 'X-WP-Nonce: <their nonce>' \
        -b cookies.txt \
        --data '{"data":{"widget":"ecommerce"}}'
   ```

6. The option is now `{"activeWidgets":["lead"]}` for the whole site.

`ALLOWED_WIDGETS` is `array( 'ecommerce', 'lead' )`, so `lead` works the same
way.

## Evidence

Taken on the run recorded in `poc/evidence.txt`:

```
state before
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["ecommerce","lead"]}

request
  curl -i -X POST 'http://127.0.0.1:8099/?rest_route=/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' \
       -H 'Content-Type: application/json' \
       -H 'X-WP-Nonce: fcfe1c0e3d' \
       -b cookies.txt \
       --data '{"data":{"widget":"ecommerce"}}'

response
  HTTP/1.1 200 OK
  Content-Type: application/json; charset=UTF-8
  Allow: GET, POST, PUT, PATCH

  {"activeWidgets":["lead"]}

state after
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["lead"]}
```

Controls, same request, same site, one variable changed at a time
(`poc/poc3.php`):

```
A. Dashboard Sharing OFF for every module
  subscriber                                  VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts)                    VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]

B. Dashboard Sharing ON: analytics-4 shared with 'contributor', view only
  subscriber                                  VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts), view-only share   VIEW_DASHBOARD=true  -> 200                  activeWidgets ["lead"]
```

The only difference between the two 403s and the 200 is the view grant.

## Root cause

`includes/Core/Modules/REST_Modules_Controller.php`

The editable half of `modules/(?P<slug>…)/data/(?P<datapoint>…)` defaults to
`$can_manage_options`, then hands that default to:

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

`Remove_Site_Goals_Widget` extends that class, and its request writes the
site-wide setting:

```php
// includes/Modules/Analytics_4/Datapoints/Remove_Site_Goals_Widget.php
return function () use ( $widget ) {
    return $this->site_goals_site_settings->remove_widget( $widget );
};
```

`Site_Goals_Site_Settings extends Setting` with
`OPTION = 'googlesitekit_analytics-4_site_goals_site_settings'` — one value for
the whole site.

`VIEW_DASHBOARD` reaches a shared-role user through
`Permissions::check_view_dashboard_capability()`, which falls back to
`check_view_shared_dashboard_capability()` when the user is not an
authenticated Site Kit user. That fallback asks only whether the user's role
appears in any module's `sharedRoles` and whether they have dismissed the
splash.

Three other datapoints use the same `VIEW_DASHBOARD` callback. Two of them
write per-user settings (`User_Setting`), which seems deliberate; this is the
only one of the four that writes a site-wide value.

## Impact

A user who was given view-only access to module data can change a setting that
every user of the site sees. The daily cron puts a removed widget back when
its provider plugin is active and Site Kit finds its events, so the change is
not necessarily permanent.

CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = **4.3 (Medium)**.

I am not claiming anything beyond this. No other user's data is readable
through it, nothing executes, and nothing else in Site Kit's settings is
reachable this way as far as I could tell.

## Suggested fix

A datapoint's own permission callback should narrow the route's permission,
never widen it — take the stricter of the two rather than replacing one with
the other. Failing that, `Remove_Site_Goals_Widget` writes site-wide state and
should require `Permissions::MANAGE_OPTIONS` like the rest of the editable
route, with `VIEW_DASHBOARD` kept for the datapoints that write per-user
settings.

## Notes on the test environment

I ran this on a local WordPress with SQLite
(`sqlite-database-integration` v3.1.2) because the machine has no MySQL. The
Google connection cannot be completed offline, so three values that an
administrator's real setup would write were set directly, and all three sit
*after* the permission check that this report is about:

* the proxy credentials, so Site Kit considers setup complete
* a Search Console property, which Site Kit requires for the same reason
* the module owner's granted OAuth scopes and an access token, so the request
  reaches the datapoint instead of stopping at `missing_required_scopes`

None of them grants the Contributor anything. With Dashboard Sharing switched
off and everything else identical, the same Contributor gets 403.

`poc/poc.php` sets the site up, `poc/poc3.php` runs the controlled comparison,
`poc/evidence.txt` is the HTTP exchange above.
