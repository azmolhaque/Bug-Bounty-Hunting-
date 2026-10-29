# site-kit-wp: the REST authorization surface, measured

2026-10-29. **74 routes, 5 reachable by a low-privileged role, no gap.**

Yesterday this was claimed from a code reading: "62 of 62 routes carry a real
permission callback". That is a statement about the code's shape, not about
who can call what. With a WordPress running, the question can be asked
properly.

## How, and the method error that had to be fixed first

The first attempt sent requests with empty bodies and read `400` as "the
permission callback passed, validation stopped it". **It does not.**
`WP_REST_Server::dispatch()` validates required parameters at line 1120 and
only reaches the permission callback at line 1264, guarded by
`! is_wp_error( $response )`:

```php
// dispatch()
$check_required = $request->has_valid_params();   // 1120
…
// respond_to_request()
if ( ! is_wp_error( $response ) && ! empty( $handler['permission_callback'] ) ) {   // 1264
```

So a `400` means authorization was never evaluated. That first run reported
"28 routes reached by a low-privileged role" and every one of them was noise.
Filling the required parameters fixed 48 routes and left 20 where even the
administrator hit `400`, because each wants a `data` object with its own
shape — 29% of the surface still unmeasured, which is the condition this repo
keeps getting burned by.

The instrument that works calls `$handler['permission_callback']` directly, as
each role. The callback is the thing under test; dispatch is only a delivery
mechanism, and skipping it covers the templated
`modules/<slug>/data/<datapoint>` routes too. (`poc/matrix3.php`)

## Result

Roles: subscriber, contributor, author, editor, administrator. Every one has
dismissed the shared-dashboard splash, so the only variable is the role.
Analytics-4 is shared with `contributor`, view only.

| route | who gets through | what it is |
|---|---|---|
| `GET core/user/data/nonces` | subscriber, contributor, author | returns the caller's **own** `updates` nonce. A nonce is not a capability: every core endpoint that accepts it also checks one, including Site Kit's own consent-API installer (`check_ajax_referer('updates')` **and** `current_user_can('activate_plugin')`). Nonces are per-user, so nothing of anyone else's comes back. |
| `GET core/search/data/entity-search` | contributor | searched as the administrator and as the contributor for a draft and a private post owned by the administrator: both return `[]`, both return the same published posts. No unpublished content leaks. (`poc/entitysearch.php`) |
| `GET core/site/data/health-checks` | contributor | diagnostics; § 3 drops those on their own |
| `GET core/user/data/dismissed-tours`, `POST core/user/data/dismiss-tour` | contributor | the caller's own UI state |

Every other route refuses every role below administrator, and no route is
registered without a permission callback.

## What this closes

The "broken access control in a REST route" class is closed for site-kit-wp
at commit `8cf47de`, not by reading but by calling. If a future release adds a
datapoint or a route, re-running `poc/matrix3.php` re-measures the whole
surface in one command.
