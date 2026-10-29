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

---

## Second pass, 2026-10-29: the places the developers themselves flagged

A `phpcs:ignore` on a security sniff is a developer writing "this looks unsafe
and I believe it is fine". That is a short, high-signal list, so all 59 were
read.

| suppressed sniff | count | what was found |
|---|---|---|
| `EscapeOutput.ExceptionNotEscaped` | 25 | exception messages returned as JSON through `WP_Error`; escaping would show entities |
| `EscapeOutput.OutputNotEscaped` | 20 | every one concatenates already-escaped parts. The Sign in with Google button (`Sign_In_With_Google.php:754`) renders on `wp-login.php`, so it was read closely: attribute keys come from a fixed list, `class` passes `sanitize_html_class`, and every value passes `esc_attr()`. `Authentication.php:1382` builds its `wp_die()` body from translated strings and `esc_url()`'d URLs, with no request input |
| `DB.DirectDatabaseQuery` | 11 | all prepared |
| `Security.NonceVerification` | 2 | `Activation_Notice.php:97` unsets `$_GET['activate']` to suppress a core notice; `Authorize_Application.php:92` reads `success_url` |
| `Security.ValidatedSanitizedInput` | 1 | `$_SERVER['SCRIPT_NAME']` compared against `wp_login_url()` |

### The one that looked like a real finding

`Core/Admin/Authorize_Application.php` hooks WordPress's **Application
Passwords** authorization screen — the screen where a user hands an external
service full REST API credentials — and decides from `$_GET['success_url']`
whether "the current service is a Google service":

```php
$parsed_url = wp_parse_url( $success_url );
if ( empty( $parsed_url['host'] ) ) { return false; }
return preg_match( '/\.google\.com$/', $parsed_url['host'] ) === 1;
```

If that check gated anything, spoofing it would hand an application password
to an attacker's domain, which is site takeover for an administrator. Two
things close it:

* The check is sound. The pattern is anchored and requires the literal dot, so
  `evil-google.com` and `evil.google.com.attacker.com` do not match, and
  `https://www.google.com@evil.com/` parses to host `evil.com`.
* It gates **nothing**: a CSS file and a "Powered by Site Kit" footer. There
  is no security decision behind it, so a bypass would gain a stylesheet.

## Other classes closed in this pass

* **Page-path resolution** (`WP_Query_Factory`, `Plain_Permalink_Top_Posts`).
  A visitor chooses the URLs that appear in Analytics, and the server resolves
  each back to a post whose title is then shown on a dashboard that view-only
  users can see. The factory copies only public query vars and restricts post
  types to `publicly_queryable`, mirroring `WP::parse_request()`, and the
  caller then re-checks: `'publish' !== get_post_status( $post )` returns
  null, with a comment saying why — *"The query returns a draft to a user who
  can edit it, so we check the status."*
* **The public verification file.** Served on the front end to anyone, so it
  was read: the URI must match `^\/google([a-z0-9]+)\.html$`, the token must
  equal a stored user meta value, that user must hold `SETUP`, and the output
  is `esc_html`'d.
* **What an anonymous visitor receives.** Fetched the front page logged out:
  no plugin inline data, no identifiers, nothing beyond the gtag snippet when
  Analytics is active.
