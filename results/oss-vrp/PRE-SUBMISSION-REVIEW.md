# Pre-submission review — site-kit-wp, 2026-10-29

Two findings were reproduced. Before submitting either, the question asked was
the one § 2 criterion 2 asks: **does the vendor's own design explain this?**
The answer killed one of them outright and put the other on hold. Both answers
came from evidence inside the repository, not from judgement.

This is the cheapest check in the whole process and it was nearly skipped.

---

## Finding 1 — view-only user writes a site-wide option: **WORKING AS INTENDED**

`tests/phpunit/integration/Modules/Analytics_4/Datapoints/Remove_Site_Goals_WidgetTest.php`

```php
public function test_is_shareable__returns_true() {
    $this->assertTrue(
        $this->datapoint->is_shareable(),
        'The removal datapoint should be shareable, so a view-only user on a shared
         dashboard can remove a widget for every user of the site.'
    );
}

public function test_permission_callback__allows_a_view_only_user() {
    $editor_id = $this->factory()->user->create( array( 'role' => 'editor' ) );
    …
    $this->assertTrue(
        $this->datapoint->permission_callback(),
        'The datapoint should let a view-only user remove a Site Goals widget.'
    );
}

public function test_permission_callback__refuses_a_subscriber() { … }
```

The assertion message states the site-wide effect in its own words — *"for
every user of the site"* — and asserts it is correct. A second test fixes the
lower boundary at Subscriber, which is exactly the line the PoC measured.

There is no reading of this where the behaviour is an oversight. **Withdrawn.**

The reproduction was still worth doing: it is what made the test file worth
reading. The mistake was the conclusion, not the method.

---

## Finding 2 — Golinks CSRF: **contested, on hold**

### For it being a vulnerability

* **It is the only `admin_action_` handler in the plugin without a nonce.**

  | handler | nonce checks |
  |---|---|
  | `Core/Authentication/Setup.php` | 5 |
  | `Core/Authentication/Authentication.php` | 3 |
  | `Modules/Sign_In_With_Google.php` | 1 |
  | `Core/Util/Reset.php` | 1 |
  | **`Core/Golinks/Golinks.php`** | **0** |

* The two that were checked by hand are correct in detail, which shows the
  project knows how to do this: `handle_disconnect_user()` binds its nonce to
  the target user (`ACTION . '-' . $user_id`) *and* checks
  `current_user_can( 'edit_user', $user_id )`; `handle_reset_action()` verifies
  a nonce *and* requires `Permissions::SETUP`.
* The handler performs a state change on a GET, which WordPress's own
  guidelines do not allow, and the change alters what every visitor's browser
  executes.
* The URL carries no secret, so anyone can host it anywhere.

### Against — and this is the part that matters

* **Golinks are email CTA links by design.**
  `Notices/Analytics_Setup_Email_Notice.php:161` builds the link with
  `$this->golinks->get_url( Email_Notices::GOLINK_NOTICE )` for the email body.
  A WordPress nonce is user- and time-bound (12–24h) and cannot survive email
  delivery, so "add a nonce" is answerable with "then the email stops working".
* **The activation was added deliberately, in review.**
  `89fb653572` — *"Update per CR feedback"*, 2026-03-04 — introduces exactly:

  ```php
  if (
      Analytics_Setup_Email_Notice::ID === $notice_id
      && user_can( $user, Permissions::MANAGE_OPTIONS )
      && ! $this->modules->is_module_active( Analytics_4::MODULE_SLUG )
  ) {
      $this->modules->activate_module( Analytics_4::MODULE_SLUG );
  }
  ```

  Authorization was considered at that line and a capability check was the
  answer chosen. That is a reviewed decision, not an omission.
* **Every email link in the plugin works this way.** There is no `hash_hmac`,
  `wp_hash` or signed token anywhere in `Core/Email_Reporting/`, so there is no
  in-project precedent to point at and say "you already sign these elsewhere".

### Verdict

Genuinely contested. A triager can close it as "email CTA, capability-gated,
the administrator clicked the link", and that answer is not unreasonable.
Against a requirement of no further Working As Intended closes, "probably" is
not good enough.

### What would have to change for it to go out

Not the evidence — the claim. "There is no nonce" invites the email answer.
The claim that survives it is narrower:

> An emailed link that performs a state change is a URL any third party can
> host. Site Kit protects every other state-changing `admin_action_` with a
> nonce; this one changes what the public site serves to every visitor. The
> fix that keeps the email flow working is a signed single-use token in the
> golink — not a WordPress nonce — or a confirmation step before the module is
> activated.

That version concedes the constraint the vendor would raise and proposes a fix
that lives inside it, which is what makes a report hard to close as intended.
It is still a judgement call, and it is the researcher's call rather than the
agent's.

---

## Duplicate check

* No fix has landed: the last change under `includes/Core/Golinks/` is
  2026-08-27, and the clone is at `8cf47de` (2026-10-28, current).
* `changelog.txt` has no CSRF, nonce or security entry for golinks.
* `SECURITY.md` routes disclosures to the Google Application Security program
  and lists no exclusions.
* Patchstack, Wordfence, WPScan and MITRE are all unreachable from this
  container (`http=000`). **That check is outstanding and has to be run from
  the Pi before anything is submitted.**

---

## What this cost, and what it saved

One WAI close avoided outright, and a second submission stopped at the line.
The check that did it — read the tests for the code you are about to report —
took four minutes and should run before every report from here on, not after.
