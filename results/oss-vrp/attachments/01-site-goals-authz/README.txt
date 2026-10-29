Site Kit: a view-only Dashboard Sharing user can write a site-wide setting
google/site-kit-wp 1.190.0 (commit 8cf47de) — Google OSS VRP
Md. Azmol Haque Rony (cindrasec), 2026-10-29

  report-to-paste.txt           the report body. Paste this into the form.
  evidence.txt                  the HTTP exchange: the state before, the exact
                                curl, the full response, the state after.
  01-setup-the-site.php         sets a WordPress up the way an administrator
                                would: credentials, a Search Console property,
                                Analytics-4 connected and owned by the admin,
                                Dashboard Sharing granting the Contributor role
                                VIEW-ONLY access, and a contributor account.
  02-controlled-comparison.php  the experiment. Resets the widgets before each
                                attempt and runs the same request as a
                                subscriber and as the contributor, with sharing
                                off and then on. The only difference between
                                the 403s and the 200 is the view grant.

To re-run: a WordPress with Site Kit 1.190.0 active, then

  php 01-setup-the-site.php /path/to/wordpress
  php 02-controlled-comparison.php /path/to/wordpress

Both take the WordPress root as their only argument and touch nothing outside
that install.
