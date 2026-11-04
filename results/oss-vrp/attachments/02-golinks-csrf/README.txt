Site Kit: one link activates a module and restores the Analytics tag
google/site-kit-wp 1.190.0 (commit 8cf47de) — Google OSS VRP
Md. Azmol Haque Rony (cindrasec), 2026-10-29

  report-to-paste.txt   the report body. Paste this into the form.
  evidence.txt          the whole sequence: Analytics-4 configured but
                        deactivated, a visitor served no gtag script, one GET
                        with no nonce as a logged-in administrator, the module
                        active, and the same visitor then served
                        googletagmanager.com/gtag/js and gtag("config", "G-…").

The request is a plain GET and needs nothing but a logged-in administrator
following it:

  /wp-admin/index.php?action=googlesitekit_go&to=email-report-notice&notice_id=analytics-setup
