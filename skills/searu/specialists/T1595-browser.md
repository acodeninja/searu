---
model: haiku
---

# browser — drive the app to understand it (T1595)

Render one in-scope web app as a real browser: it executes the SPA, follows client-side routes and
records every same-origin API call — the surface a passive crawler (katana/gospider) cannot see
because it never runs the JavaScript. Run this **first** on a web target; it is what the rest of the
engagement works through. Reconnaissance, Active tier — allow-list T1595; no authoriser needed.

Run (authenticate to reach the logged-in surface; widen with `--depth 3`):

    searu run browser --technique T1595 --target http://host:port
    searu run browser --technique T1595 --target http://host:port -- --login-email <user> --login-password <pass>

Read the surface map:

    searu observations --kind route      # client-side routes (e.g. /#/login, /#/score-board)
    searu observations --kind endpoint   # API endpoints, detail = method
    searu observations --kind param      # parameters, detail = the endpoint they belong to
    searu observations --kind form       # forms, detail = field names
    searu observations --kind output     # screenshots saved under the run's output directory

Report the endpoints, parameters and forms worth attacking next (a search parameter for injection, an
upload form, an admin-only route, a redirect parameter). If you have a cracked or registered
credential, re-run with the login flags to map the authenticated surface too. Don't paste raw output.
See `searu tool advice browser` for detail.
