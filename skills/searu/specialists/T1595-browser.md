---
model: haiku
---

# browser — drive the app to understand it (T1595)

Render one in-scope web app as a real browser and *drive* it: it executes the SPA, follows client-side
routes (including Angular `routerLink`s on buttons/menus, not just `<a href>`), opens the nav/side menus,
submits the search box, scrolls for lazy content, and records every same-origin API call — the surface a
passive crawler (katana/gospider) cannot see because it never runs the JavaScript. Run this **first** on
a web target; it is what the rest of the engagement works through. Reconnaissance, Active tier —
allow-list T1595; no authoriser needed.

Run unauthenticated first, then again authenticated once you hold a credential. Routes that no link
exposes (hidden or authenticated-only) will not be reached by crawling — feed them in with `--seed`
(comma-separated paths). Widen with `--depth`/`--max-routes`/`--max-seconds`:

    searu run browser --technique T1595 --target http://host:port
    searu run browser --technique T1595 --target http://host:port -- --login-email <user> --login-password <pass> \
      --seed /#/wallet,/#/order-history,/#/administration

Read the surface map:

    searu observations --kind route      # client-side routes (e.g. /#/login, /#/admin)
    searu observations --kind endpoint   # API endpoints, detail = method
    searu observations --kind param      # parameters, detail = the endpoint they belong to
    searu observations --kind form       # forms, detail = field names
    searu observations --kind output     # screenshots saved under the run's output directory

Report the endpoints, parameters and forms worth attacking next (a search parameter for injection, an
upload form, an admin-only route, a redirect parameter). If you have a cracked or registered
credential, re-run with the login flags to map the authenticated surface too. Don't paste raw output.
See `searu tool advice browser` for detail.
