# Angular

A client-side SPA served as a JS bundle over a JSON/REST API. The routes, guards and forms live in the
compiled JavaScript, not in server-rendered HTML, so a passive crawler sees almost nothing — the surface
has to be pulled out of the bundle and driven in a real browser.

## Confirm it

`tech` observations naming Angular, a `<app-root>` element, `runtime`/`polyfills`/`main.<hash>.js`
bundles, and `ng-` attributes. The API base is usually a sibling path (`/api`, `/rest`) the bundle calls.

## Enumerate the surface

- **Drive it in a browser first** — `searu run browser --technique T1595` renders the SPA, follows its
  client-side routes and records every same-origin API call as observations (see
  `specialists/T1595-browser.md`). This is where the real endpoints/params/forms come from.
- **Read routes out of the bundle.** Fetch `main.<hash>.js` (and lazy chunks) with `fetch` and search the
  source for route definitions (`path:` entries in the router config, `loadChildren` lazy modules) and
  API call sites (`HttpClient` `.get/.post` URLs). These reveal routes no link exposes — feed them back
  in with `searu run browser --seed <route,route,...>` and drive them, authenticated once you hold a
  credential. Guarded/admin routes are still reachable directly even when a UI guard hides the link.
- Re-run `searu coverage` after each pass: the newly recorded endpoints/params are fresh work items.

## Weakness classes it tends to expose

- **Object-level access control (IDOR/BOLA)** on the id-bearing REST endpoints the bundle calls — the
  dominant class. Mint a token (see `sections/initial-access.md`) and sweep ids with `authz --header`.
- **Token/session auth** — the JWT/session the SPA stores and attaches; forge/So confirm with `jwt` +
  `authz` (`specialists/T1606.001-jwt.md`).
- **DOM XSS** in client-side sinks (a value routed into `innerHTML`, `bypassSecurityTrust*`, a
  `javascript:` URL). Drive `xss` per sink — it reports every payload that fires, so an `<iframe
  src=javascript:>` sink is caught, not just a reflected one (`specialists/T1595-xss.md`).
- **Mass-assignment** on write endpoints — a create/update call that accepts more fields than the form
  shows; add a privileged field to the JSON body via `fetch --method POST/PUT`.
