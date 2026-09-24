# React

A client-side SPA (often bundled with webpack/Vite, routed with React Router) over a JSON/REST or GraphQL
API. As with any SPA the surface lives in the JS bundle and must be driven in a real browser, not scraped.

## Confirm it

`tech` observations naming React, a root mount node (`<div id="root">`/`#app`), `static/js/main.<hash>.js`
bundles, and `data-reactroot`/hydration markers. A `__NEXT_DATA__` script or `/_next/` paths mean Next.js
(server-rendered React) — also probe its API routes under `/api`.

## Enumerate the surface

- **Drive it in a browser first** (`searu run browser --technique T1595`) to record the routes and the
  same-origin API/GraphQL calls behind them (`specialists/T1595-browser.md`).
- **Read the bundle** with `fetch`: React Router route tables, `fetch`/`axios` call sites and their URLs,
  and any embedded config/keys. Source maps (`*.js.map`), if served, hand you the original source. Feed
  discovered routes back with `searu run browser --seed`.
- If the API is GraphQL, pull the schema via introspection and enumerate queries/mutations as endpoints.

## Weakness classes it tends to expose

- **Object-level access control (IDOR/BOLA)** on id-bearing API calls — mint a token, sweep with
  `authz --header` (`sections/initial-access.md`).
- **Token/session auth** — forge and confirm with `jwt` + `authz` (`specialists/T1606.001-jwt.md`).
- **DOM XSS** via `dangerouslySetInnerHTML`, a `javascript:`/`href` sink, or unsanitised markdown; drive
  `xss` per sink (`specialists/T1595-xss.md`).
- **Secrets in the bundle** — API keys and endpoints shipped to the client; treat any recovered secret as
  loot.
- **Mass-assignment** on write endpoints via `fetch --method POST/PUT` with extra fields.
