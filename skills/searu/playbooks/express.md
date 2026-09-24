# Express

A Node.js REST API (Express/Koa/Fastify), usually the back end behind an SPA. The interesting surface is
the JSON API: id-bearing resource routes, auth endpoints, and write endpoints that trust the request body.

## Confirm it

`tech`/`server` observations naming Express/Node, an `X-Powered-By: Express` header, JSON error bodies
with a `stack` trace when a route throws, and REST paths (`/api/...`, `/rest/...`) the SPA calls.

## Enumerate the surface

- Take the API routes from the SPA crawl (`searu run browser`) and from the client bundle's call sites.
- Provoke a stack-trace error (malformed JSON, wrong content-type, a type-mismatched field) — Express
  often returns the trace, revealing internal paths, the framework version and middleware.
- Enumerate id-bearing collections (`/<resource>/<id>`) and their verbs; a `404` vs `401` vs `403`
  distinguishes "no such route" from "exists but denied" and maps the real surface.

## Weakness classes it tends to expose

- **Object-level access control (IDOR/BOLA)** — the dominant class: mint a token
  (`sections/initial-access.md`), then `authz --header 'Authorization: Bearer <token>' --range` to sweep
  neighbouring ids; a served id that is not yours is the bug (`specialists/T1190-authz.md`).
- **Broken/weak JWT** — `alg:none` or key-confusion acceptance; forge with `jwt` and confirm by replaying
  with `authz` (`specialists/T1606.001-jwt.md`).
- **Mass-assignment** — a create/update that binds the whole body to the model; add a privileged field
  (`role`, `isAdmin`, an ownership id) via `fetch --method POST/PUT`.
- **NoSQL injection** (Mongo back ends) — an operator object where a scalar is expected (`{"$ne":null}`,
  `$where`); send it via `fetch --method POST/PUT` and read the response for the leak/effect.
- **Vulnerable dependencies** — fetch a leaked `package.json`/lockfile and run `osv-scanner`/`grype` on it
  via `--target src:<downloaded-path>` (`specialists/T1593.003-osv-scanner.md`).
