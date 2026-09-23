# Playbook — OWASP Juice Shop

An intentionally vulnerable Angular SPA + Express/REST API (`/rest/...`, `/api/...`) on a SQLite
back-end, whose progress is tracked on a score board. Use this to head straight for the real work; it
accelerates the coverage loop but does not replace it — finish by clearing `searu coverage`, not this
list. Fingerprint: the browser records the `/#/score-board` route and `/api/Challenges/` endpoint.

**Step 0 — drive the SPA first.** Before attacking any row below, understand the app by driving it:
`searu run browser --technique T1595 --target http://host:port`. It maps the client routes, the
`/rest`/`/api` calls behind them, the forms and the score-board. Register or crack a credential, then
drive it again authenticated (`-- --login-email <u> --login-password <p>`) to reveal the logged-in
surface (baskets, orders, the JWT). Then `searu coverage` turns that surface into the work list.

Recognise it, then map its weakness categories (from *Pwning OWASP Juice Shop*) to searu:

| Category | Surface to attack | Class / how |
| --- | --- | --- |
| Injection | `q` on `/rest/products/search`; the `email` field on `/rest/user/login` | `sqli` — `sqlmap`/`ghauri` on the parameter; login bypass is a `' OR 1=1--` style payload |
| Broken authentication | `/rest/user/login`; JWT in the `Authorization: Bearer` token | `brute-force` — `hydra` with `S=authentication`; `auth` — forge/alter the RS256 JWT (needs the JWT hand) |
| Broken access control | `/rest/basket/{id}`, `/api/Users/{id}`, admin-only routes (`/#/administration`), `/#/score-board` | `access-control` — replay a request with another object's id or without the admin role (manual until the IDOR hand exists) |
| XSS | reflected/DOM sinks: the search parameter, the `/#/track-result?id=` route | `xss` — `dalfox` on the parameter |
| Sensitive data exposure | `/ftp/` directory: `*.bak`, `package.json.bak`, `coupons_*.md.bak`, `incident-support.kdbx` | download the file, then crack the KeePass DB / hashes (needs the file-download + crack hands); the `.bak` 403 is bypassed with a `%2500.md` null-byte trick |
| Unvalidated redirect | the `to`/`redirect` parameter on `/redirect` | `redirect-ssrf` — supply an allow-listed-prefix bypass (manual) |
| Vulnerable components / known CVEs | server headers, exposed metadata, `/rest/admin/application-configuration` | `known-vuln` — `nuclei`/`nikto` on the endpoints |
| File upload | the complaint form's `file` field on `/#/complain` | `upload` — `fuxploider`, then abuse the accepted type (XXE via `.xml`, oversized/deep-nested) |
| Cryptographic issues | dumped user password hashes (MD5), the JWT signing key | crack the MD5 loot; recover/confirm the weak signing key (crypto is largely manual) |

Always authenticate the browser crawl with a registered or cracked credential to reveal the logged-in
surface (baskets, orders, the token), then re-run `searu coverage` — the authenticated endpoints are
new items to clear. The score board (`/api/Challenges/`) is the ground truth for how much of the app
you have actually broken; scoring against it is a separate, opt-in step and never a prerequisite.
