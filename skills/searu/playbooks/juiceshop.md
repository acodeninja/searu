# Playbook — OWASP Juice Shop

An intentionally vulnerable Angular SPA + Express/REST API (`/rest/...`, `/api/...`) on a SQLite
back-end, whose progress is tracked on a score board. Use this to head straight for the real work; it
accelerates the coverage loop but does not replace it — finish by clearing `searu coverage`, not this
list. Fingerprint: the browser records the `/#/score-board` route and `/api/Challenges/` endpoint.

**Step 0 — drive the SPA first.** Before attacking any row below, understand the app by driving it:
`searu run browser --technique T1595 --target http://host:port`. It maps the linked client routes, the
`/rest`/`/api` calls behind them and the forms. Several routes are hidden or authenticated-only (no link
exposes them), so feed them in with `--seed` and drive them authenticated once you hold a credential:

    searu run browser --technique T1595 --target http://host:port -- \
      --login-email <u> --login-password <p> \
      --seed /#/score-board,/#/administration,/#/accounting,/#/wallet,/#/order-history,/#/order-summary,/#/address,/#/saved-payment-methods,/#/privacy-security/change-password,/#/2fa/enter,/#/complain,/#/track-result,/#/recycle,/#/photo-wall,/#/deluxe-membership,/#/basket

Register or crack a credential first (a fresh `/#/register` account is enough to expose the logged-in
surface: baskets, orders, wallet, the JWT). Then `searu coverage` turns that surface into the work list.

**Step 1 — mint a JWT (unlocks the authenticated surface).** Most challenges need a session token. Log
in with `fetch --method POST` and the token lands in loot:

    searu run fetch --technique T1083 --target http://host:port/rest/user/login -- \
      --method POST --header 'Content-Type: application/json' \
      --data '{"email":"<user>","password":"<pass>"}'
    searu loot --category session-token --reveal      # → carry as 'Authorization: Bearer <token>'

Carry that token into every authenticated attack below (`authz --header`, IDOR sweeps, NoSQL writes).

Recognise it, then map its weakness categories (from *Pwning OWASP Juice Shop*) to searu:

| Category | Surface to attack | Class / how |
| --- | --- | --- |
| Injection | `q` on `/rest/products/search`; the `email` field on `/rest/user/login` | `sqli` — `sqlmap`/`ghauri` on the parameter; login bypass is a `' OR 1=1--` style payload. **NoSQL** (the order/review endpoints): send an operator payload with `fetch --method PUT`/`POST` — e.g. `--data '{"orderLinesData":"...$where..."}'` — and read the response body for the leak/effect |
| Broken authentication | `/rest/user/login`; JWT in the `Authorization: Bearer` token | `brute-force` — `hydra` with `S=authentication`; `auth` — forge with `jwt` (`-X a` alg:none / `-X k` key-confusion), then **confirm** by replaying the forged token with `authz` against `/rest/user/whoami` (a 2xx = signature not verified) |
| Broken access control | `/rest/basket/{id}`, `/api/Cards/{id}`, `/api/Addresss/{id}`, `/api/Users/{id}`; admin routes (`/rest/admin/*`) | `access-control` — mint a JWT (Step 1), then `authz --header 'Authorization: Bearer <token>' --range 1-20` to sweep object ids (a served id that is not yours is IDOR); drop the header to test admin/unauth routes |
| XSS | reflected/DOM sinks: the search parameter, the `/#/track-result?id=` route | `xss` — run it per sink (search **and** `trackResult?id=`); it now tries every payload and reports each that fires, so the DOM-XSS `<iframe src=javascript:>` is caught, not just the first reflected `<img onerror>` |
| Sensitive data exposure | `/ftp/` directory: `*.bak`, `package.json.bak`, `coupons_*.md.bak`, `incident-support.kdbx` | `fetch` the file (the `.bak` 403 is bypassed with a `%2500.md` null-byte trick), then `crack --target src:<downloaded-path>` the KeePass DB / hashes — add `--rules best64` when a plain wordlist misses |
| Unvalidated redirect | the `to`/`redirect` parameter on `/redirect` | `redirect-ssrf` — `redirect --param to --allowlisted <an-allow-listed-url> --attacker https://evil.example`; it defeats the substring allow-list and confirms CWE-601 |
| Vulnerable components / known CVEs | server headers, exposed metadata, `/rest/admin/application-configuration`; the dependency manifest at `/ftp/package.json.bak` | `known-vuln` — `nuclei`/`nikto` on the endpoints. **SCA**: `fetch` the `package.json.bak`, then run `osv-scanner`/`grype` on it via `--target src:<downloaded-path>` to name the vulnerable dependency |
| File upload | the complaint form's `file` field on `/#/complain` | `upload` — `fuxploider`, then abuse the accepted type (XXE via `.xml`, oversized/deep-nested) |
| Cryptographic issues | dumped user password hashes (MD5), the JWT signing key | crack the MD5 loot; recover/confirm the weak signing key (crypto is largely manual) |

Always authenticate the browser crawl with a registered or cracked credential to reveal the logged-in
surface (baskets, orders, the token), then re-run `searu coverage` — the authenticated endpoints are
new items to clear. Between rounds, run `searu benchmark score` to read the score board
(`/api/Challenges/`) — the ground truth for how much you have actually broken and the delta since last
round; it is an opt-in measurement, never a prerequisite.
