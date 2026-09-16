---
model: haiku
---

# ghauri — SQL injection (T1190, CWE-89)

Confirm and exploit SQL injection in a parameter recon surfaced — a leaner alternative to sqlmap.
Exploitation tier — the ROE must allow-list T1190 and name an authoriser.

Run — the target goes to ghauri with `-u`; the POST body and further flags after `--`:

    searu run ghauri --technique T1190 --target 'http://host:port/item?id=1' -- -p id

ghauri has no `--ignore-redirects`. On a login form that redirects on success, give it an in-page
oracle instead — `--not-string` for text on the failure page (or `--string` for text unique to
success) — plus `--prefix`/`--suffix` if the query needs them. Read results:

    searu findings                    # confirmed SQL-injection finding, CWE-89
    searu observations --kind tech    # the fingerprinted back-end DBMS

To retrieve data add ghauri's own flags after `--` (e.g. `--dump`, `--dbs`). A negative without an
oracle means "ghauri could not tell", not "clean". See `searu tool advice ghauri` for detail.
