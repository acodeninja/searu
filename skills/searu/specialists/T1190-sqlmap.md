---
model: haiku
---

# sqlmap — SQL injection (T1190, CWE-89)

Confirm and exploit SQL injection in a parameter recon surfaced. Exploitation tier — the ROE must
allow-list T1190 and name an authoriser.

Run — the target goes to sqlmap with `-u`; the POST body and further flags after `--`:

    searu run sqlmap --technique T1190 --target http://host:port/login -- --data "username=a&password=a" -p username

Blind login form (identical redirect on success and failure): add `--level 3 --risk 3`,
`--ignore-redirects` and `--not-string login`, and `--suffix "/*"` if the query spans lines. Read
results:

    searu findings                    # confirmed SQL-injection finding, CWE-89
    searu observations --kind tech    # the fingerprinted back-end DBMS

To retrieve data add sqlmap's own flags after `--` (e.g. `--dump`, `--current-db`). Dumped credentials
land in `searu loot` (subject + host), each also raised as a CWE-522 exposed-credential finding.

Unless the ROE authorises destructive action, searu restricts a run to `--technique=BEU`
(boolean/error/union) — sqlmap's default time-based payload can crash a fragile target (a heavy SQLite
`RANDOMBLOB` delay can take one down). Pin your own `-- --technique=...` (e.g. add `T`) to override.

A negative with no oracle means "sqlmap could not tell", not "clean". See `searu tool advice sqlmap`
for detail.
