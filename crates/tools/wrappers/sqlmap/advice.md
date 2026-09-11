# sqlmap — SQL injection exploitation

sqlmap detects and exploits SQL injection. Point it at a parameter recon has surfaced (a form field
or query parameter) and it confirms the injection and fingerprints the back-end DBMS.

## How to drive it
- `searu run sqlmap --technique T1190 --target http://host:port/login -- --data "username=a&password=a"`
  — the target goes to sqlmap with `-u`; supply the POST body, and any further sqlmap flags, after `--`.
- Point it with what recon found: the `endpoint` and `param` observations from katana and the
  `tech`/`server` hints from httpx.
- Read the result with `searu findings` (a confirmed SQL-injection finding, CWE-89) and
  `searu observations` (a `tech` observation for the back-end DBMS).
- To retrieve data, add sqlmap's own flags after `--` (e.g. `--dump`, `--current-db`).

## Blind login forms
A login query is often guarded — the injected field is ANDed with a password check and errors are
swallowed to an identical redirect, so the default run reports nothing injectable. Then:
- Focus the field with `-p username` and raise coverage with `--level 3 --risk 3` (risk 3 enables the
  `OR` payloads a login needs, since the base row does not match).
- If the query spans lines, a `--` comment will not reach the trailing `AND pass = …`; force an
  open block comment with `--suffix "/*"` (SQLite runs it to end of input).
- The success/failure signal is the raw redirect, so add `--ignore-redirects` and anchor the failing
  page with `--not-string login`.

## Notes
- Exploitation tier: the ROE must allow-list T1190 and name an authoriser. sqlmap auto-fingerprints
  the DBMS, so there is no need to pass `--dbms`.
