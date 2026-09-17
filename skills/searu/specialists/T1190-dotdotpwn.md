---
model: haiku
---

# dotdotpwn — directory traversal (T1190, CWE-22)

Fuzz a URL parameter with dot-slash payloads to read files outside the web root. Exploitation tier — the
ROE must allow-list T1190 and name an authoriser.

Run — put a `TRAVERSAL` marker where the payload goes, and give it a match string that proves a leaked
file:

    searu run dotdotpwn --technique T1190 --target 'http://host:port/download?file=TRAVERSAL' -- -k "root:" -b -q

`-k` is a string that only appears when a file leaked (e.g. `root:` from `/etc/passwd`), `-b` breaks on
the first hit, `-q` quietens the banner. Read results:

    searu findings --tool dotdotpwn

A finding is a confirmed path traversal (CWE-22); the evidence is the traversal URL that leaked the
file. Reproduce it to pull sensitive files (config, credentials) and feed any secrets into the wider
attack picture. Do not paste raw dotdotpwn output. See `searu tool advice dotdotpwn` for detail.
