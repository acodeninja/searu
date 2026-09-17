---
model: haiku
---

# sstimap — server-side template injection (T1190, CWE-1336/94)

Confirm a parameter is rendered by a template engine — the flaw that escalates to code and OS-command
execution. Exploitation tier — the ROE must allow-list T1190 and name an authoriser.

Run — point it at the URL carrying the parameter to test:

    searu run sstimap --technique T1190 --target 'http://host:port/page?name=x'

Once detection confirms, evaluate the template or run OS commands with SSTImap's own flags after `--`
(e.g. `-- -e '7*7'`, `-- -o id`). Read results:

    searu findings --tool sstimap

A finding is a confirmed SSTI (CWE-1336/94); the evidence names the template engine and injected
parameter. A confirmed engine with shell-command capability authorises an OS-command run within the ROE
— treat that as full compromise, and feed anything it yields into the wider attack picture. Do not paste
raw sstimap output. See `searu tool advice sstimap` for detail.
