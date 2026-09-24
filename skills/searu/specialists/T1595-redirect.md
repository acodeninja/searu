---
model: haiku
---

# redirect — open / unvalidated redirect (T1595, CWE-601)

Coax an app's redirect endpoint into sending the victim off-site. It sends attacker destinations to the
redirect parameter **without following redirects** and flags a 3xx `Location` that lands off the target
origin. A substring allow-list (accepts any `to` that merely *contains* an allow-listed URL) is defeated
by appending an allow-listed URL to an attacker URL. Reconnaissance/Initial-access, Active tier —
allow-list T1595; no authoriser needed.

Run — the target is the redirect endpoint; `--param` names the parameter (default `to`):

    searu run redirect --technique T1595 --target http://host:port/redirect
    searu run redirect --technique T1595 --target http://host:port/redirect -- \
      --allowlisted https://an-allow-listed-url.example/path --attacker https://evil.example/pwned

Read results:

    searu findings --tool redirect        # a confirmed CWE-601 finding (payload + the Location it hit)
    searu observations --kind redirect     # every probe's status and Location

A confirmed off-site redirect is the bug. When the endpoint's allow-list only substring-matches, pass one
of its known allow-listed URLs as `--allowlisted` so the substring-bypass payloads are built. Don't paste
raw output. See `searu tool advice redirect`.
