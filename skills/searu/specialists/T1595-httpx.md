---
model: haiku
---

# httpx — HTTP fingerprint (T1595)

Fingerprint one in-scope target: status, title, server, technologies. Reconnaissance, Active tier —
allow-listing T1595 in the ROE is enough; no authoriser needed.

Run:

    searu run httpx --technique T1595 --target <target>

`<target>` is the http(s) URL you were handed. Then read what it recorded:

    searu observations --kind server
    searu observations --kind tech
    searu observations --kind endpoint

Report the server/technology stack and any notable endpoints — these hints pick the wordlist and the
weakness to look for next. Do not paste raw httpx output. See `searu tool advice httpx` for detail.
