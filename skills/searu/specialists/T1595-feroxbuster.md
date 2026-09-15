---
model: haiku
---

# feroxbuster — content discovery (T1595)

Brute-force paths and files on one in-scope target to find unlinked routes. Active tier —
allow-listing T1595 in the ROE is enough; no authoriser needed.

feroxbuster needs a wordlist — pass one as a `seclists:` token (searu fetches it once and mounts it
read-only):

    searu run feroxbuster --technique T1595 --target http://host:port -- -w seclists:Discovery/Web-Content/common.txt

Add `-x php,txt,html` to append extensions, `-r` to follow redirects, `-d 2` to limit recursion
depth. Read the results:

    searu observations --kind endpoint

One observation per discovered path with its status. Pick the wordlist from the stack hints Recon
recorded, and feed the discovered endpoints/parameters to Initial access. Do not paste raw output.
See `searu tool advice feroxbuster` for detail.
