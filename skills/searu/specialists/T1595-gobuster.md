---
model: haiku
---

# gobuster — directory brute-forcing (T1595)

Brute-force directories and files on one in-scope target (dir mode). Active tier — allow-listing
T1595 in the ROE is enough; no authoriser needed.

gobuster needs a wordlist — pass one as a `seclists:` token (searu fetches it once and mounts it
read-only):

    searu run gobuster --technique T1595 --target http://host:port -- -w seclists:Discovery/Web-Content/common.txt

Add `-x php,txt,html` to append extensions. Read the results:

    searu observations --kind endpoint

One observation per discovered path with its status. This runs `dir` mode; for a second engine on the
same surface use feroxbuster/ffuf. Feed discovered endpoints to Initial access. Do not paste raw
output. See `searu tool advice gobuster` for detail.
