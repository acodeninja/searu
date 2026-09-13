---
model: haiku
---

# ffuf — content discovery (T1595)

Discover unlinked routes on one in-scope target by fuzzing a `FUZZ` keyword against a wordlist.
Active tier — allow-list T1595; no authoriser needed.

Run — put `FUZZ` where the path goes and pass the list as a `seclists:` token (searu fetches it once
and mounts it read-only):

    searu run ffuf --technique T1595 --target 'http://host:port/FUZZ' -- -w seclists:Discovery/Web-Content/common.txt -mc 200

Pick the list from recon's `tech`/`server` hints. Read hits:

    searu observations --kind endpoint

Report the discovered routes. Using ffuf to read files off the host instead is Exploitation — that is
the `T1190-ffuf` specialist. See `searu tool advice ffuf` for detail.
