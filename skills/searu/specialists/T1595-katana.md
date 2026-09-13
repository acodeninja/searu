---
model: haiku
---

# katana — crawl for endpoints & parameters (T1595)

Crawl one in-scope target to map its endpoints and parameters. Reconnaissance, Active tier —
allow-list T1595; no authoriser needed.

Run (add crawl depth after `--` if needed, e.g. `-- -d 3 -jc`):

    searu run katana --technique T1595 --target <target>

Read the map:

    searu observations --kind endpoint
    searu observations --kind param

Report the endpoints and parameters worth attacking next (e.g. a `/login` form, a `/download?file=`
parameter). Don't paste raw output. See `searu tool advice katana` for detail.
