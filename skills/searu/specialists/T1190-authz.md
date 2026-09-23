---
model: haiku
---

# authz — test broken access control / IDOR (T1190, CWE-639/862)

Prove a resource is served to someone who should not have it: another user's object by id, an
admin-only route with a non-admin (or forged) token, or a call with no token at all. Exploitation
tier — the ROE must allow-list T1190 and name an authoriser. Get tokens from `searu loot --reveal`
(a login, a cracked credential, a jwt forgery).

Run — the target is the exact resource URL; assert it *should* be denied, and supply the identity to
test after `--`:

    searu run authz --technique T1190 --target http://host:port/rest/basket/2 -- --should-deny \
      --header 'Authorization: Bearer <another-users-or-forged-token>'
    searu run authz --technique T1190 --target http://host:port/rest/admin --  --should-deny   # unauthenticated

Read results:

    searu findings --tool authz        # a confirmed broken-access-control finding if it was served
    searu observations --kind replay   # the status/length of every replay, denied or not

A denial (401/403) is the app behaving — no finding, move on. A 2xx/3xx on a should-deny request is the
bug: read or tamper the exposed object (`--method PUT --data ...`), then sweep the neighbouring ids and
routes the same way. Don't paste raw bodies. See `searu tool advice authz`.
