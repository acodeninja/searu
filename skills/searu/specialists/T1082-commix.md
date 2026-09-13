---
model: haiku
---

# commix — system information discovery via the foothold (T1082)

Gather host and system information through a confirmed OS command injection. Exploitation tier — the
ROE must allow-list T1082 and name an authoriser.

    searu run commix --technique T1082 --target "http://host:port/path?param=1" -- --os-cmd 'uname -a; id; hostname'

Read the result:

    searu findings --technique T1082
    searu observations

Report the OS/kernel/user context that frames what else is worth trying. See
`searu tool advice commix` for detail.
