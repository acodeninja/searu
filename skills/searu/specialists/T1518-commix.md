---
model: haiku
---

# commix — software discovery via the foothold (T1518)

Enumerate installed software through a confirmed OS command injection. Exploitation tier — the ROE
must allow-list T1518 and name an authoriser.

    searu run commix --technique T1518 --target "http://host:port/path?param=1" -- --os-cmd 'which nmap python3 curl; cat /etc/os-release'

Read the result:

    searu findings --technique T1518
    searu observations

Report which interpreters and tools are present that could widen the foothold. See
`searu tool advice commix` for detail.
