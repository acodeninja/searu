---
model: haiku
---

# commix — command execution via the foothold (T1059)

Run a specific command through an already-confirmed OS command injection. Exploitation tier — the ROE
must allow-list T1059 and name an authoriser.

    searu run commix --technique T1059 --target "http://host:port/path?param=1" -- --os-cmd '<command>'

Use this only when no more specific collection technique fits (prefer `T1552-commix` for credentials,
`T1083-commix` for files, `T1518-commix` for software, `T1082-commix` for system info). Keep commands
non-destructive. Read the result:

    searu findings
    searu loot --reveal

Report what the command returned, not the raw dump. See `searu tool advice commix` for detail.
