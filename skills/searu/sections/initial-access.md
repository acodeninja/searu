# Initial access (TA0001)

Detect an exploitable weakness on a discovered endpoint/parameter. This is *detection* — confirming
a class of weakness exists — ahead of the Exploitation phase that exercises it. `T1190` is the
Exploitation tier, so the ROE must allow-list it **and** name an authoriser.

## Tools

- **sqlmap** (`T1190`, CWE-89) — SQL injection against a parameter:
  ```
  searu run sqlmap --technique T1190 --target "http://host:port/path?id=1" -- -p id
  ```
  For a blind login form give it an oracle (`--not-string`, `--ignore-redirects`, `--level`/`--risk`)
  — see `searu tool advice sqlmap`. A negative with no oracle means "sqlmap could not tell", not
  "clean".
- **ffuf** LFI / path traversal (`T1190`, CWE-22) — fuzz a traversal wordlist against a file parameter.
- **commix** (`T1190`) — confirm OS command injection with a harmless probe first
  (`-- --os-cmd id`); acting on it is the Exploitation phase.

## Read the results

```
searu findings --technique T1190
searu observations
```

A confirmed weakness with its evidence is what authorises moving to Exploitation. Let the recorded
findings — not raw tool output — drive what you do next.
