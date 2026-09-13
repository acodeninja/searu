# Reconnaissance (TA0043)

Learn what the target *is* before choosing an attack. Passive/active, read-only: allow-listing the
technique in the ROE is enough — no authoriser needed.

## Tools

- **httpx** (`T1595`) — probe and fingerprint: status, title, server, detected technologies.
  ```
  searu run httpx --technique T1595 --target http://host:port
  ```
- **katana** (`T1595`) — crawl for reachable endpoints (and parameters, which feed Discovery).
  ```
  searu run katana --technique T1595 --target http://host:port
  ```

Run `searu tool advice httpx` / `searu tool advice katana` for the per-tool detail; don't re-read raw
tool output.

## Read the results

Recon lands in observations:

```
searu observations --kind server
searu observations --kind tech
searu observations --kind endpoint
```

The `server`/`tech` values are your stack and OS hints — they decide which SecLists wordlist to pick
in Discovery and which weakness to look for in Initial access. Recon is not a one-shot phase: fold
what you learn back into the next steps.
