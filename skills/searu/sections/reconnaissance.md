# Reconnaissance (TA0043)

Learn what the target *is* before choosing an attack. Passive/active, read-only: allow-listing the
technique in the ROE is enough — no authoriser needed.

## Tools

- **nmap** (`T1046`) — discover open TCP services on a host (connect + version scan). The target is
  a host or IP, not a URL.
  ```
  searu run nmap --technique T1046 --target host
  ```
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
searu observations --kind service
searu observations --kind server
searu observations --kind tech
searu observations --kind endpoint
```

The `service` values are the open ports and their versions; the `server`/`tech` values are your stack
and OS hints — they decide which SecLists wordlist to pick
in Discovery and which weakness to look for in Initial access. Recon is not a one-shot phase: fold
what you learn back into the next steps.
