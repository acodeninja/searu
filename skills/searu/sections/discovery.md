# Discovery (TA0007)

Map the reachable surface — content and parameters — on an in-scope target. Active, read-only:
allow-list the technique; no authoriser needed.

## Tools

- **ffuf** content discovery (`T1595`) — fuzz a `FUZZ` keyword against a SecLists wordlist (mounted
  read-only via a `seclists:` token):
  ```
  searu run ffuf --technique T1595 --target http://host:port/FUZZ -- -w seclists:Discovery/Web-Content/common.txt
  ```
- **katana** (`T1595`) — crawl-derived endpoints and parameters, if not already gathered in Recon.

Pick the wordlist from the stack hints Recon recorded. `searu tool advice ffuf` has the filtering
guidance (a catch-all page that defeats auto-calibration, etc.).

## Read the results

```
searu observations --kind endpoint
searu observations --kind param
```

Discovered endpoints and parameters are the input to Initial access — the parameters are where you
test for injection next.
