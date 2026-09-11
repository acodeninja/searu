# httpx — HTTP probe & fingerprint

httpx probes a target over HTTP and reports what it is: status, title, web server, and detected
technologies. Use it first, black-box, to learn the stack before choosing an exploit.

## How to drive it
- `searu run httpx --technique T1595 --target http://host:port` — the target is passed to httpx with `-u`.
- Read the result with `searu observations` (kinds `endpoint`, `server`, `tech`); the `server`/`tech`
  values are your stack/OS hints (e.g. which SecLists list to pick later).

## Notes
- Active tier: allow-listing the technique in the ROE is enough (no authoriser). It only probes; it
  does not exploit.
