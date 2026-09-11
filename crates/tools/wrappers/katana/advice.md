# katana — crawl to discover endpoints and parameters

katana crawls a web app and reports the endpoints it links to and the parameters they take. Use it,
black-box, to map the attack surface before choosing an exploit — e.g. to find a `/login` form or a
`/download?file=` parameter.

## How to drive it
- `searu run katana --technique T1595 --target http://host:port` — the seed URL is passed to katana with `-u`.
- Read the map with `searu observations` (kinds `endpoint`, `param`); pick the injectable
  endpoint/parameter to point the exploit tool at next.
- Add katana flags after `--` if you need deeper crawling (e.g. `-- -d 3 -jc`).

## Notes
- Active tier: allow-listing the technique in the ROE is enough. It crawls; it does not exploit.
