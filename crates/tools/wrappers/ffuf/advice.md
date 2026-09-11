# ffuf — web fuzzer (content discovery and path traversal)

ffuf fuzzes a `FUZZ` keyword in the target URL against a wordlist. With a content-discovery list it
finds unlinked routes; with a path-traversal (LFI) list it exploits a file parameter recon surfaced.

## How to drive it
- Put `FUZZ` where the payload goes and pass the list as a `seclists:` token — searu fetches that one
  list once and mounts it read-only:
  `searu run ffuf --technique T1190 --target 'http://host:port/download?file=FUZZ' -- -w seclists:Fuzzing/LFI/LFI-Jhaddix.txt -mc 200`
- Pick the list from recon: use the `tech`/`server` observations to choose the OS-appropriate
  `Fuzzing/LFI/...` list, and the `param` observations to place `FUZZ`.
- ffuf's default matcher already drops 404s; add `-mc 200` to keep only successful reads.
- Read the result with `searu findings` (a confirmed path-traversal finding, CWE-22, when the matched
  payloads are traversals) or `searu observations` (an `endpoint` per hit, for content discovery).

## Notes
- Content discovery is Active (T1595, allow-list only); using it to read files off the host is
  Exploitation (T1190) and needs an authoriser in the ROE.
