---
model: haiku
---

# crlfuzz — CRLF injection (T1595, CWE-93)

Fuzz a URL for carriage-return/line-feed injection — the flaw that lets you inject response headers
(session fixation, cache poisoning, open redirect). Active tier — allow-listing T1595 in the ROE is
enough; no authoriser needed. The target is a URL, ideally one carrying a parameter.

Run — point it at the parameterised endpoint in scope:

    searu run crlfuzz --technique T1595 --target 'http://host:port/path?param=x'

Change method or body with crlfuzz's own flags after `--` (e.g. `-- -X POST -d 'a=b'`). Read results:

    searu findings --tool crlfuzz

Each finding is one injectable URL; the evidence is the payload URL that injected a header. Reproduce it
to inject a `Set-Cookie` or `Location` header and escalate to session fixation or an open redirect
within the ROE. Do not paste raw crlfuzz output. See `searu tool advice crlfuzz` for detail.
