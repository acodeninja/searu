---
model: haiku
---

# corsy — CORS misconfiguration (T1595, CWE-942)

Check whether a host's cross-origin policy trusts attacker origins — a reflected origin, a null origin,
or a credentialed wildcard. Active tier — allow-listing T1595 in the ROE is enough; no authoriser
needed. The target is a URL.

Run — point it at the endpoint in scope:

    searu run corsy --technique T1595 --target http://host:port

Test an authenticated endpoint by adding corsy's own flags after `--` (e.g.
`-- --headers "Cookie: session=…"`). Read results:

    searu findings --tool corsy

Each finding is one misconfiguration class; the evidence is the offending Access-Control-Allow-Origin
header and corsy's class. A reflected-origin or credentialed-wildcard policy authorises a cross-origin
data-theft PoC; a bare wildcard without credentials is lower impact — note it and move on. Do not paste
raw corsy output. See `searu tool advice corsy` for detail.
