---
model: haiku
---

# tlsx — TLS surface (T1595, Reconnaissance)

Read a host's TLS certificate (subject, SANs, issuer, validity) and its negotiated version/cipher —
expanding the attack surface and surfacing related hostnames. Active tier — allow-listing T1595 in the
ROE is enough; no authoriser needed. The target is a `host:port` endpoint.

Run — point it at the TLS endpoint in scope:

    searu run tlsx --technique T1595 --target acme.example:443

Enumerate supported versions/ciphers with tlsx's own flags after `--` (e.g. `-- -ve -ce`). Read the
results:

    searu observations --kind tls

The value is the certificate subject; the detail carries the endpoint and negotiated version/cipher. The
certificate's SAN hostnames are additional in-scope hosts — add them to the surface (resolve with dnsx,
fingerprint with httpx). A weak or expired TLS config is a reportable weakness. Do not paste raw tlsx
output. See `searu tool advice tlsx` for detail.
