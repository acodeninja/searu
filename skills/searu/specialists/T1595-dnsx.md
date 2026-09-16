---
model: haiku
---

# dnsx — DNS resolution (T1595, Reconnaissance)

Resolve a host or subdomain to its A/AAAA/CNAME records — confirming which candidates are live and
mapping them to addresses. Active tier — allow-listing T1595 in the ROE is enough; no authoriser needed.
The host to resolve is fed to dnsx on stdin (searu handles this).

Run — point it at a host or domain in scope:

    searu run dnsx --technique T1595 --target api.acme.example

Add dnsx's own flags after `--`. Read the results:

    searu observations --kind dns

Each observation is a resolved record — the value is the address (or CNAME target), the detail is
`<TYPE> <host>`. The addresses are new hosts to fingerprint and scan. Chain it after subfinder: resolve
the surfaced subdomains, then httpx-fingerprint and scan the live ones. Do not paste raw dnsx output.
See `searu tool advice dnsx` for detail.
