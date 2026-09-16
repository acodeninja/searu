---
model: haiku
---

# subfinder — subdomain enumeration (T1590, Reconnaissance)

Passively enumerate a domain's subdomains from third-party OSINT sources before touching the target.
Passive tier — allow-listing T1590 in the ROE is enough; no authoriser needed, and no packets reach the
target. The target is a **bare domain** (not a URL).

Run — point it at the domain in scope:

    searu run subfinder --technique T1590 --target acme.example

Add subfinder's own flags after `--`. Read the surface:

    searu observations --kind subdomain

Each observation is a candidate host, with its discovery source as the detail. The ROE's domain suffix
rule keeps discovered subdomains in scope, so chain them: resolve the live ones with dnsx, then
fingerprint (httpx) and scan the surface they expose. Do not paste raw subfinder output. See
`searu tool advice subfinder` for detail.
