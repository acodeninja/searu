---
model: haiku
---

# gospider — web crawling (T1595, Reconnaissance)

Crawl a web target to map its URLs, forms and linked JavaScript from robots/sitemap/body/JS, building
the attack surface. Active tier — allow-listing T1595 in the ROE is enough; no authoriser needed. The
target is a URL.

Run — point it at the in-scope web root:

    searu run gospider --technique T1595 --target http://host:port

Bound or widen the crawl with gospider's own flags after `--` (e.g. `-- -d 2 -c 10` for depth and
concurrency). Read the surface:

    searu observations --kind endpoint

Each observation is a discovered URL, with how it was found (form/url/javascript/robots) as the detail.
Feed the endpoints and forms into discovery (ffuf/arjun) and initial access (dalfox/sqlmap) for the
parameters worth attacking. Do not paste raw gospider output. See `searu tool advice gospider` for
detail.
