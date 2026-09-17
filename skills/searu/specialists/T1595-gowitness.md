---
model: haiku
---

# gowitness — screenshot triage (T1595, Reconnaissance)

Capture what a URL renders — a login page, admin panel, default app, or error — to prioritise targets
visually. Active tier — allow-listing T1595 in the ROE is enough; no authoriser needed. The target is a
URL.

Run — point it at the in-scope web root:

    searu run gowitness --technique T1595 --target http://host:port

Read the results:

    searu observations --kind screenshot    # the captured URL and its page title
    searu observations --kind output         # the run's output directory holding the image file

The image file lands under `pentest/outputs/gowitness/<id>/`. Eyeball the screenshots to pick the
interesting hosts, then fingerprint (httpx) and crawl (gospider) the ones worth attacking. Do not paste
raw gowitness output. See `searu tool advice gowitness` for detail.
