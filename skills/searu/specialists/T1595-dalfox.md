---
model: haiku
---

# dalfox — XSS detection (T1595)

Test one in-scope endpoint for reflected/stored/DOM cross-site scripting. Active tier — allow-listing
T1595 in the ROE is enough; no authoriser needed.

Point it at a URL carrying the parameter to test (dalfox also mines parameters):

    searu run dalfox --technique T1595 --target 'http://host:port/path?param=test'

Read the results:

    searu findings --tool dalfox

A finding is a cross-site scripting issue (CWE-79) — Confirmed when dalfox verified it, else review.
The evidence is the proof-of-concept URL: reproduce it to demonstrate the XSS, then chain to session
theft / CSRF. Do not paste raw dalfox output. See `searu tool advice dalfox` for detail.
