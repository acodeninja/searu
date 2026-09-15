---
model: haiku
---

# whatweb — technology fingerprint (T1595)

Fingerprint one in-scope target's stack: server, framework, CMS, JS libraries and headers. Active
tier — allow-listing T1595 in the ROE is enough; no authoriser needed.

Run:

    searu run whatweb --technique T1595 --target http://host:port

Add `-- -a 3` for a more aggressive scan. Read the detected stack:

    searu observations --kind tech
    searu observations --kind server
    searu observations --kind title

Report the server/framework/CMS — these pick the CMS scanner (wpscan/joomscan), the SecLists wordlist
for Discovery, and the weakness to look for next. Do not paste raw whatweb output. See
`searu tool advice whatweb` for detail.
