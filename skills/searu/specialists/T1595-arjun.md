---
model: haiku
---

# arjun — hidden parameter discovery (T1595)

Discover query/body parameters an in-scope endpoint secretly accepts. Active tier — allow-listing
T1595 in the ROE is enough; no authoriser needed.

Point it at a specific endpoint (the path matters):

    searu run arjun --technique T1595 --target http://host:port/endpoint

Add `-- -m POST` for body parameters, `-- -m JSON` for a JSON body. Read the results:

    searu observations --kind param

Each `param` observation is a hidden parameter arjun confirmed. Feed these to Initial access — they
are where you test for injection (sqlmap `-p`, ffuf `FUZZ`, dalfox). Do not paste raw arjun output.
See `searu tool advice arjun` for detail.
