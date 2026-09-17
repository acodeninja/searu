---
model: haiku
---

# fuxploider — unrestricted file upload (T1190, CWE-434)

Fuzz a file-upload form to find which dangerous extensions it accepts — the flaw that escalates to a web
shell and code execution. Exploitation tier — the ROE must allow-list T1190 and name an authoriser.

Run — point it at the page carrying the upload form, and give it an oracle for upload success/failure:

    searu run fuxploider --technique T1190 --target 'http://host:port/upload' -- --not-regex 'not allowed'

`--not-regex` (or `--true-regex`) is a pattern matching a rejected (or accepted) upload — fuxploider
needs it to tell whether an extension slipped through. Read results:

    searu findings --tool fuxploider

An unrestricted-upload finding (CWE-434) means dangerous extensions were accepted; the evidence is how
many slipped through (or that code execution was reached). Upload a web shell in an accepted extension
and browse to it for code execution within the ROE — treat that as full compromise. Do not paste raw
fuxploider output. See `searu tool advice fuxploider` for detail.
