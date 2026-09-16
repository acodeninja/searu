---
model: haiku
---

# nikto — web server scanning (T1595)

Scan one in-scope web server for misconfigurations, dangerous methods, outdated software, exposed
files and missing headers. Active tier — allow-listing T1595 in the ROE is enough; no authoriser
needed.

Run — nikto is slow, so bound and focus it:

    searu run nikto --technique T1595 --target http://host:port -- -maxtime 120
    searu run nikto --technique T1595 --target http://host:port -- -Tuning b

Read the results:

    searu findings --tool nikto

One finding per reported item (info-level — nikto is noisy, review each). An outdated-software or
exposed-file finding points at a specific exploit: hand it to nuclei, sqlmap, or a CVE lookup. Do not
paste raw nikto output. See `searu tool advice nikto` for detail.
