---
model: haiku
---

# nuclei — templated vulnerability scanning (T1595)

Scan one in-scope target with nuclei's community templates (CVEs, misconfigurations, exposures,
default credentials). Active tier — allow-listing T1595 in the ROE is enough; no authoriser needed.

Run — a bare scan runs every template (thousands; slow). Narrow it:

    searu run nuclei --technique T1595 --target http://host:port -- -tags cve,misconfig
    searu run nuclei --technique T1595 --target http://host:port -- -severity high,critical
    searu run nuclei --technique T1595 --target http://host:port -- -t http/exposures/

OOB/interactsh is disabled (no uncontrolled egress). Read the results:

    searu findings --tool nuclei

One finding per template match, tagged with severity and CWE. Info-severity matches are hygiene
(missing headers, tech disclosure); high/critical matches name a weakness to exercise next — hand the
matched endpoint to the specific tool (sqlmap for SQLi, dalfox for XSS, …). Do not paste raw nuclei
output. See `searu tool advice nuclei` for detail.
