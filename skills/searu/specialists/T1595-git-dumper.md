---
model: haiku
---

# git-dumper — source disclosure via exposed .git (T1595, CWE-527)

Reconstruct a web app's source tree from an exposed `.git` directory — turning a misconfiguration into
the full codebase. Active tier — allow-listing T1595 in the ROE is enough; no authoriser needed. The
target is the `http://host/.git` URL (recon/feroxbuster often surfaces a reachable `/.git/`).

Run — point it at the exposed `.git`:

    searu run git-dumper --technique T1595 --target http://host:port/.git

Read the results:

    searu findings --tool git-dumper       # a source-disclosure finding when the tree is reconstructed
    searu observations --kind output        # the run's output directory holding the recovered source

The recovered tree lands under `pentest/outputs/git-dumper/<id>/`. Chain it: scan the source with SAST —
`searu run semgrep --target src:pentest/outputs/git-dumper/<id>` — and sweep it for secrets
(gitleaks/trufflehog). Do not paste raw git-dumper output. See `searu tool advice git-dumper` for detail.
