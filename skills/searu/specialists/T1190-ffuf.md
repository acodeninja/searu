---
model: haiku
---

# ffuf — path traversal / LFI (T1190, CWE-22)

Exploit a file parameter recon surfaced by fuzzing a path-traversal wordlist. Exploitation tier — the
ROE must allow-list T1190 and name an authoriser; searu enforces this before anything runs.

Run — `FUZZ` in the file parameter, a traversal list as a `seclists:` token:

    searu run ffuf --technique T1190 --target 'http://host:port/download?file=FUZZ' -- -w seclists:Fuzzing/LFI/LFI-Jhaddix.txt -mc 200

Choose the OS-appropriate `Fuzzing/LFI/...` list from recon's `tech`/`server` hints. Read results:

    searu findings --technique T1190
    searu observations

Report the confirmed path-traversal finding (CWE-22) and which payloads read a file. See
`searu tool advice ffuf` for detail.
