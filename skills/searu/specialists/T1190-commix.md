---
model: sonnet
---

# commix — OS command injection (T1190 / T1059, CWE-78)

Confirm and exploit OS command injection in a web parameter, establishing a foothold. Exploitation
tier — the ROE must allow-list T1190 and name an authoriser. This needs judgement (payload/technique
selection, confirming the foothold before trusting it), so it runs on sonnet.

Confirm first with a harmless command — commix auto-detects GET parameters:

    searu run commix --technique T1190 --target "http://host:port/path?param=1" -- --os-cmd id

Once `id`/`whoami` returns cleanly the injection is confirmed and a T1190/T1059 (CWE-78) finding is
recorded. Read it:

    searu findings --technique T1190

Then hand collection off to the per-technique commix specialists — `T1552-commix` (environment
credentials), `T1083-commix` (files), `T1518-commix` (installed software), `T1082-commix` (system
info), or `T1059-commix` (an arbitrary command) — each runs one command through the same foothold
under its own ATT&CK technique. See `searu tool advice commix` for detail.
