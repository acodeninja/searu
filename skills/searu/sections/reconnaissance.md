# Reconnaissance (TA0043)

Learn what the target *is* before choosing an attack. Passive/active, read-only: allow-listing the
technique in the ROE is enough — no authoriser needed.

## Tools

Choose from this phase's tools — the roster is owned by the tools, not this file, so a new tool appears
here automatically:

    searu tool list --phase reconnaissance

Each line says when to reach for that tool. Delegate a run to the tool's specialist, which fetches the
how-to (`searu tool advice <tool>`) and keeps the scanner output out of this conversation.

## Read the results

Recon lands in observations — `service` (open ports + versions), `server`/`tech` (stack/OS hints) and
`endpoint`:

    searu observations

The stack hints decide which SecLists wordlist to pick in Discovery and which weakness to look for in
Initial access. Recon is not a one-shot phase: fold what you learn back into the next steps.
