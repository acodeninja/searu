# Discovery (TA0007)

Map the reachable surface — content and parameters — on an in-scope target. Active, read-only:
allow-list the technique; no authoriser needed.

## Tools

Choose from this phase's tools (the roster is owned by the tools, not this file):

    searu tool list --phase discovery

Each line says when to reach for that tool; delegate a run to its specialist, which fetches the how-to
(`searu tool advice <tool>`) and keeps the output out of this conversation. Pick the wordlist from the
stack hints Recon recorded.

## Read the results

    searu observations --kind endpoint
    searu observations --kind param

Discovered endpoints and parameters are the input to Initial access — the parameters are where you
test for injection next.
