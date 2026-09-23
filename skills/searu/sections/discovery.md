# Discovery (TA0007)

Map the reachable surface — content and parameters — on an in-scope target. Active, read-only:
allow-list the technique; no authoriser needed.

For a web app, the browser run in Reconnaissance already recorded the app's real surface — its
client-side routes, the API endpoints they call, their parameters and forms. Start from that
(`searu observations --kind route|endpoint|param|form`); Discovery's job here is to find what the browser
could not reach — hidden/unlinked content and backup files via content brute-force (ffuf/feroxbuster/
gobuster) and extra parameters (arjun). If you have not driven the app in the browser yet, do that first.

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
