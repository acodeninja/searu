# Initial access (TA0001)

Detect an exploitable weakness on a discovered endpoint/parameter. This is *detection* — confirming a
class of weakness exists — ahead of the Exploitation phase that exercises it. Where confirming a
weakness means exercising it, that is the Exploitation tier, so the ROE must allow-list the technique
**and** name an authoriser.

## Tools

Choose from this phase's tools (the roster is owned by the tools, not this file):

    searu tool list --phase initial-access

Each line says when to reach for that tool; delegate a run to its specialist, which fetches the how-to
(`searu tool advice <tool>`) and keeps the output out of this conversation.

Many weaknesses only appear behind a login. Mint a session token early with `fetch --method POST`
against the login endpoint (it records a `session-token` in loot), then carry it into the
access-control (`authz --header`) and token-forgery (`jwt`) classes.

## Read the results

    searu findings
    searu observations

A confirmed weakness with its evidence is what authorises moving to Exploitation. Let the recorded
findings — not raw tool output — drive what you do next.
