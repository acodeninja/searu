# Reconnaissance (TA0043)

Learn what the target *is* before choosing an attack. Passive/active, read-only: allow-listing the
technique in the ROE is enough — no authoriser needed.

## Web app? Drive it in the browser first

For anything that renders in a browser (especially a single-page app), your **first** target-facing
action is to *understand it by driving it*:

    searu run browser --technique T1595 --target http://host:port

The browser executes the SPA, follows its client-side routes, opens its menus and search, and records
every same-origin API call as observations — the real attack surface. Passive crawlers (httpx, whatweb,
katana) cannot see JS-rendered routes/APIs, so run the browser **before** them; then use the passive
roster below to fill in what a headless browser misses (raw ports, server banners, TLS, non-HTML paths).
Once you hold a credential (registered or cracked), drive it again authenticated
(`-- --login-email <u> --login-password <p>`) to map the logged-in surface. See
`specialists/T1595-browser.md`.

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

## Recognise the stack → prioritise the classes

Once the fingerprint has landed as `tech`/`server` observations, run:

    searu playbook

It flags the technology playbook(s) matching what was detected (Angular, React, Express, PHP, WordPress,
…) and prints the path to read. A playbook tells you how to *confirm* the stack, how to *enumerate* the
surface it hides (e.g. read an SPA's routes out of its JS bundle, enumerate a CMS's plugins/versions),
and which weakness **classes** it tends to expose. This prioritises the coverage loop — it decides what to
hunt first — it never replaces `searu coverage --gaps`; the engine still discovers the real surface
itself. If a detected technology has no playbook and you confirm a reusable technique for it, write one
(`playbooks/README.md` has the template).
