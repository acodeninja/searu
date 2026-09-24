# Technology playbooks

Reusable, transferable attack techniques **per technology** — not per application. A playbook captures
what generalises about a stack (how to confirm it, how to enumerate its surface, which weakness classes
it tends to expose and how they manifest), so the next Angular app or the next PHP app benefits from what
the last one taught. It never encodes one target's answers (fixed routes, specific ids, an app's secret
paths) — those belong to that engagement, not to the toolkit.

## How they are used

`whatweb` and the other fingerprinting tools record the detected stack as `tech`/`server` observations.
`searu playbook` reads those observations and flags the playbooks whose slug matches a detected
technology, printing the path to read. This *augments and prioritises* the coverage loop — it decides
which classes to hunt first — it never replaces `searu coverage --gaps`; the engine still discovers the
real surface itself.

## Naming

One file per technology, `<tech-slug>.md`, where the slug is the lower-cased leading identifier of the
`tech` value (`PHP/8.1.2` → `php`, `Angular 15.0` → `angular`). This `README.md` is not a playbook.

## Section template

Each playbook keeps to these headings (only generic classes and techniques — no target routes/hosts):

    # <Technology>

    ## Confirm it
    How to be sure the target really is this stack (a header, a bundle signature, a version-revealing
    error), beyond the fingerprint tool's guess.

    ## Enumerate the surface
    How to expand the attack surface this stack tends to hide (e.g. read client-side routes out of the
    JS bundles, enumerate plugins/users, provoke a debug/version response) and feed it back into
    `searu run browser --seed`, discovery, and the coverage matrix.

    ## Weakness classes it tends to expose
    The coverage classes worth prioritising for this stack and how they usually manifest here, pointing
    at the generic `sections/` and `specialists/` for the mechanics rather than restating them.

## Extend me

When you confirm a technique that would transfer to the next target on this stack, add it to that
technology's playbook (copy the template into a new `<tech-slug>.md` if none exists). The canonical copy
lives in the repo under `skills/searu/playbooks/`; `install-skill` deploys it and `searu playbook` reads
the deployed copy, so back-port a live addition to the repo and commit it — that is how the knowledge
compounds across engagements. Keep it generic: if it only applies to one app, it is a finding, not a
playbook entry.
