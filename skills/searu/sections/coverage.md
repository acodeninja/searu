# Coverage — be exhaustive, not opportunistic

The objective is not "find *a* bug and stop". It is to try **every applicable technique against every
surface item** until the surface is exhausted. `searu coverage` is how you know where you are.

## The loop

1. **Understand first.** Run `searu run browser --technique T1595 --target <url>` (authenticate with
   `-- --login-email <u> --login-password <p>` once you hold a credential). It renders the app and
   records the routes, API endpoints, parameters and forms as observations — the surface the matrix is
   built from. Passive recon (katana, httpx) adds to it.
2. **Read the matrix.** `searu coverage` prints every `surface-item × applicable-class` pairing and its
   state (`untried` / `attempted` / `succeeded`); `searu coverage --gaps` lists only the untried work.
   The summary line reports how much of the surface has been tried and how many gaps have no tool yet.
3. **Take the next untried pairing** and drive its class's tool against **that specific item**, scoped
   tightly — e.g. `sqlmap`/`ghauri` on one parameter, `dalfox` on one parameter, `corsy` on one
   endpoint, `fuxploider` on one upload form. Scope matters: coverage credits an attempt only when the
   run references the item (its endpoint path / parameter), so a run aimed at one parameter is what
   turns that pairing from `untried` to `attempted`. Delegate noisy runs to the tool's specialist.
4. **Re-read the matrix** and repeat. Keep going until no `untried` automatable pairing remains — do not
   stop at the first success. This replaces "stop when the objective is met": here the objective is an
   exhausted surface.

## Gaps with no tool (`manual`)

Some classes have no searu tool yet — broken access control / IDOR, broken authentication / token
forgery, open redirect / SSRF. These still show as applicable gaps. Work them by hand through
`searu run` where a tool exists for the mechanics (replaying a request with a swapped id or a forged
token), and record what you confirm as a finding so the pairing flips to `succeeded`. When a capability
is missing entirely, name it in the report rather than letting the gap pass silently.

## Known apps

If the target is a recognised application, read `playbooks/<app>.md` first — it maps that app's
weakness categories to concrete surface items, techniques and tools, so the loop heads straight for the
real work instead of rediscovering it. A playbook accelerates the loop; it never replaces it — finish
by clearing the matrix, not the playbook.
