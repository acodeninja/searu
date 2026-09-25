---
name: searu
description: |
  Authorised pen-testing toolkit (searu). Use for security assessment, penetration testing, MITRE
  ATT&CK technique lookup, scanning, and authorised exploitation of in-scope targets. Triggers:
  "pentest", "security assessment", "exploit", "ATT&CK", "scope check", "assess a target".
allowed-tools: Bash Read Write Edit Grep Glob Agent Task TodoWrite NotebookEdit WebFetch WebSearch
hooks:
  PreToolUse:
    - matcher: "*"
      hooks:
        - type: command
          command: "searu scope-hook"
---

# searu — authorised pen-testing toolkit

`searu` turns Claude Code into an authorised pen-testing operator. It is organised around the MITRE
ATT&CK framework and drives containerised tools that only run against in-scope, authorised targets.
You decide what to do next; `searu` gates and runs each step and remembers the results.

## Safety model — read before acting

- **Every target-facing action goes through `searu`.** It loads `./pentest/rules-of-engagement.json`
  and refuses an out-of-scope target before any network call. Scope is intrinsic — there is no way
  around it.
- **Exploitation is gated by the ROE.** A technique runs only if its exact ATT&CK ID is allow-listed;
  the Exploitation tier also needs a named authoriser, and destructive techniques need
  `destructive_authorised: true`.
- **Never reach a target with anything but `searu`.** The PreToolUse hook (`searu scope-hook`) blocks
  any Bash or PowerShell command that is not a `searu …` call, and blocks non-searu skills and MCP tools
  outright (the searu family — `searu` and its `searu-*` kin — passes so you can reload its guidance).
  Drive tools only through `searu run`. Nothing else — `docker`, `curl`, `wget`, a scanner, a browser
  skill — may touch a target.
- **`WebFetch`/`WebSearch` are for off-target research only.** They are allowed so you can look up a CVE
  or a library advisory while you scan, but the hook **blocks a `WebFetch` whose host is an in-scope
  target** (on any port) — the target is reachable only through `searu run`. `WebSearch` (no host) is
  always allowed. Never use `WebFetch` to fetch, probe, or exfiltrate to the target.

## Phases

An engagement flows through ATT&CK-aligned phases. **Before acting in a phase, read its section file
first** (`~/.claude/skills/searu/sections/<file>`):

| When you are…                                                    | Read                         |
|------------------------------------------------------------------|------------------------------|
| starting/resuming an engagement, defining scope, writing the ROE | `sections/scoping.md`        |
| understanding a web app before scanning it (drive it, browser)   | `sections/reconnaissance.md` |
| fingerprinting a live target                                     | `sections/reconnaissance.md` |
| enumerating endpoints, content, parameters                       | `sections/discovery.md`      |
| detecting an exploitable weakness                                | `sections/initial-access.md` |
| exercising an authorised weakness and collecting                 | `sections/exploitation.md`   |
| driving toward exhaustive coverage of the attack surface         | `sections/coverage.md`       |
| reviewing and summarising what was recorded                      | `sections/reporting.md`      |

Start at scoping unless a valid `./pentest/rules-of-engagement.json` already exists. Then, for a web/SPA
target, the **first target-facing action is `searu run browser`** — drive the app to understand it before
you reach for any scanner or exploit tool (`sections/reconnaissance.md` says how).

The objective is exhaustive, not opportunistic: try every applicable technique against every discovered
surface item. Understand the app first by driving it in the browser, then work `searu coverage --gaps`
until no automatable pairing is left untried — do not stop at the first success. Once you have
fingerprinted the stack, run `searu playbook` to read the technology playbook(s) for what you detected
(e.g. Angular, PHP) — they prioritise which weakness classes to hunt and how they manifest on that stack,
augmenting the coverage loop rather than replacing it.

For a noisy tool run, delegate it to its **specialist** rather than running it inline: spawn
`specialists/<technique>-<tool>.md` via the Agent tool on the `model:` that file names, so scanner
output stays out of this conversation. Scope and authorisation are still enforced by `searu` inside
the specialist.

## Commands

- `searu attack list [--tactic TAxxxx]` / `searu attack show <Txxxx>` — browse the embedded ATT&CK matrix.
- `searu validate-roe [--roe <path>]` — check a rules-of-engagement file.
- `searu run <tool> --technique <Txxxx> --target <t> [-- <tool args>]` — run a containerised tool
  against an in-scope, authorised target (needs Docker).
- `searu findings [--technique|--severity|--tool]`, `searu loot [--category] [--reveal]`,
  `searu observations [--kind]` — query what was recorded under `./pentest/`.
- `searu coverage [--gaps]` — the attack surface crossed with the technique classes that apply to it,
  each pairing scored untried/attempted/succeeded; `--gaps` lists the untried work to drive to zero.
- `searu playbook` — list the technology playbooks and flag those matching the engagement's `tech`
  observations, so you read the right per-stack techniques for what was fingerprinted.
- `searu tool list [--phase <phase>]` — the tools; with `--phase`, the phase's tools and when to use each.
- `searu tool advice <tool> [--phase <phase>]` — how to drive a tool: invoke, interpret, chain (per phase).
