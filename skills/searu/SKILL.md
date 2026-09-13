---
name: searu
description: |
  Authorised pen-testing toolkit (searu). Use for security assessment, penetration testing, MITRE
  ATT&CK technique lookup, scanning, and authorised exploitation of in-scope targets. Triggers:
  "pentest", "security assessment", "exploit", "ATT&CK", "scope check", "assess a target".
hooks:
  PreToolUse:
    - matcher: "Bash"
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
- **Never invoke `docker`, `curl`, `wget` or a scanner directly against a target.** The PreToolUse
  hook (`searu scope-hook`) blocks any Bash command that is not a `searu …` call. Drive tools only
  through `searu run`.

## Phases

An engagement flows through ATT&CK-aligned phases. **Before acting in a phase, read its section file
first** (`~/.claude/skills/searu/sections/<file>`):

| When you are… | Read |
| --- | --- |
| starting/resuming an engagement, defining scope, writing the ROE | `sections/scoping.md` |
| fingerprinting a live target | `sections/reconnaissance.md` |
| enumerating endpoints, content, parameters | `sections/discovery.md` |
| detecting an exploitable weakness | `sections/initial-access.md` |
| exercising an authorised weakness and collecting | `sections/exploitation.md` |
| reviewing and summarising what was recorded | `sections/reporting.md` |

Start at scoping unless a valid `./pentest/rules-of-engagement.json` already exists.

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
- `searu tool list` / `searu tool advice <tool>` — the tools, their ATT&CK techniques, and how to drive each.
