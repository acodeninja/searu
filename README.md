# Searu

> **searu** · *noun*, neuter (Old English)
> a. stratagem, craft, artifice; trick, b. skill, art; ability, c. device, contrivance; equipment d. war-gear, weapon

Searu is a Claude skill for running authorised security assessments. You tell Claude what you're
testing, it works out which tools to reach for, and Searu actually runs them: in containers, checked
against your rules of engagement, with whatever they turn up written down so you can query it later.

## What it is

Claude does the thinking. Searu does the running and the remembering. It won't exploit anything by
itself; that's the job of the tools it wraps (sqlmap, ffuf, commix, and the rest). What Searu adds is a
gate in front of every run and a record behind it. Before a tool fires, it checks that the target is in
scope and that the technique is one you've authorised. Once it finishes, the output lands in three
places you can search: findings, loot, and recon observations. Tools are grouped by MITRE ATT&CK
technique, so in practice an assessment is just a sequence of techniques you've signed off on.

## Where it runs

Windows, macOS and Linux. You need two things and nothing else:

- Docker, so every tool runs in a throwaway container and nothing lands on your host.
- The `searu` binary, a single executable with no other runtime dependencies.

## A note on authorisation

This is for people who have permission to test. Searu won't touch a target unless it's in scope and the
exact technique is allow-listed in a rules-of-engagement file you write and control; if either check
fails, the run is refused. Pen testers, red teams and CTF players are who it's for. Point it at your own
labs and signed-off engagements, nothing else.

## Install

Grab the latest build for your platform.

On macOS, Linux, or a POSIX shell (Git Bash, WSL):

```sh
curl -fsSL https://raw.githubusercontent.com/acodeninja/searu/main/install.sh | sh
```

That drops the `searu` binary in `~/.local/bin` (override with `SEARU_BIN_DIR`).

On Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/acodeninja/searu/main/install.ps1 | iex
```

That drops `searu.exe` in `%LOCALAPPDATA%\Programs\searu` (override with `$env:SEARU_BIN_DIR`) and
adds that directory to your user PATH, so new shells find it automatically. Pin a release with
`$env:SEARU_VERSION`.

Either installer also registers the `/searu` Claude Code skill into `~/.claude/skills/searu` and the
`/searu-upgrade` command into `~/.claude/commands` (it won't touch a skill or command of that name
you already own; set `SEARU_NO_SKILL=1` to skip this step). Later, run `/searu-upgrade` to update to
the latest release or a release candidate.

Where there's no prebuilt binary yet — Apple silicon or Windows on Arm, for instance — the script
builds from source instead, so you'll need Rust on hand. Either way you also need Docker running,
since every tool runs in a container. Check it took:

```sh
searu tool list        # the tools, and the ATT&CK techniques each one covers
```

Rather not pipe a script into your shell? Download the archive for your OS straight from the
[latest release](https://github.com/acodeninja/searu/releases/latest) and drop `searu` on your `PATH`.

## Contributing

Clone it, switch on the git hooks, and build:

```sh
mise run install-hooks
cargo build
```

To dogfood your changes, install the working-tree build onto your `PATH` with `mise run
install-local` — it drops `searu` in `~/.cargo/bin` via `cargo install`. Re-run it after each change;
you still need Docker running to use the tools.

There are ready-made rules-of-engagement files under `examples/` for the practice labs.
