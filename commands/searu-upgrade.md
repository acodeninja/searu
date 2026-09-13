---
description: Upgrade the searu binary and the /searu skill to the latest full release, or to a release candidate.
allowed-tools: AskUserQuestion, Bash
---

<!-- searu-owned -->

Upgrade searu by re-running its installer at the channel the operator chooses. This replaces the
`searu` binary and re-installs the `/searu` skill and this command.

Best run in a **fresh session**: mid-engagement the `/searu` skill's PreToolUse scope-hook blocks any
non-`searu` Bash command, which would stop the installer's `curl`/`irm`.

## Steps

1. **Ask the operator which channel** with AskUserQuestion:
   - **Full release** (recommended) — the latest stable version.
   - **Release candidate** — the newest prerelease, for testing an unreleased build.

2. **If they chose a release candidate, resolve the newest prerelease tag** on `acodeninja/searu`:
   - Prefer the GitHub CLI: `gh release list --repo acodeninja/searu --limit 30` and take the most
     recent entry marked as a prerelease (a `v<version>-rc<N>` tag).
   - If `gh` is unavailable, use the API:
     `curl -fsSL https://api.github.com/repos/acodeninja/searu/releases` and take the first entry with
     `"prerelease": true` — its `tag_name` is the target.

3. **Run the installer for this OS** (a fresh process — do not try to self-update via a `searu`
   subcommand). It downloads the binary, verifies it, puts it on PATH, and re-runs
   `searu install-skill`:
   - **macOS / Linux / Git Bash / WSL:**
     - Full: `curl -fsSL https://raw.githubusercontent.com/acodeninja/searu/main/install.sh | sh`
     - Release candidate: `export SEARU_VERSION=<tag>; curl -fsSL https://raw.githubusercontent.com/acodeninja/searu/main/install.sh | sh`
   - **Windows (PowerShell):**
     - Full: `irm https://raw.githubusercontent.com/acodeninja/searu/main/install.ps1 | iex`
     - Release candidate: `$env:SEARU_VERSION='<tag>'; irm https://raw.githubusercontent.com/acodeninja/searu/main/install.ps1 | iex`

4. **Confirm** the result: `searu --version` and `searu tool list`. Tell the operator to restart this
   session so the refreshed `/searu` skill is loaded.
