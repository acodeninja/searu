# Searu — current plan & handoff

Living plan and session-handoff for rebuilding the pen-testing toolkit as **Searu**. Detailed enough
to resume in a fresh session. See [architecture.md](architecture.md) for crate diagrams.

> [product-plan.md](product-plan.md) is the authoritative design (ATT&CK as the organising spine, a
> single `/searu` skill, authorised-is-executable exploitation with NIST SP 800-115 tiers). Work is
> sequenced into **milestones** (M1–M5), one ATDD slice per commit. M1 (end-to-end exploit of the
> local CWE-78 lab) has shipped; see *Current status* below for where we are.

## Why

The previous toolkit *was* the user's `~/.claude` directory: 61 Python scripts (~17k lines) on
absolute paths, 38 scanners installed natively, and a `scope_hook.py` gate depending on a shebang +
exec-bit (broken on Windows). It could not be installed or updated. It now lives in `old-version/`
as a **read-only reference** (git-ignored, never committed) we port semantics and tests from.

Searu is a clean-slate rebuild on gstack's model: a self-contained cloneable repo that installs and
updates via one script, registers into `~/.claude` with thin pointers, keeps runtime state out of
`~/.claude`, and runs on Windows/macOS/Linux. Outside dependencies collapse to two: **Docker** (every
scanner containerised) and **one prebuilt `searu` Rust binary** (zero runtime deps).

## Working method

Small vertical slices, each a full ATDD cycle: write the failing test first → implement the minimum
to pass → refactor → **commit** (one commit per slice) → pause for review. Do not batch slices.

## Locked decisions

- **Name** Searu — binary `searu`; repo `searu`; ghcr prefix `searu-`; upgrade command `/searu-upgrade`.
- **Single skill, no registered agents** — only `/searu` is registered. Context-heavy tool runs are
  spawned as *ephemeral* subagents from prompt files under `searu/specialists/`; there are no
  `searu-*` agents or skills registered anywhere.
- **Skill payload authored directly** — `SKILL.md`, `sections/`, `specialists/` are committed files,
  not generated from a `SKILL.md.tmpl`; a small CI/test check keeps `manifest.json` and the
  specialist `model:` headers honest.
- **Architecture** hexagonal / ports-and-adapters (the `../bellman` model): ports in `domain`, use-cases in `app` generic over ports, **one adapter crate per external system**, `cli` as the sole composition root. **No `infra` catch-all crate.** DI via generics; tests via hand-written fakes.
- **Scope is intrinsic** — a domain rule enforced inside `searu run`; **no `check-scope` command**. The PreToolUse hook is a `searu`-only allowlist, not a scope check.
- **`searu` delivery** — `install.sh`/`install.ps1` download a prebuilt binary from GitHub Releases per OS/arch with a `cargo install` fallback; `mise run install-local` builds the local checkout for development.
- **Docker images** — built on first use from each tool crate's embedded `Dockerfile`; pull-through of `ghcr.io/<ns>/searu-<tool>` is planned.
- **Hosting** — public GitHub repo (clone-install, Releases, ghcr, Actions).

## Current status

The hexagon is built and walking. Workspace crates (`Cargo.toml` members): `domain`, `app`,
`adapter-store`, `adapter-docker`, `tools/parser`, `tools/registry`, the five tool wrappers
(`commix`, `ffuf`, `httpx`, `katana`, `sqlmap`), `cli`, `xtask`.

Shipped:

- **ATT&CK reference layer** — full Enterprise matrix embedded offline via `cargo xtask attack-sync`;
  `searu attack list|show`.
- **Scope + the authorisation gate** — `domain::is_host_in_scope`, `gate::decide`, `technique::tier_of`;
  `searu run` refuses out-of-scope / unauthorised targets before any container starts.
- **Containerised tool runner** — `DockerToolRunner` builds each tool crate's embedded `Dockerfile`
  on first use, runs it with `--add-host=host.docker.internal:host-gateway`.
- **Five tools** — commix (CWE-78, end-to-end against the live lab), httpx + katana (black-box
  recon), sqlmap (CWE-89), ffuf (content discovery / CWE-22), plus a download-once SecLists wordlist
  cache with read-only mounts.
- **Three engagement stores** under `./pentest/` — findings, loot, observations — with
  `searu findings|loot|observations` queries; ROE default path `pentest/rules-of-engagement.json`.
- **M2 — ROE tooling & backstop** — `searu validate-roe` (loads a ROE and checks every allow-listed
  ID against the embedded ATT&CK matrix; `app::ValidateRoe`) and `searu scope-hook` (strict allowlist,
  only `searu …` Bash passes else exit 2; pure `domain::scope_hook::decide`).
- **Binary installers** — `install.sh`, `install.ps1`, and `mise run install-local` (see *Locked
  decisions*). Release/CI scaffolding (release-please, cross-compiled Linux + Windows assets).
- **M5 — `/searu` skill payload (router + sections + specialists)** — `skills/searu/SKILL.md` (router
  with the `PreToolUse -> searu scope-hook` frontmatter) + six phase `sections/` + `manifest.json` +
  eleven `specialists/` (one per registry binding, each naming a `model:`), guarded by registry-driven
  `xtask` consistency tests. `mise run install-local` installs the whole payload into
  `~/.claude/skills/searu/` (copy done in Rust via `xtask install-skill`, no shell dependency).

Not yet built: M4 reporting/intel; the release-installer `~/.claude` pointer (M5 slice 4) and
`/searu-upgrade` (slice 5); plus the deferred credential-access section.

## How to resume (build, test, commit)

- Toolchain: `mise install` (installs Rust 1.98.1). Ambient `cargo` on the dev box is 1.96.0; both build edition-2021.
- Enable git hooks once per clone: `mise run install-hooks` (sets `core.hooksPath=.githooks`).
- Build/test (what CI and the pre-commit hook run):
  - `cargo test --all`
  - `cargo fmt --all --check`  (run `cargo fmt --all` to fix)
  - `cargo clippy --all-targets --all-features -- -D warnings`
- Commit: Conventional Commits (`<type>[(scope)][!]: subject`, ≤72 chars, types feat/fix/docs/style/refactor/perf/test/build/ci/chore/revert). **Never** add AI attribution trailers. One commit per slice.
- The pre-commit hook runs fmt/clippy/test on commit; commit-msg validates the message.

## Remaining work (by milestone)

One ATDD slice per commit; pause for review between slices. (M2 — `validate-roe` + `scope-hook` —
has shipped; see *Current status*.)

**M3 — more tools (in progress)**
- Remaining wrappers, one slice each (nmap, nuclei, dalfox, testssl, …), every one a new tool crate
  bound to its ATT&CK cell — never a new command; preserve each tool's hard-won defaults.

**M4 — reporting & intel**
- `emit-finding`, `report` (WeasyPrint container), Dradis export; CWE/EPSS/KEV via a new
  `adapter-intel`; `propose-exploits`/`record-exploit`. ATT&CK coverage heat-map + CWE attack-chains;
  RoE appendix after the executive summary; redaction at record- *and* report-time.

**M5 — install & the `/searu` skill**
Author the skill payload directly (no template generator). Planned slice sequence:
1. ~~`searu scope-hook` subcommand~~ — **shipped with M2.**
2. ~~`SKILL.md` router + `sections/` + `manifest.json`~~ — **shipped** (six sections;
   credential-access deferred until cred tools land). `mise run install-local` installs the skill.
3. ~~`specialists/` — one prompt per (technique × tool), each naming a `model:`~~ — **shipped** (all
   11 registry bindings; a registry-driven `xtask` test enforces coverage + model headers).
4. Extend `install.sh`/`install.ps1` to register the single `~/.claude/skills/searu/` pointer +
   `.searu-owned` markers + hook rewrite (symlink on Unix, copy on Windows without Dev Mode);
   detect-and-skip a user's own skill; test against a throwaway HOME.
5. `/searu-upgrade` command + release scaffolding.

## old-version reference map (semantics/tests to port)

- Scope: `old-version/pentest-toolkit/scripts/check_scope.py`; hook (redesign as allowlist): `scope_hook.py`.
- ROE: schema `.../schemas/roe.schema.json`, example `.../examples/roe.example.json`, validator `.../scripts/validate_roe.py`, techniques `.../scripts/techniques.py`.
- Findings: `.../scripts/{emit_finding,findings_model,redact,loot,secret_context,tool_run}.py`.
- Exploitation gates: `.../scripts/{exploit_gate,propose_exploits,record_exploit}.py`.
- Report/intel: `.../scripts/{generate_report,export_dradis,cwe_catalog,exploit_intel}.py`; `.../reporting/{Dockerfile,build.py,report.css}`.
- Tool wrappers: `.../scripts/run_*.py` (31). Install specs → Dockerfiles: `.../manifests/*.yaml` (48).
- Agents/skill/setup: `old-version/agents/pentest-*.md`, `old-version/skills/pentest-orchestrator/SKILL.md`, `old-version/setup.sh`, `.../scripts/provision.sh`.
- Deep design rationale (why each safety property exists): `old-version/CLAUDE.md`.

## Conventions & gotchas (learned this session)

- **The Write tool strips the final trailing newline.** After writing any file, verify and append one (`[ -n "$(tail -c 1 f)" ] && printf '\n' >> f`). The pre-commit hook fails a commit otherwise.
- **`core.filemode` is false on this Windows box**, so `chmod +x` is not recorded by git. Executable files (git hooks, shell scripts) must be staged with `git update-index --chmod=+x <file>` to land as mode `100755` (Unix clones skip non-executable hooks).
- British English everywhere; **no code comments** (naming + clear logic; doc comments only where they earn it) — see `CLAUDE.md`.
- **Pin every dependency to the current latest** — look it up online before adding/bumping (crates, Actions, toolchain, base images). Do not trust memory for versions.
- Docker CLI is installed (29.6.2) but the **daemon may be down**; the scope-refusal path and all argv-construction tests need no daemon.
- `old-version/` is git-ignored on purpose; read it, never stage it.

## Invariants to preserve (safety properties from old-version)

- **Scope** — `searu run` refuses an out-of-scope target (default-deny, most-specific-wins, exclusion overridden only by an exact target); the allowlist hook forces agents through `searu`. Attribution and third-party-hosting judgement stay behavioural (orchestrator/skill prose).
- **Exploitation is proposal-only** until the ROE names an authoriser; a single reader of that field; unauthorised is the well-formed default and exits 0, not a refusal; the proposer never executes.
- **Redaction twice** (record-time + report-time; no ROE field disables the report pass); only unsalted digests derivable; screenshot base64 skipped by pattern-scan but scrubbed by equality.
- **Two stores joined by fingerprint** — findings keep `sha256_12` never the value; loot keeps plaintext (0600 in 0700); renderers mask by equality.
- **Coverage from tool-run records** on every path; `silent` vs `missing` stays distinguishable.
- **`secret_context`** only downgrades, never `info`, never infers liveness, whole-value anchored.
- **Ranking** — `confirmed` status + `is_dependency` weighting; attack-chains render only when every link is satisfied by a specific-CWE issue.

## Environment notes

- Primary working dir: `C:\Users\Lawrence\Documents\GitHub\pentest-toolkit`; sibling model project `..\bellman`.
- Rust 1.98.1 pinned via `mise.toml` (local box has 1.96.0 active; mise installs the pinned one).
- The Bash tool runs under Git Bash, so `install.sh` and the POSIX git hooks are testable on Windows here.
