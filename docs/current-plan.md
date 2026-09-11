# Searu — current plan & handoff

Living plan and session-handoff for rebuilding the pen-testing toolkit as **Searu**. Detailed enough
to resume in a fresh session. See [architecture.md](architecture.md) for crate diagrams.

> **Superseded framing:** [product-plan.md](product-plan.md) is now the authoritative design (ATT&CK
> as the organising spine, a single `/searu` skill, authorised-is-executable exploitation with
> NIST SP 800-115 tiers). Work is re-sequenced into **milestones**; Milestone 1 is an end-to-end
> exploit of the local CWE-78 lab target. The old "Slice 2 … Slice 11" numbering below is retained
> for reference but the product-plan roadmap (M1.1–M1.5, then M2–M5) is the plan of record.

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

- **Name** Searu — binary `searu` (alias `sr`); repo `searu`; ghcr prefix `searu-`; skill/agent prefix `searu-`; upgrade command `/searu-upgrade`.
- **Architecture** hexagonal / ports-and-adapters (the `../bellman` model): ports in `domain`, use-cases in `app` generic over ports, **one adapter crate per external system**, `cli` as the sole composition root. **No `infra` catch-all crate.** DI via generics; tests via hand-written fakes.
- **Scope is intrinsic** — a domain rule enforced inside `searu run`; **no `check-scope` command**. The PreToolUse hook is a `searu`-only allowlist, not a scope check.
- **`searu` delivery** — installer downloads a prebuilt static binary from GitHub Releases per OS/arch; `cargo build` fallback.
- **Docker images** — pull `ghcr.io/<ns>/searu-<tool>` on first use; build from `images/<tool>.Dockerfile` on pull failure.
- **Hosting** — public GitHub repo (clone-install, Releases, ghcr, Actions).

## Repo state right now

Committed (`f382df4`, `chore: scaffold workspace, CLI, CI and git hooks`) — Slice 1:

```
Cargo.toml                     workspace: members = domain, cli
mise.toml                      [tools] rust = "1.98.1"; [tasks.install-hooks]
.gitattributes                 * text=auto eol=lf   (LF everywhere)
.gitignore                     ignores /old-version/, /.idea/, /target/
CLAUDE.md                      conventions (British English, no comments, latest deps, clean arch, ATDD, hooks)
.github/workflows/ci.yml       jobs cli/fmt, cli/quality, cli/test (checkout@v7, jdx/mise-action@v4)
.githooks/pre-commit  (100755) hygiene (trailing newline, no trailing ws) + fmt + clippy + test
.githooks/commit-msg  (100755) Conventional Commits, subject ≤72, rejects AI trailers
crates/domain/{Cargo.toml, src/lib.rs}   empty lib (doc line only)
crates/cli/{Cargo.toml, src/main.rs, tests/cli.rs}   clap skeleton + version/bare-help tests
```

Uncommitted working changes present in this session: `docs/architecture.md`, `docs/current-plan.md`.

**Not yet done / known deltas to apply in Slice 2:**
- `crates/cli/src/main.rs` (committed) still declares a `check-scope` subcommand — **remove it**.
- `crates/cli/tests/cli.rs` (committed) asserts bare help contains `"check-scope"` — **change to `"run"`**.
- `app`, `adapter-docker`, `adapter-store` crates **do not exist yet** — create and add to workspace members.

## How to resume (build, test, commit)

- Toolchain: `mise install` (installs Rust 1.98.1). Ambient `cargo` on the dev box is 1.96.0; both build edition-2021.
- Enable git hooks once per clone: `mise run install-hooks` (sets `core.hooksPath=.githooks`).
- Build/test (what CI and the pre-commit hook run):
  - `cargo test --all`
  - `cargo fmt --all --check`  (run `cargo fmt --all` to fix)
  - `cargo clippy --all-targets --all-features -- -D warnings`
- Commit: Conventional Commits (`<type>[(scope)][!]: subject`, ≤72 chars, types feat/fix/docs/style/refactor/perf/test/build/ci/chore/revert). **Never** add AI attribution trailers. One commit per slice. Slice 1 was `chore`.
- The pre-commit hook runs fmt/clippy/test on commit; commit-msg validates the message.

## Slice 2 — implementation spec (scope rule + `searu run`)

Task #2 in the task list. Vertical slice through the hexagon; live `docker run` deferred to Slice 8.

**Crates to add** (workspace members): `crates/app`, `crates/adapter-docker`, `crates/adapter-store`.
Dependency direction: `cli → {app, adapter-docker, adapter-store} → domain`; adapters depend on
`domain` only.

**`domain`** (grow `crates/domain/src/lib.rs`, still no external deps):
- `enum EntryKind { Domain, Ip, Cidr, Url }`, `struct ScopeEntry { kind, value: String }`,
  `struct Scope { targets: Vec<ScopeEntry>, exclusions: Vec<ScopeEntry> }`.
- `fn is_in_scope(target: &str, scope: &Scope) -> bool` — port faithfully from
  `old-version/pentest-toolkit/scripts/check_scope.py`:
  - `target_host(t)`: if `t` contains `"://"` take the URL host (strip scheme, userinfo, path, port); else `t.split(':').next()` (host before any `:port`).
  - `host_matches(host, entry)`: Domain → `host == value || host.ends_with(&format!(".{value}"))`; Ip/Cidr → parse `host` as `IpAddr` and test membership of the network `value` (a bare IP is a /32 or /128; implement v4 + v6 CIDR containment with std only — mask compare); Url → `host == target_host(value)`.
  - `host_matches_exact(host, entry)` (only rescues an exclusion): Domain → `host == value`; Url → `host == target_host(value)`; Ip → `IpAddr` equality; Cidr → false.
  - `is_in_scope`: default-deny (no target matches → false); if any exclusion matches → return `any exact target matches`; else true.
- Port traits (co-located in `domain`): `trait RoeRepository { fn load(&self) -> Result<Roe, RepoError>; }` with a minimal `struct Roe { scope: Scope }` for now (extend later); `struct ToolInvocation<'a> { tool: &'a str, target: &'a str, args: &'a [String] }`; `trait ToolRunner { fn run(&self, inv: &ToolInvocation) -> Result<i32, RunnerError>; }`. Error enums `RepoError`, `RunnerError` in `domain`. Sync traits (no async).

**`app`** (`RunTool`, generic over ports; dep: `domain`):
- `struct RunTool<R: RoeRepository, T: ToolRunner> { roe: R, runner: T }`.
- `fn execute(&self, tool: &str, target: &str, args: &[String]) -> Result<i32, RunError>`:
  load ROE (→ `RunError::Repo`); if `!is_in_scope(target, &roe.scope)` → `Err(RunError::OutOfScope(target))` **without touching the runner**; else `runner.run(...)` (→ `RunError::Runner`).
- `enum RunError { Repo(RepoError), OutOfScope(String), Runner(RunnerError) }`.

**`adapter-store`** (`JsonRoeRepository`; deps: `domain`, serde, serde_json):
- serde model `{ "scope": { "targets": [{ "type": "...", "value": "..." }], "exclusions": [...] } }` → map to `domain::Roe`. Map `type` string → `EntryKind`; unknown type → `RepoError`.
- `JsonRoeRepository { path: PathBuf }` reads + parses the file. Keep a pure `fn parse_roe(json: &str) -> Result<Roe, RepoError>` to unit-test without a file.

**`adapter-docker`** (`DockerToolRunner`; deps: `domain`):
- `image_for(tool) = format!("{registry}/searu-{tool}:{version}")` (registry from a field/env, default a `ghcr.io/<owner>` placeholder — owner TBD when the GitHub repo exists; tag = crate `CARGO_PKG_VERSION`).
- pure `fn docker_argv(image: &str, args: &[String]) -> Vec<String>` = `["run", "--rm", image, ...args]` (unit-tested).
- `run` executes `docker` with that argv via `std::process::Command`, returns the exit code or `RunnerError`. Per-tool argument shaping (how the target/flags reach the tool) is **Slice 9**, not here.

**`cli`** (add deps `app`, `adapter-docker`, `adapter-store`; dev-dep `tempfile`):
- Remove the `check-scope` subcommand. Add `run`:
  `searu run <tool> --roe <PATH> --target <TARGET> [-- <ARG>...]`.
- Wire: build `JsonRoeRepository::new(roe)` + `DockerToolRunner::default()`, `RunTool { .. }.execute(tool, target, &args)`.
- Exit codes: `Ok(code)` → that code; `Err(OutOfScope(t))` → eprintln `OUT OF SCOPE: {t}`, exit 1; `Err(Repo)`/`Err(Runner)` → eprintln reason, exit 1.

**Tests (write first — ATDD):**
- domain unit (`#[cfg(test)]` in lib.rs): in-scope exact domain; subdomain via suffix; unlisted → out (default-deny); IP inside CIDR → in, outside → out; URL target resolves to host; excluded host → out; exclusion rescued by an exact target entry → in; IP exact equality.
- app unit (fakes): out-of-scope → `Err(OutOfScope)` and fake `ToolRunner` **never called** (assert with a flag/`unreachable!`); in-scope → runner called once, returns its code; repo failure → `Err(Repo)`.
- adapter-store unit: `parse_roe(SAMPLE)` yields expected entries; unknown `type` → `Err`.
- adapter-docker unit: `docker_argv("img", ["-x"])` == `["run","--rm","img","-x"]`.
- cli acceptance (`crates/cli/tests/cli.rs`, uses `tempfile`): keep `--version` + bare-help (assert `"run"`); add `searu run scan --roe <f> --target evil.example.org` → exit 1 + stderr `OUT OF SCOPE` (no daemon needed). Sample ROE for tests:
  ```json
  { "scope": { "targets": [
      { "type": "domain", "value": "staging.example.com" },
      { "type": "cidr", "value": "10.20.0.0/24" } ],
    "exclusions": [ { "type": "domain", "value": "billing.staging.example.com" } ] } }
  ```

**Pinned dep versions to use** (verified latest 2026-09): serde `1.0.229`, serde_json `1.0.151`,
tempfile `3.27.0`. Already used: clap `4.6.6`, assert_cmd `2.2.2`, predicates `3.1.4`.

## Remaining backlog (after Slice 2)

- **Slice 3 — `searu validate-roe`**: carry `old-version/pentest-toolkit/schemas/roe.schema.json`; validate `./pentest/roe.json`, no default-allow.
- **Slice 4 — `searu scope-hook` (allowlist)**: permit only `searu …` + file reads for target-facing agents; block `docker`/`curl`/raw scanners (exit 2). Does not read the ROE.
- **Slice 5 — `install.sh` + `--check` (+ `install.ps1`)**: register pointers + `.searu-owned` markers into `~/.claude/{agents,skills,commands}/`; rewrite the agent hook command to the installed `searu` path; symlink on Unix, copy on Windows without Dev Mode. Test against a throwaway HOME.
- **Slice 6 — `/searu-upgrade` + release scaffolding**: the upgrade skill + `release.yml` (cross-compile 5 targets) + installer download-with-cargo-fallback.
- **Slice 7 — findings core**: `emit-finding`, tool-run records, `findings_model` (rank, coverage), `redact` (record + report), loot two-store, `secret_context`. Each its own ATDD sub-slice.
- **Slice 8 — Docker tool runner** (needs daemon): pull-ghcr → build-fallback → `docker run` with the engagement dir mounted; first `images/nuclei.Dockerfile`. Live happy-path of Slice 2 completes here.
- **Slice 9 — `searu run <tool>` wrappers** (needs daemon): port the 31 `run_*.py`, one slice per tool, preserving hard-won defaults.
- **Slice 10 — reporting + intel**: `report` (WeasyPrint container), `export-dradis`, CWE/EPSS/KEV, propose/record-exploit.
- **Slice 11 — entry point + agents**: `/searu` router skill (cwd inference + freeform args) + `searu-orchestrator` and `searu-*` tool-agents, wired to the binary + hook.

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
- Docker CLI is installed (29.6.2) but the **daemon may be down**; the Slice 2 scope-refusal path and all argv-construction tests need no daemon.
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
