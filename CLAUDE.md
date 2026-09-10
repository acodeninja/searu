# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

Searu — a cross-platform pen-testing toolkit for authorised engagements, built as a self-contained,
cloneable payload that installs into `~/.claude` via thin pointers (never scattering files) and runs
on Windows, macOS, and Linux. It replaces a previous Python toolkit that *was* the user's `~/.claude`
directory; that code lives in `old-version/` as a **read-only reference** and is never committed.

Two outside dependencies only: **Docker** (every scanner runs in a container) and the single
**`searu` Rust binary** (zero runtime deps, replacing all the old Python scripts).

## Conventions

### Language
British English everywhere — prose, identifiers, output strings, docs (authorise, behaviour,
colour, licence).

### Comments
Do not write comments. Code and config document themselves through naming and clear logic. The only
acceptable comment explains a genuinely non-obvious edge-case reason for doing something unusual —
and even then, prefer a well-named function. Rust doc comments (`//!`, `///`) are allowed but keep
them terse and only where they earn their place.

### Dependency versions
Always pin to the current latest version. Before adding or bumping any dependency — Cargo crates,
GitHub Actions, the Rust toolchain, base images — look up the latest release on the internet and use
it. Do not rely on memory for version numbers.

### Clean architecture
Layers are crates: `cli → infra → application → domain`, dependencies point inward only, and
`domain` depends on nothing external. The rule is enforced by what each crate lists under
`[dependencies]`: the domain crate physically cannot reach for Docker, clap, or the filesystem. Keep
it that way.

### ATDD
Work in small vertical slices, each a full cycle: write the failing acceptance test first (CLI
behaviour via `assert_cmd`; use cases via in-memory fake ports; domain rules as pure unit tests),
implement the minimum to pass, refactor. Pause for review after each slice rather than chaining them.

### Toolchain
`mise.toml` pins the Rust version; `mise install` locally and `jdx/mise-action` in CI both use it, so
a green local run and a green CI run mean the same thing. CI runs `cargo fmt --check`, `cargo clippy
-D warnings`, and `cargo test` as separate namespaced jobs (`cli/fmt`, `cli/quality`, `cli/test`).

### Commits
Conventional Commits — `<type>[(scope)][!]: subject`, types feat/fix/docs/style/refactor/perf/test/
build/ci/chore/revert, subject 72 chars or fewer. One commit per ATDD slice: commit as you go, do
not batch slices. Never add AI attribution trailers (`Co-Authored-By: Claude`, `Claude-Session:`,
etc.). The `.githooks/commit-msg` hook enforces all of this.

### Git hooks
POSIX-sh hooks in `.githooks/` run on Windows, macOS and Linux via git's shell. `pre-commit` enforces
file hygiene (trailing newline, no trailing whitespace) then runs `cargo fmt --check`, `cargo clippy
-D warnings`, and `cargo test`; `commit-msg` enforces the commit conventions above. Enable them in a
fresh clone with `mise run install-hooks` (sets `core.hooksPath`).
