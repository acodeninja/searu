# Searu — current plan & handoff

Living plan and session-handoff for rebuilding the pen-testing toolkit as **Searu**. Detailed enough
to resume in a fresh session. See [architecture.md](architecture.md) for crate diagrams.

> [product-plan.md](product-plan.md) is the authoritative design (ATT&CK as the organising spine, a
> single `/searu` skill, authorised-is-executable exploitation with NIST SP 800-115 tiers). Work is
> sequenced into **milestones** (M1–M8), one ATDD slice per commit. M1 (end-to-end exploit of the
> local CWE-78 lab) has shipped; see *Current status* below for where we are. A design review settled
> eleven decisions (networked-systems scope) recorded in `product-plan.md → Resolved design decisions`.

## Why

The previous toolkit *was* the user's `~/.claude` directory: 61 Python scripts (~17k lines) on
absolute paths, 38 scanners installed natively, and a `scope_hook.py` gate depending on a shebang +
exec-bit (broken on Windows). It could not be installed or updated. It now lives in `old-version/`
as a **read-only reference** (git-ignored, never committed) we port semantics and tests from.

Searu is a clean-slate rebuild on gstack's model: a self-contained cloneable repo that installs and
updates via one script, registers into `~/.claude` with thin pointers, keeps runtime state out of
`~/.claude`, and runs on Windows/macOS/Linux. Outside dependencies collapse to two: **Docker** (every
scanner containerised) and **one prebuilt `searu` Rust binary** (zero runtime deps). (The M7
reverse-shell redirector path adds a named, opt-in third-party dependency; assessment and the default
foothold-driven session mode stay within this envelope.)

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
- **Docker images** — pulled on first use from `ghcr.io/acodeninja/searu-<tool>:<version>`, built from each tool crate's embedded `Dockerfile` only as a fallback; CI builds and pushes every wrapper image on each release/RC (**shipped**).
- **Hosting** — public GitHub repo (clone-install, Releases, ghcr, Actions).
- **Design-review decisions recorded** — eleven resolved issues (networked-only scope) in
  `product-plan.md → Resolved design decisions`: hook hardening (default-deny hook + `searu harden`
  project egress deny — **shipped**; frontmatter `allowed-tools` is advisory, not enforced);
  gate-enforced ROE limits (`windows`/`rate`/`stop_after`); an append-only `./pentest/audit.jsonl`;
  identity-never-expands-scope; URL-subtree scope; ATT&CK as the sole authorisation key with
  fail-closed unknown; opt-in C2 redirectors; a container privileged escape hatch; a consequence-based
  model floor; and a report pulled ahead of the asset/session milestones.

## Current status

The hexagon is built and walking. Workspace crates (`Cargo.toml` members): `domain`, `app`,
`adapter-store`, `adapter-docker`, `tools/parser`, `tools/registry`, the six tool wrappers
(`commix`, `ffuf`, `httpx`, `katana`, `nmap`, `sqlmap`), `cli`, `xtask`.

Shipped:

- **ATT&CK reference layer** — full Enterprise matrix embedded offline via `cargo xtask attack-sync`;
  `searu attack list|show`.
- **Scope + the authorisation gate** — `domain::is_host_in_scope`, `gate::decide`, `technique::tier_of`;
  `searu run` refuses out-of-scope / unauthorised targets before any container starts.
- **Containerised tool runner** — `DockerToolRunner` builds each tool crate's embedded `Dockerfile`
  on first use, runs it with `--add-host=host.docker.internal:host-gateway`.
- **Six tools** — commix (CWE-78, end-to-end against the live lab), httpx + katana (black-box
  recon), nmap (port/service discovery / `T1046`), sqlmap (CWE-89), ffuf (content discovery / CWE-22),
  plus a download-once SecLists wordlist cache with read-only mounts.
- **Three engagement stores** under `./pentest/` — findings, loot, observations — with
  `searu findings|loot|observations` queries; ROE default path `pentest/rules-of-engagement.json`.
- **M2 — ROE tooling & backstop** — `searu validate-roe` (loads a ROE and checks every allow-listed
  ID against the embedded ATT&CK matrix; `app::ValidateRoe`) and `searu scope-hook` (`domain::scope_hook`).
- **Hook hardening (decision 1)** — `scope-hook` is now **default-deny** over all tools (matcher `*`):
  `Bash` must be `searu …`, a small local-tool allow-set passes, every network-capable tool
  (`WebFetch`/`WebSearch`/`Skill`/`mcp__*`) is blocked (exit 2). `searu harden` writes a project-scoped
  `.claude/settings.json` (`domain::egress`, `app::HardenProject`, `adapter-store::FileProjectSettings`):
  a settings-level `hooks.PreToolUse` running `searu scope-hook` **plus** a `permissions.deny` over the
  egress tools and the target-reaching Bash programs (`Bash(docker:*)`/`curl`/`wget`/`nc`/`ncat`/`socat`)
  — the layer that reaches a spawned specialist, since a skill-frontmatter hook does not (see
  *Field-test defects* #1) and Claude Code does not enforce frontmatter `allowed-tools`/`tools:`.
- **Audit trail (decision 3)** — `RunAction` appends every gate decision (authorised *and* refused:
  tool, technique, target, decision, requested args) to append-only `./pentest/audit.jsonl` before the
  runner runs, via an `AuditLog` port + `JsonlAuditLog` adapter (time stamped in the adapter). The
  write is fail-closed. Pulled ahead of M6 (decision 10).
- **Binary installers** — `install.sh`, `install.ps1`, and `mise run install-local` (see *Locked
  decisions*). Release/CI scaffolding (release-please, cross-compiled Linux + Windows assets).
- **M5 — `/searu` skill payload (router + sections + specialists)** — `skills/searu/SKILL.md` (router
  with the `PreToolUse -> searu scope-hook` frontmatter) + six phase `sections/` + `manifest.json` +
  eleven `specialists/` (one per registry binding, each naming a `model:`), guarded by registry-driven
  `xtask` consistency tests.
- **M5 — skill install** — the payload is embedded in the `searu` binary (`include_dir`); `searu
  install-skill` writes it to `~/.claude/skills/searu/`, rewrites the hook to the binary's absolute
  path, drops `.searu-owned`, refuses to clobber a user's own skill, and also installs the
  `/searu-upgrade` command into `~/.claude/commands/`. `install.sh`, `install.ps1`, and
  `mise run install-local` all call it (one cross-platform Rust path; `SEARU_NO_SKILL` opts out).
- **M5 — `/searu-upgrade`** — a slash command that asks the operator for the full release or a
  release candidate, then re-runs the installer at that channel (`SEARU_VERSION=<rc-tag>` for RCs);
  the installer replaces the binary and reinstalls the skill. **M5 is complete.**

Not yet built: M4 reporting/intel; plus the deferred credential-access section.

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
- Remaining wrappers, one slice each (nuclei, dalfox, testssl, …), every one a new tool crate
  bound to its ATT&CK cell — never a new command; preserve each tool's hard-won defaults.

**M4 — reporting & intel**
- `emit-finding`, `report` (WeasyPrint container), Dradis export; CWE/EPSS/KEV via a new
  `adapter-intel`; `propose-exploits`/`record-exploit`. ATT&CK coverage heat-map + CWE attack-chains;
  RoE appendix after the executive summary; redaction at record- *and* report-time.
- **Resolved-review additions (this band):** the append-only `./pentest/audit.jsonl` audit trail is
  **shipped** (decision 3); still to build — a *minimal defensible report* (findings + RoE appendix +
  audit trail) pulled *ahead* of M6–M7; **gate-enforced** ROE `windows`/`rate`/`stop_after`
  (`Decision::OutOfWindow`/`RateExceeded`); and CWE/OWASP-WSTG as first-class attribution tags on
  findings with an unknown/untiered technique failing closed. See `product-plan.md → Resolved design
  decisions` (2, 3, 6, 10).

**M5 — install & the `/searu` skill**
Author the skill payload directly (no template generator). Planned slice sequence:
1. ~~`searu scope-hook` subcommand~~ — **shipped with M2.**
2. ~~`SKILL.md` router + `sections/` + `manifest.json`~~ — **shipped** (six sections;
   credential-access deferred until cred tools land). `mise run install-local` installs the skill.
3. ~~`specialists/` — one prompt per (technique × tool), each naming a `model:`~~ — **shipped** (all
   11 registry bindings; a registry-driven `xtask` test enforces coverage + model headers).
4. ~~Install the skill from the binary~~ — **shipped.** The payload is embedded (`include_dir`) and
   `searu install-skill` writes it to `~/.claude/skills/searu/`, rewrites the hook to the binary's
   absolute path, drops `.searu-owned`, and won't clobber a user's own skill; `install.sh`,
   `install.ps1` and `install-local` all call it (tested against a throwaway HOME). Retired the
   `xtask install-skill` copy.
5. ~~`/searu-upgrade` command~~ — **shipped.** A slash command (installed by `install-skill` into
   `~/.claude/commands/`) that asks full-release vs release-candidate and re-runs the installer at
   that channel. Release scaffolding already existed (release-please + RC prereleases in CI).

**M5 is complete.**

**M6 — the asset model (slices 1–4 shipped)**
Prompted by a known gap: commix runs recorded identical generic "OS command injection / T1190"
findings and discarded the real command output (OS = Alpine, the user, files, a credential), because
`Tool::parse` wasn't told the technique and `Loot`/`Observation` had no target. The full design —
hosts / addresses / networks / services / footholds, deterministic fingerprint-based host identity,
the `(host, service, network, tool, technique)` attribution tuple, credential subjects, candidate
hosts, and the network-aware scope gate — is in `product-plan.md` (*Targets: hosts, services &
networks*, incl. the storage decision: JSONL source of truth + in-memory `petgraph` projection, no
DB) and `architecture.md`. Sub-slice order:
1. ~~**Store upsert.**~~ **shipped.** The three `adapter-store` emits upsert on record identity
   (content minus timestamps) with `first_seen`/`last_seen`, deduping every JSONL store; `AuditLog`
   stays append-only. Attribution travels via a `RecordContext` so wrappers stay untouched.
2. ~~Add `host`/`service`/`network` attribution + `--host`.~~ **shipped.** New `domain::assets`
   (opaque fingerprint `HostId`, `Address`/`Service`/`ClaimKind`, `derive_id`/`project`/`possible_clone`);
   `run` resolves `--target` → `(host, service, network)` and stamps every record; `--host` filter on
   findings/loot/observations; `searu hosts` derives the graph from the records (no `assets.jsonl`, no
   `petgraph` yet — that's for traversals in slices 5+).
3. ~~Thread `technique` into `Tool::parse` (all ~40 wrappers); rework commix.~~ **shipped.** commix
   labels the injection finding by technique (T1190/T1059 only, so collection runs don't duplicate it)
   and decomposes `'<cmd>' execution output:` into `user`/`os`/`file` observations (`/etc/passwd` → one
   `user` per account) plus `identity-claim` observations (machine-id/hostname/ssh-host-key) the host
   projection reads back to sharpen/merge identity.
4. ~~Credential subject + CWE-522.~~ **shipped.** `Loot` gains `principal`/`authenticates` (parsed from
   credential URLs); commix emits a CWE-522 exposed-credential finding per secret, linked by
   fingerprint (never the plaintext); `searu loot` shows the subject.
5. Candidate hosts/services + pivot discipline (`searu run` refuses a candidate until the ROE names it).
6. Foothold discovery — Discovery techniques (`T1016`/`T1018`/`T1046`/`T1049`) on commix + network
   observation parsers + candidate hosts + a `discovery` foothold-recon section.
7. Scope & networks — the `network` label on scope entries + the network-aware gate; generalise
   `ScopeEntry` to a matcher sum type adding **URL-prefix** subtree scoping (decision 5); enforce
   **identity-never-expands-scope** — a correlation merge that would widen scope stays *candidate*
   until the operator confirms, and TLS-SPKI ranks below per-host identity claims (decision 4).

**M7 — interactive sessions (planned, depends on M6)**
`Session`/`SessionBroker` + a new `adapter-session` crate; the per-session broker container (channel +
bundled ngrok/cloudflared/ssh-`R` redirectors); foothold-driven (default) and reverse-shell (opt-in,
explicit `--callback`) modes; pivot relays hop-by-hop; `searu session start|exec|list|close`,
Exploitation-tier + scope-gated, transcripts redacted, torn down at engagement end.

**M8 — external scanners (planned)** dnsx/subfinder (`T1590`/`T1595`), one tool-wrapper slice each.
nmap (`T1046`, connect scan) has **shipped**; its SYN / OS-detection modes still await the documented
**privileged escape hatch** (`--cap-add` / `--net=host`) on native Linux, gated identically (decision 8).

## Field-test defects (Juice Shop assessment, 2026-09-17)

Four issues surfaced running a full assessment against a local OWASP Juice Shop
(`http://localhost:3000/`) through the `/searu` skill. Ordered by severity.

1. **The scope hook does not constrain a spawned specialist's Bash — safety-property violation.**
   **Fixed.** A sqlmap specialist (ephemeral subagent) found the target down mid-run and started it
   with a raw `docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop:latest`. In the
   top-level session the `PreToolUse -> searu scope-hook` allowlist blocks any non-`searu` Bash, so
   `docker run` should have been refused; it was not, because the hook lived only in `SKILL.md`
   frontmatter and Claude Code does not propagate a skill-frontmatter hook into a Task-spawned subagent
   ([anthropics/claude-code#27661](https://github.com/anthropics/claude-code/issues/27661)). The
   enforcement moved to the layer that does reach a subagent: `searu harden` now writes a settings-level
   `hooks.PreToolUse` running `searu scope-hook` into the project `.claude/settings.json`, plus a
   `permissions.deny` covering the egress tools **and** the target-reaching Bash programs
   (`Bash(docker:*)`/`curl`/`wget`/`nc`/`ncat`/`socat`) as an enforced backstop. `scope_hook::decide`
   was already correct; only its delivery changed. The operator should still confirm live-session that a
   settings-level hook fires inside a subagent; the `permissions.deny` Bash specifiers are enforced
   regardless. Relates to decision 1 (hook hardening) and the *Invariants → Scope* entry.

2. **The sqlmap wrapper never records dumped credentials as loot.** **Fixed.** A confirmed
   T1190/CWE-89 injection in `/rest/products/search?q=` was exploited to dump the `Users` table (24
   rows: id, role, email, MD5 password) yet `searu loot` stayed empty — the emails/hashes lived only
   in the raw `pentest/outputs/sqlmap/…` stdout/CSV. A new `text::dump_tables` parser reads sqlmap's
   `+----+`-bordered `--dump` tables, and the wrapper's `parse()`
   (`crates/tools/wrappers/sqlmap/src/lib.rs`) now maps each row's secret column
   (`password`/`hash`/…) to `Loot` (principal from a `username`/`email` column or a connection
   string's userinfo; `authenticates` = the target host), deduped by fingerprint, plus one CWE-522
   exposed-credential finding per secret — fingerprint-linked, never the plaintext (mirrors the
   commix credential-subject pattern from `a813bb2`, M6 slice 4).

3. **sqlmap's default SQLite payload crashed the target (incidental DoS).** **Fixed.** The default
   technique mix included a time-based payload (`RANDOMBLOB(500000000/2)`) that segfaulted Juice Shop's
   `better-sqlite3` binding (container exit 139); re-running restricted to boolean/error/union
   completed cleanly. Decision (user): gate on `destructive_authorised`. A new `InvocationContext`
   (`domain::tools`) threads the ROE's `destructive_authorised` into a provided `Tool::invocation_in`
   (defaults to `invocation`, so the ~40 other wrappers are untouched); the app passes it at the single
   call site. sqlmap overrides it to append `--technique=BEU` unless destructive is authorised or the
   caller pinned their own `--technique`. Full defaults (incl. time-based) return the moment destructive
   is authorised, preserving sqlmap's hard-won behaviour where the operator opted into impact.

4. **nmap cannot run against a `url`-type target.** **Fixed** (scope-authoring approach, user
   decision). With ROE target `http://localhost:3000/`, nmap (which needs a bare host, never a URL)
   could not run: a host-only `--target localhost` was refused out-of-scope because the `url` entry
   pins port 3000. Rather than split host:port in the wrapper or relax the gate, searu now guides the
   operator to scope the host. `domain::scope::suggest_addition` detects a target refused only on the
   port — or a loopback alias of an in-scope loopback host — and `searu run` prints a `hint:` naming
   the `host`/`ip` entries to add (for a loopback URL, both `localhost` and `127.0.0.1`). The scoping
   section and the nmap specialist tell the operator to add them (explicitly — searu never widens
   scope). With `localhost` scoped as a host, `searu run nmap --target localhost` reaches
   `host.docker.internal` via the adapter's existing rewrite and scans normally. Upholds *scope is
   intrinsic* and *identity-never-expands-scope*.

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
