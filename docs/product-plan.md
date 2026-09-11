# Searu — product & design plan

An ATT&CK-driven security-assessment toolkit: one skill (`/searu`) that turns Claude Code into an
authorised pen-testing operator, organised around the **MITRE ATT&CK** framework, driving
containerised tools that can both *assess* and — with sufficient authorisation — *exploit* a target.

This is the "what & why & architecture" reference. The living ATDD slice tracker is
[current-plan.md](current-plan.md); the crate-level rules are in [architecture.md](architecture.md).

## Implemented architecture (authoritative)

Milestone 1 shipped, and it settled the tool boundary. Where sections further down still describe an
`assess` command, a built-in HTTP injector, or a capability overlay, **this section supersedes them.**

- **Claude orchestrates; searu is gated hands + memory.** searu never plans and never exploits by
  hand. For one invocation it enforces the gate, runs the authorised tool in its container,
  normalises the tool's output into findings/loot, and answers queries over that state. Claude
  decides what to run next by querying findings/loot.
- **One gated action:** `searu run <tool> --technique <Txxxx> --target <t> [-- <tool args>]`. The gate
  is: the tool must list that technique; the target must be in scope *now*; the exact ATT&CK ID must
  be in the ROE allow-list; and the technique's tier must be satisfied (Exploitation → a named
  authoriser; Destructive → authoriser + `destructive_authorised`). Tiers come from a curated
  `domain::technique::tier_of` table (unknown → Exploitation).
- **Queries:** `searu findings [--technique|--severity|--tool]`, `searu loot [--category] [--reveal]`,
  `searu tool list`, `searu tool advice <tool>`, `searu attack list|show`.
- **Crate-per-tool.** Each tool is a thin crate under `crates/tools/wrappers/<tool>` implementing the
  `domain::tools::Tool` trait, with its `Dockerfile` and Claude-facing `advice.md` compiled in via
  `include_str!`, and its own `parse` that normalises output into a `ParsedOutput { findings, loot }`.
  Shared normalisation helpers (fingerprint, HTML-unescape, secret scan) live in
  `crates/tools/parser` (`searu-tool-parser`); `crates/tools/registry` (`searu-tool-registry`)
  exposes them through the `ToolRegistry` port. A generic SARIF parser will join the parser crate when
  the first SARIF-emitting tool (grype/snyk) lands.
- **Docker adapter** builds the tool's embedded Dockerfile on first use and runs it with
  `--add-host=host.docker.internal:host-gateway`, feeding the (host-rewritten) target on the tool's
  stdin so a container can reach a host-published target. First tool: **commix** (OS command
  injection, T1190/T1059), proven end-to-end against the CWE-78 lab.

## Vision

Searu is the security-assessment counterpart to gstack. It is a single cross-platform Rust binary
(`searu`) plus one Claude Code skill, distributed as a self-contained cloneable payload that installs
into `~/.claude` via thin pointers. Two outside dependencies only: **Docker** (every tool runs in a
container) and the **`searu` binary** (zero runtime deps).

A prior Python toolkit (now read-only in `old-version/`) proved the hard parts: an ROE-as-gate scope
model, a technique vocabulary already tagged with ATT&CK IDs, an exploitation gate, coverage records,
fingerprint redaction, and PDF/Dradis reporting. Searu rebuilds it from first principles so that:

- **ATT&CK is the organising spine**, not a side-attribute.
- The old orchestrator + 15 tool-agents collapse into a **single `/searu` skill** (the gstack `/cso`
  shape) — no pollution of the user's skill namespace.
- Every safety invariant is preserved, while **authorised = executable**: active and destructive
  testing run directly when the Rules of Engagement authorise them.

### Design decisions

- **Pure single skill.** Only `/searu` is registered. Context-heavy tool runs are spawned as
  *ephemeral* subagents via the Agent tool from prompt files under `searu/specialists/`. No `searu-*`
  agents or skills are registered anywhere.
- **Full ATT&CK Enterprise matrix present from day one** (all tactics + every technique/
  sub-technique), embedded and offline. Tools attach to matrix cells incrementally; most cells start
  with "no tooling".
- **Authorised = executable.** Active and destructive testing run directly when the ROE authorises
  them; `propose-exploits` is an optional planning aid (an ROE `require_review` setting can make it
  mandatory per tier). Scope is the one absolute gate. There are **no absolute prohibitions**:
  authorisation is granting the *exact* ATT&CK technique/sub-technique ID in the ROE (so `T1498.002`
  reflection-amplification DoS can be sanctioned without sanctioning `T1498.001` direct flood).
  Exploitation tier also needs a named authoriser (person + email); Destructive tier also needs
  `destructive_authorized: true`.

## The core idea: two catalogues, ATT&CK as the spine

Everything hangs off two layers that both live in `domain` (zero external deps):

1. **ATT&CK reference layer (complete, read-only).** The full embedded Enterprise matrix: tactics,
   techniques, sub-techniques — id, name, tactic membership, parent/child. Used for categorisation,
   naming, coverage display, and report attribution. Present in full from the start so the toolkit
   can *speak ATT&CK* even about cells it cannot yet act on. Offline (never depends on
   attack.mitre.org at runtime), mirroring the old `ATTACK_NAMES` table but complete.

2. **Searu capability overlay (curated, grows).** The subset of ATT&CK cells the toolkit can
   actually operate, each entry binding:
   `{ capability id, attack_ids: [Txxxx…], tier, tools: [image…], gate }`.
   `tier ∈ { Passive, Active, Exploitation, Destructive }` — the intrusiveness/impact ladder from
   **NIST SP 800-115** (Review → Target Identification & Analysis → Target Vulnerability Validation),
   extended with `Destructive` for impact. `Passive` = no packets to the target (OSINT/third-party);
   `Active` = read-only interaction (discovery, enumeration, fingerprinting, vulnerability
   *detection*); `Exploitation` = validating a weakness by exercising it / gaining access;
   `Destructive` = may modify, degrade or deny (writes, DoS).
   This is where nmap/nuclei/sqlmap/hydra/etc. hang off their ATT&CK techniques. Starts with the
   handful of techniques needed for the first milestone; every new tool is a new binding, never a new
   command. **Authorisation is by exact ATT&CK ID:** a capability is runnable only if *every* one of
   its `attack_ids` appears in the ROE's allow-list, matched exactly and sub-technique-specifically
   (a parent never implies a child, nor a child its parent). This makes the ROE speak ATT&CK
   directly — the same spine the catalogue is built on.

Coverage is then a *join*: "for tactic X, here are the ATT&CK techniques, here is which searu
capabilities/tools cover them, here is what remains unaddressed." That join is the report's ATT&CK
heat-map and the operator's menu.

```mermaid
graph TD
    STIX["MITRE ATT&CK STIX<br/>(pinned release)"] -->|cargo xtask attack-sync| GEN["generated.rs<br/>full Enterprise matrix"]
    GEN --> REF["ATT&CK reference layer<br/>(domain, offline, complete)"]
    REF -. tags .-> CAP
    CAP["Capability overlay<br/>attack_id × tool × tier × gate<br/>(curated, grows)"]
    ROE["rules-of-engagement.json<br/>allow-list of exact ATT&CK IDs<br/>+ authorisers"] --> GATE
    SCOPE["scope (absolute)"] --> GATE
    CAP --> GATE{authorised?}
    GATE -->|no| STOP["refuse — no container"]
    GATE -->|yes| TOOL["searu run tool<br/>→ Docker image"]
    TOOL --> FIND["findings + loot<br/>(ATT&CK-tagged)"]
    REF -. names .-> REP
    FIND --> REP["report: RoE appendix<br/>+ ATT&CK heat-map"]
```

### Embedding the full matrix without giving `domain` dependencies

`domain` must depend on nothing. So the matrix is embedded as **generated Rust**, not parsed at
runtime:

- A dev-only `xtask` crate (not in the shipping dependency graph) command
  `cargo xtask attack-sync --version <v>` downloads the pinned MITRE ATT&CK STIX 2.1 release
  (`mitre-attack/attack-stix-data`, `enterprise-attack/…json`), transforms it, and writes a compact
  `crates/domain/src/attack/generated.rs` (`static TACTICS/TECHNIQUES: &[…]`, a few hundred KB).
- Only the generated Rust is committed (not the ~30 MB STIX). `domain` `include!`s it and stays
  dependency-free. The ATT&CK release version is pinned like any dependency; look up the current
  latest release before regenerating.

## CLI surface (`searu` binary), organised around ATT&CK

- `searu attack list [--tactic <TA…>]` — browse the full embedded matrix.
- `searu attack show <Txxxx>` — technique detail + which searu capabilities/tools cover it.
- `searu capability list [--tier <t>]` — what searu can *do* today, grouped by tactic.
- `searu run <tool|capability> --roe <path> --target <t> [-- <args…>]` — the one execution path.
  Scope (intrinsic, default-deny, most-specific-wins) + tier gate + the ROE's ATT&CK-technique
  allow-list all enforced *before* any container starts. (No `check-scope` command — scope is
  intrinsic.)
- `searu assess --roe <path> --target <t>` — orchestrate the applicable capabilities against a
  target end-to-end (detect → gated exploit → emit). The "full assessment" driver.
- `searu validate-roe` — schema-validate `./pentest/rules-of-engagement.json` (carry
  `rules-of-engagement.schema.json`).
- `searu scope-hook` — PreToolUse allowlist backstop: permit only `searu …` + file reads, block raw
  `docker`/`curl`/scanners (exit 2). Does not read the ROE.
- `searu emit-finding` / `searu report` — findings JSONL (with `attack_technique`) → PDF/Dradis,
  with a **Rules of Engagement appendix** (scope, authorised ATT&CK techniques, authorisers, limits)
  rendered immediately after the executive summary, then the ATT&CK coverage heat-map + CWE
  attack-chains + KEV/EPSS exploitability.
- `searu exploit <step> --roe <path> --target <t>` — **execute** an authorised exploitation/
  destructive action directly (scope + tier + authorisation checked first).
- `searu propose-exploits` / `searu record-exploit` — optional planning aid: write/record an
  exploitation plan without executing. An ROE setting can make review-before-execute mandatory per
  tier.

## Domain model (`crates/domain`, zero deps)

- ATT&CK reference: `TacticId`, `TechniqueId`, `AttackTactic`, `AttackTechnique { id, name, tactic,
  parent }`, plus `include!`d `generated.rs`.
- Capability overlay: `Tier`, `Capability { id, attack_ids, tier, tools, gate }`.
- ROE (`Roe`, loaded from `rules-of-engagement.json`): scope + an **allow-list of exact ATT&CK
  technique/sub-technique IDs** + `authorization { exploitation_authorized_by, destructive_authorized,
  require_review }`. `fn authorises(&self, id: &TechniqueId) -> bool` does exact, sub-technique-
  specific matching (no parent↔child implication).
- Scope (ported from `check_scope.py`): `EntryKind`, `ScopeEntry`, `Scope`, `is_in_scope`
  (default-deny; domain-suffix + v4/v6 CIDR containment with std only; exclusion overridden only by
  an exact target).
- Authorisation gate: `Decision`/gate combining scope (absolute) + exact ATT&CK authorisation + the
  tier's extra requirement (Exploitation → authoriser present; Destructive → `destructive_authorized`).
- Port traits (co-located in `domain`, sync, DI via generics not `dyn`): `RoeRepository`,
  `ToolRunner`, `FindingsStore`, `LootStore`, `AttackCatalogue`, `CapabilityCatalogue`.

## Crate layering — hexagonal / ports-and-adapters

`cli → {app, adapter-docker, adapter-http, adapter-store, adapter-intel} → domain`; adapters depend
on `domain` only; `domain` on nothing; `cli` is the sole composition root. Use-cases (`RunTool<R,T>`,
`ValidateRoe`, `ProposeExploits`, `EmitFinding`, `Report`) generic over ports, tested with
hand-written fakes. The load-bearing test: **an out-of-scope target never launches a container**
(fake `ToolRunner` asserted never-called). The `xtask` crate (dev-only, not in the shipping graph)
generates the ATT&CK matrix for `domain` via `attack-sync`.

```mermaid
graph TD
    cli["cli — bin: searu<br/>(composition root)"]
    app["app — use-cases, generic over ports"]
    domain["domain — ATT&CK matrix + capabilities<br/>+ scope + authorisation gate + ports"]
    ad["adapter-docker — ToolRunner via Docker"]
    ah["adapter-http — HTTP exploitation execution"]
    ast["adapter-store — ROE/findings/loot (serde + fs)"]
    ai["adapter-intel — CWE/EPSS/KEV feeds (later)"]
    xt["xtask — attack-sync (dev only)"]

    cli --> app
    cli --> ad
    cli --> ah
    cli --> ast
    cli --> ai
    app --> domain
    ad --> domain
    ah --> domain
    ast --> domain
    ai --> domain
    xt -. generates .-> domain
```

## The single `/searu` skill (gstack `/cso` shape)

```
~/.claude/skills/searu/          <- the ONLY registered entry
  SKILL.md                       skeleton router (frontmatter: name: searu, one-line
                                   description + " (searu)", triggers, allowed-tools,
                                   hooks.PreToolUse -> `searu scope-hook`)
  sections/                      on-demand phase workflows, one per ATT&CK-aligned stage
    scoping.md                   /searu scoping interview -> ./pentest/rules-of-engagement.json
    reconnaissance.md            TA0043 — nmap, subfinder, httpx …
    discovery.md                 TA0007 — content/route/param discovery
    initial-access.md            TA0001 — nuclei, sqlmap, dalfox (detect)
    credential-access.md         TA0006 — hydra, john/hashcat, jwt (gated)
    exploitation.md              authorised execution (propose optional)
    reporting.md                 emit-finding / report / export
    manifest.json                PASSIVE registry (id, file, title, trigger)
  specialists/                   subagent PROMPTS spawned inline via Agent tool
    T1046-nmap.md                one (technique × tool) intersection per file
    T1595.002-nuclei.md          named <ATT&CK-id>-<tool>; each carries a
    T1190-sqlmap.md              `model:` header (see Model selection) and
    T1190-commix.md              (never registered as agents)
    …
  bin/                           small POSIX shims: preamble + $HOME-abs-then-relative resolve
```

`SKILL.md` is a skeleton: a trigger→section table + STOP directives ("Read
`~/.claude/skills/searu/sections/<x>.md` before executing"). Phases map PTES onto ATT&CK tactics so
the operator flows Recon → Discovery → Initial Access → Credential Access → … each section calling
the `searu` binary and, for heavy output, spawning a `specialists/*.md` subagent so scanner dumps
never pollute the main context. Authored as `SKILL.md.tmpl` and committed generated (Claude reads it
at load time), following gstack's pipeline.

**Specialists are keyed by ATT&CK technique × tool.** Each `specialists/<Txxxx[.nnn]>-<tool>.md` is
the agent-facing playbook for driving *one tool* to accomplish *one ATT&CK technique*: the invocation
variants and hard-won defaults for that use case (expressed as `searu run <tool> -- <flags…>`), how
to read the output, and the finding schema to emit. A tool spanning several techniques gets one file
per technique (e.g. `T1046-nmap` service/version detection vs `T1595.001-nmap` host-block sweeps),
which keeps each prompt narrow — and narrow is what lets it run on haiku. This mirrors the domain
capability overlay exactly: every catalogue binding `(attack_id × tool)` has a matching specialist
file, so the catalogue *routes and authorises* while the specialist *tells the agent how*. (Naming is
technique-first to match the ATT&CK spine; a tool-first alias index can be added if operators want
"show me every nmap specialist".)

## Model selection (cheapest faithful model per role)

Specialists are spawned via the Agent tool, so the model is chosen *per spawn* — the section prose
passes the `model` named in each `specialists/*.md` header. The rule: **use the cheapest model that
can do the task faithfully, which is only safe when the specialist prompt is fully self-contained**
(target, the exact ATT&CK-authorised technique IDs, the precise `searu run …` invocation contract,
and the finding-output schema all passed in — so the model reasons about nothing it wasn't given).

- **Haiku** — deterministic single-tool specialists: shape the invocation from provided inputs, run
  it via `searu run`, parse stdout, emit a structured finding. sqlmap, nmap, nuclei, httpx, testssl,
  gobuster, dalfox, etc. The bulk of specialists.
- **Sonnet** — specialists needing judgement or interaction: authenticated browser/SPA driving,
  multi-step exploitation (e.g. commix payload/technique selection and chaining), cross-finding
  triage.
- **Opus** — reserved for reasoning the skill itself does or delegates for: phase sequencing,
  scope/authorisation and attribution/third-party judgement, and report synthesis.

Each `specialists/*.md` declares its tier in a header (`model: haiku|sonnet|opus`); a `mise`/CI check
can assert every specialist names one so the choice is explicit, never defaulted. Getting a
specialist down to haiku is a *prompt-completeness* exercise: if it needs a bigger model, that
usually means context it should have been handed is missing.

## Install & distribution (gstack model, cross-platform)

- `install.sh` + `install.ps1`: create the real dir `~/.claude/skills/searu/`, then symlink (Unix)
  / copy (Windows without Developer Mode) `SKILL.md`, `sections/`, `specialists/`, `bin/` from the
  repo checkout. Drop `.searu-owned` provenance markers; never clobber a user's same-named skill
  (detect-and-skip); back up a pre-existing custom SKILL.md.
- Rewrite the installed `SKILL.md` `hooks.PreToolUse` command to the absolute installed binary path.
- Binary → `~/.searu/bin/searu` (`SEARU_HOME`): prebuilt static download from GitHub Releases per
  OS/arch, `cargo build` fallback. Runtime state (binary + CWE/EPSS/KEV caches) lives in `~/.searu/`,
  never in `~/.claude`. Engagement data stays per-project in `./pentest/`.
- Tool images `ghcr.io/<ns>/searu-<tool>:<ver>`, pulled on first use, built from checked-in
  `images/<tool>.Dockerfile` on pull failure.

## Exploitation posture (authorised = executable; propose optional)

Authorisation *unlocks execution*, not merely a written proposal. `searu exploit` and `searu assess`
run active — and, when authorised, destructive — actions directly. The gate is layered so scope is
absolute and everything else is unlocked by the ROE:

- **Scope is the one absolute gate.** The target must be in scope *now*, always, for every tier. No
  ROE field can bypass it (default-deny, most-specific-wins).
- **ATT&CK authorisation unlocks the tier.** `Passive`/`Active` need only their techniques allowed.
  `Exploitation` additionally needs `authorization.exploitation_authorized_by` (a person **and**
  email). `Destructive` (e.g. DoS, destructive-write) additionally needs an explicit
  `authorization.destructive_authorized: true`.
- **No absolute prohibitions; authorisation is granting the exact ATT&CK ID.** Nothing is banned
  outright — a technique runs iff its *exact* technique/sub-technique ID is present in the ROE's
  allow-list. Matching is exact and sub-technique-specific: authorising `T1498.002` (Reflection
  Amplification) authorises *only* that — **not** `T1498.001` (Direct Network Flood) nor the bare
  parent `T1498`. Even DoS is thus scoped precisely to the sanctioned method. Listing a technique in
  the ROE is the *sole* way to authorise it.
- **Propose is optional.** `searu propose-exploits` writes `./pentest/exploitation-plan.md` (literal
  command, blast radius, reversibility) and runs nothing — a planning aid, not a mandatory step. An
  ROE `require_review: [<tier>…]` setting can make propose→review→`record-exploit`→execute mandatory
  for chosen tiers.

The `Decision` type in `domain` encodes this precedence; `app` refuses execution the moment scope or
the required authorisation is missing, and `adapter-docker`/`adapter-http` never see an unauthorised
invocation.

```mermaid
flowchart TD
    A["searu run / exploit<br/>tool · target · technique"] --> B{target in scope now?}
    B -- no --> R1["refuse — OUT OF SCOPE<br/>(no container)"]
    B -- yes --> C{exact ATT&CK id<br/>in ROE allow-list?}
    C -- no --> R2["refuse — technique not authorised"]
    C -- yes --> D{tier?}
    D -- Passive / Active --> RUN["execute"]
    D -- Exploitation --> E{authoriser<br/>name + email present?}
    E -- no --> R3["refuse — no authoriser"]
    E -- yes --> RUN
    D -- Destructive --> F{destructive_authorized<br/>= true?}
    F -- no --> R4["refuse — destructive not authorised"]
    F -- yes --> RUN
```

## First milestone — end-to-end CWE-78 exploit (the walking skeleton)

The first functional deliverable: **run a full assessment against
`ghcr.io/ere-be-dragons/cwe-78:main`, locally, ending in a real exploit.** It is a deep vertical
slice — a tracer bullet through scope → ROE → capability catalogue → containerised tool runner →
*authorised* exploitation gate → findings/loot — kept as thin as possible at each layer, then
thickened by later milestones.

### The target (verified from the repo)

- Node/Express app, prebuilt image `ghcr.io/ere-be-dragons/cwe-78:main`, listens on **:5000**.
  Bring it up: `docker run -it --rm -p 5000:5000 ghcr.io/ere-be-dragons/cwe-78:main`.
- Sink: `GET /cmd/dig?ip_addr=<input>` → ``exec(`dig ${req.query.ip_addr}`)`` — unsanitised, runs via
  `/bin/sh`. Classic **CWE-78** OS command injection.
- Objective: inject a shell command to exfiltrate `process.env.DATABASE_URL`.

### The exploit (on-theme, containerised)

Use **commix** (the automated OS-command-injection tool) in a container as the first bound tool:
`commix --url "http://<target>:5000/cmd/dig?ip_addr=INJECT" -p ip_addr --batch
--os-cmd="printenv DATABASE_URL"`. Confirms injection, executes, returns the credential → loot.
Because the vulnerable command is literally `dig`, a DNS-exfiltration fallback is available. ATT&CK
mapping: **T1190** (Exploit Public-Facing Application) + **T1059** (Command & Scripting
Interpreter); CWE-78; `Tier::Exploitation`.

```mermaid
sequenceDiagram
    participant Op as Operator (/searu)
    participant Cli as searu assess
    participant Uc as app use-case
    participant Gate as authorisation gate (domain)
    participant Dk as adapter-docker
    participant Tgt as CWE-78 container :5000
    participant St as findings + loot

    Op->>Cli: searu assess --roe rules-of-engagement.cwe-78.json --target http://localhost:5000
    Cli->>Uc: capability command-injection (T1190, T1059)
    Uc->>Gate: scope + exact ATT&CK ids + Exploitation authoriser
    Gate-->>Uc: authorised
    Uc->>Dk: run commix image
    Dk->>Tgt: GET /cmd/dig?ip_addr=;printenv DATABASE_URL
    Tgt-->>Dk: DATABASE_URL=…
    Dk-->>Uc: exit code + captured credential
    Uc->>St: finding (T1190, CWE-78) + loot (credential, redacted in report)
```

### The lab ROE (ships as `examples/rules-of-engagement.cwe-78.json`)

Self-owned lab, fully authorised: `targets` = `127.0.0.1` / `localhost:5000`; the ATT&CK allow-list
carries the *exact* IDs the command-injection capability binds to (**`T1190`** and **`T1059`**); and
`authorization.exploitation_authorized_by` names a person **and** email so the Exploitation tier is
unlocked and the exploit actually runs — this is where the toolkit proves it can exploit, not just
propose.

### Milestone-1 ATDD sub-slices (each its own failing-test-first commit)

1. **ATT&CK reference layer** — `cargo xtask attack-sync` + generated full matrix + `AttackCatalogue`
   + `searu attack show <T…>`. Dep-free domain, no daemon.
2. **Scope + `searu run` refusal** — `domain::is_in_scope`; `app::RunTool`;
   `adapter-store::JsonRoeRepository`; `adapter-docker::DockerToolRunner` with pure `docker_argv`.
   Out-of-scope target **never** launches a container. No daemon.
3. **Capability overlay + authorisation gate** — `Tier`, `Capability`, `CapabilityCatalogue` with one
   entry (`command-injection` → commix → T1190/T1059 → Exploitation); authorisation `Decision`.
   Unauthorised refuses cleanly; the lab ROE authorises both IDs + names an authoriser. Pure, no
   daemon.
4. **commix wrapper + live `DockerToolRunner` + findings/loot** (needs daemon) — shape the commix
   argv, `docker run` it against the running target, parse the credential, emit a finding
   (`attack_technique: T1190`, cwe 78) + loot (the `DATABASE_URL`, redacted in any deliverable).
   `images/commix.Dockerfile` fallback if no ghcr image.
5. **`searu assess`** — drive the (currently N=1) capability set against the lab ROE end-to-end:
   scope-check → detect → gated exploit → emit. Live acceptance test brings up the CWE-78 container,
   runs `searu assess`, asserts the credential lands in loot and a T1190 finding is recorded; gated
   on daemon availability (unit path always runs).

## Later milestones (generalisation, once the skeleton walks)

Each still one ATDD slice per commit:

- **M2 — ROE tooling & backstop:** `searu validate-roe` (carry `rules-of-engagement.schema.json`) +
  `searu scope-hook` allowlist (block raw `docker`/`curl`/scanners, exit 2).
- **M3 — more capabilities:** port the old `techniques.py` ATT&CK map in full, remapping each entry
  onto the NIST 800-115 tier ladder; add tools one slice each (nmap, httpx, nuclei, sqlmap, dalfox,
  …), every one a new capability-overlay binding to its ATT&CK cell — never a new command.
- **M4 — reporting & intel:** ATT&CK coverage heat-map, CWE attack-chains, KEV/EPSS exploitability,
  Dradis export (RoE appendix after the executive summary); `propose-exploits`/`record-exploit` for
  the optional review-before-execute branch.
- **M5 — install & the `/searu` skill:** `install.sh`/`install.ps1` (single `searu/` pointer,
  `.searu-owned` markers, hook rewrite, throwaway-HOME test); `/searu-upgrade` + release scaffolding;
  the generated `SKILL.md` skeleton + `sections/` + `specialists/` + `manifest.json` + PreToolUse
  hook.

## Safety invariants to preserve (from old-version)

Scope default-deny / most-specific-wins / allowlist hook (the one absolute gate); execution
authorised **only** by an exact ATT&CK technique/sub-technique ID in the ROE (no parent↔child
implication), with Exploitation/Destructive tiers additionally requiring the recorded authoriser /
destructive flag; redaction twice (record + report, undisableable); two stores joined by fingerprint
(findings keep `sha256_12`, loot keeps plaintext 0600/0700); coverage from tool-run records
(`silent` vs `missing` distinct); attribution + third-party-hosting judgements stay behavioural in
the skill prose; metasploit intentionally excluded (per-module scope ungateable).
