//! Application use-cases, generic over the domain ports. searu gates and runs a tool, lets the tool
//! normalise its own output into findings/loot, stores them, and answers queries over that state.

use searu_domain::egress::merge_deny;
use searu_domain::findings::{Finding, Loot, Observation};
use searu_domain::gate::{decide, Decision};
use searu_domain::ports::{
    AuditEntry, AuditLog, FindingsStore, LootStore, Mount, ObservationStore, ProjectSettings,
    RepoError, RoeRepository, RunnerError, SettingsError, SourceError, SourceProvider, StoreError,
    ToolInvocation, ToolOutcome, ToolRunner, WordlistError, WordlistProvider,
};
use searu_domain::scope::{source_target, SOURCE_MOUNT};
use searu_domain::tools::ToolRegistry;

const SECLISTS_TOKEN: &str = "seclists:";
const SECLISTS_MOUNT: &str = "/seclists";

pub struct RunAction<R, Reg, T, FS, LS, OS, W, A, S> {
    pub roe: R,
    pub registry: Reg,
    pub runner: T,
    pub findings: FS,
    pub loot: LS,
    pub observations: OS,
    pub wordlists: W,
    pub audit: A,
    pub source: S,
}

pub enum RunReport {
    Ran {
        outcome: ToolOutcome,
        findings: usize,
        loot: usize,
        observations: usize,
    },
    Refused(Decision),
}

#[derive(Debug)]
pub enum RunError {
    Repo(RepoError),
    UnknownTool(String),
    UnsupportedTechnique { tool: String, technique: String },
    Runner(RunnerError),
    Store(StoreError),
    Wordlist(WordlistError),
    Source(SourceError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Repo(error) => write!(f, "{error}"),
            RunError::UnknownTool(tool) => write!(f, "unknown tool: {tool}"),
            RunError::UnsupportedTechnique { tool, technique } => {
                write!(f, "tool {tool} cannot perform technique {technique}")
            }
            RunError::Runner(error) => write!(f, "{error}"),
            RunError::Store(error) => write!(f, "{error}"),
            RunError::Wordlist(error) => write!(f, "{error}"),
            RunError::Source(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RunError {}

impl<R, Reg, T, FS, LS, OS, W, A, S> RunAction<R, Reg, T, FS, LS, OS, W, A, S>
where
    R: RoeRepository,
    Reg: ToolRegistry,
    T: ToolRunner,
    FS: FindingsStore,
    LS: LootStore,
    OS: ObservationStore,
    W: WordlistProvider,
    A: AuditLog,
    S: SourceProvider,
{
    pub fn run(
        &self,
        tool_name: &str,
        technique: &str,
        target: &str,
        args: &[String],
    ) -> Result<RunReport, RunError> {
        let roe = self.roe.load().map_err(RunError::Repo)?;
        let tool = self
            .registry
            .tool(tool_name)
            .ok_or_else(|| RunError::UnknownTool(tool_name.to_string()))?;
        // `contains(&technique)` cannot typecheck: elements are `&'static str`, the argument a
        // borrowed `&str`; hence the explicit comparison.
        #[allow(clippy::manual_contains)]
        let performs_technique = tool.techniques().iter().any(|id| *id == technique);
        if !performs_technique {
            return Err(RunError::UnsupportedTechnique {
                tool: tool_name.to_string(),
                technique: technique.to_string(),
            });
        }

        let decision = decide(&roe, technique, target);
        self.audit
            .record(&AuditEntry {
                tool: tool_name,
                technique,
                target,
                decision: &decision.to_string(),
                args,
            })
            .map_err(RunError::Store)?;
        match decision {
            Decision::Authorised => {}
            refused => return Ok(RunReport::Refused(refused)),
        }

        let (argv, mounts) = self.resolve_mounts(target, tool.invocation(target, args))?;
        let invocation = ToolInvocation {
            tool: tool.name(),
            target,
            args: &argv,
            dockerfile: tool.dockerfile(),
            mounts: &mounts,
        };
        let outcome = self.runner.run(&invocation).map_err(RunError::Runner)?;
        let parsed = tool.parse(target, &outcome);
        for loot in &parsed.loot {
            self.loot.emit(loot).map_err(RunError::Store)?;
        }
        for finding in &parsed.findings {
            self.findings.emit(finding).map_err(RunError::Store)?;
        }
        for observation in &parsed.observations {
            self.observations
                .emit(observation)
                .map_err(RunError::Store)?;
        }
        Ok(RunReport::Ran {
            findings: parsed.findings.len(),
            loot: parsed.loot.len(),
            observations: parsed.observations.len(),
            outcome,
        })
    }

    /// Resolve the run's mounts and rewrite mount tokens in the tool argv. A `src:<path>` target
    /// resolves to a confined workspace tree mounted read-only at [`SOURCE_MOUNT`]; any `src:` token in
    /// the argv is rewritten to that mount point (a tool needing a sub-path builds it from the
    /// constant). A `seclists:<path>` token fetches the referenced list once and mounts the shared cache
    /// read-only. Only the referenced mounts are added.
    fn resolve_mounts(
        &self,
        target: &str,
        argv: Vec<String>,
    ) -> Result<(Vec<String>, Vec<Mount>), RunError> {
        let mut mounts = Vec::new();
        if let Some(relative) = source_target(target) {
            let host = self.source.resolve(relative).map_err(RunError::Source)?;
            mounts.push(Mount {
                host,
                container: SOURCE_MOUNT.to_string(),
                readonly: true,
            });
        }

        let mut resolved = Vec::with_capacity(argv.len());
        let mut uses_seclists = false;
        for arg in argv {
            if source_target(&arg).is_some() {
                resolved.push(SOURCE_MOUNT.to_string());
            } else if let Some(relative) = arg.strip_prefix(SECLISTS_TOKEN) {
                self.wordlists
                    .ensure(relative)
                    .map_err(RunError::Wordlist)?;
                resolved.push(format!("{SECLISTS_MOUNT}/{relative}"));
                uses_seclists = true;
            } else {
                resolved.push(arg);
            }
        }
        if uses_seclists {
            mounts.push(Mount {
                host: self.wordlists.root(),
                container: SECLISTS_MOUNT.to_string(),
                readonly: true,
            });
        }
        Ok((resolved, mounts))
    }
}

pub struct QueryFindings<FS> {
    pub findings: FS,
}

impl<FS: FindingsStore> QueryFindings<FS> {
    pub fn filtered(
        &self,
        technique: Option<&str>,
        severity: Option<&str>,
        tool: Option<&str>,
    ) -> Result<Vec<Finding>, StoreError> {
        let mut items = self.findings.list()?;
        if let Some(technique) = technique {
            items.retain(|f| f.attack_technique.iter().any(|id| id == technique));
        }
        if let Some(severity) = severity {
            items.retain(|f| f.severity.as_str() == severity);
        }
        if let Some(tool) = tool {
            items.retain(|f| f.tool == tool);
        }
        Ok(items)
    }
}

pub struct QueryLoot<LS> {
    pub loot: LS,
}

impl<LS: LootStore> QueryLoot<LS> {
    pub fn filtered(&self, category: Option<&str>) -> Result<Vec<Loot>, StoreError> {
        let mut items = self.loot.list()?;
        if let Some(category) = category {
            items.retain(|l| l.category == category);
        }
        Ok(items)
    }
}

pub struct QueryObservations<OS> {
    pub observations: OS,
}

impl<OS: ObservationStore> QueryObservations<OS> {
    pub fn filtered(&self, kind: Option<&str>) -> Result<Vec<Observation>, StoreError> {
        let mut items = self.observations.list()?;
        if let Some(kind) = kind {
            items.retain(|o| o.kind == kind);
        }
        Ok(items)
    }
}

pub struct ValidateRoe<R> {
    pub roe: R,
}

pub struct RoeReport {
    pub targets: usize,
    pub allowed: usize,
    pub unknown_techniques: Vec<String>,
}

impl RoeReport {
    pub fn is_valid(&self) -> bool {
        self.unknown_techniques.is_empty()
    }
}

impl<R: RoeRepository> ValidateRoe<R> {
    pub fn validate(&self) -> Result<RoeReport, RepoError> {
        let roe = self.roe.load()?;
        let unknown_techniques = roe
            .allowed_techniques
            .iter()
            .filter(|id| searu_domain::attack::technique(id).is_none())
            .cloned()
            .collect();
        Ok(RoeReport {
            targets: roe.scope.targets.len(),
            allowed: roe.allowed_techniques.len(),
            unknown_techniques,
        })
    }
}

pub struct HardenProject<S> {
    pub settings: S,
}

pub struct HardenReport {
    pub added: usize,
    pub total: usize,
}

impl<S: ProjectSettings> HardenProject<S> {
    pub fn harden(&self) -> Result<HardenReport, SettingsError> {
        let current = self.settings.denied_egress()?;
        let merged = merge_deny(&current);
        let added = merged.len() - current.len();
        self.settings.set_denied_egress(&merged)?;
        Ok(HardenReport {
            added,
            total: merged.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use searu_domain::findings::{Severity, Status};
    use searu_domain::ports::{Authorisation, Authoriser, Roe};
    use searu_domain::scope::{HostForm, Scope, ScopeEntry};
    use searu_domain::tools::{ParsedOutput, PhaseAdvice, Tool};
    use std::cell::RefCell;

    struct FakeTool;
    static FAKE_TOOL: FakeTool = FakeTool;
    impl Tool for FakeTool {
        fn name(&self) -> &'static str {
            "faketool"
        }
        fn techniques(&self) -> &'static [&'static str] {
            &["T1190"]
        }
        fn dockerfile(&self) -> &'static str {
            ""
        }
        fn uses(&self) -> &'static [PhaseAdvice] {
            &[]
        }
        fn invocation(&self, _target: &str, args: &[String]) -> Vec<String> {
            let mut argv = vec!["--built".to_string()];
            argv.extend(args.iter().cloned());
            argv
        }
        fn parse(&self, target: &str, _outcome: &ToolOutcome) -> ParsedOutput {
            ParsedOutput {
                findings: vec![Finding {
                    tool: "faketool".to_string(),
                    target: target.to_string(),
                    title: "OS command injection".to_string(),
                    severity: Severity::Critical,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1190".to_string()],
                    cwe: vec![78],
                    evidence: "e".to_string(),
                    loot_fingerprint: Some("ff00ff00ff00".to_string()),
                }],
                loot: vec![Loot {
                    fingerprint: "ff00ff00ff00".to_string(),
                    category: "database-url".to_string(),
                    value: "testing".to_string(),
                }],
                observations: vec![Observation {
                    kind: "endpoint".to_string(),
                    value: "/login".to_string(),
                    detail: None,
                }],
            }
        }
    }

    struct FakeSourceTool;
    static FAKE_SOURCE_TOOL: FakeSourceTool = FakeSourceTool;
    impl Tool for FakeSourceTool {
        fn name(&self) -> &'static str {
            "sourcetool"
        }
        fn techniques(&self) -> &'static [&'static str] {
            &["T1593.003"]
        }
        fn dockerfile(&self) -> &'static str {
            ""
        }
        fn uses(&self) -> &'static [PhaseAdvice] {
            &[]
        }
        fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
            let mut argv = vec!["scan".to_string(), target.to_string()];
            argv.extend(args.iter().cloned());
            argv
        }
        fn parse(&self, _target: &str, _outcome: &ToolOutcome) -> ParsedOutput {
            ParsedOutput::default()
        }
    }

    struct FakeRegistry;
    impl ToolRegistry for FakeRegistry {
        fn tool(&self, name: &str) -> Option<&'static dyn Tool> {
            match name {
                "faketool" => Some(&FAKE_TOOL as &dyn Tool),
                "sourcetool" => Some(&FAKE_SOURCE_TOOL as &dyn Tool),
                _ => None,
            }
        }
        fn tools_for(&self, _technique: &str) -> Vec<&'static dyn Tool> {
            vec![&FAKE_TOOL]
        }
        fn all(&self) -> Vec<&'static dyn Tool> {
            vec![&FAKE_TOOL]
        }
    }

    struct StubRoe(fn() -> Roe);
    impl RoeRepository for StubRoe {
        fn load(&self) -> Result<Roe, RepoError> {
            Ok((self.0)())
        }
    }

    fn authorising() -> Roe {
        Roe {
            scope: Scope {
                targets: vec![ScopeEntry::Host {
                    form: HostForm::Url,
                    value: "http://localhost:5000".to_string(),
                    port: None,
                }],
                exclusions: vec![],
            },
            allowed_techniques: vec!["T1190".to_string()],
            authorisation: Authorisation {
                exploitation_authorised_by: Some(Authoriser {
                    name: "Jane".to_string(),
                    email: "jane@example.com".to_string(),
                }),
                destructive_authorised: false,
            },
        }
    }

    fn authorising_source() -> Roe {
        Roe {
            scope: Scope::default(),
            allowed_techniques: vec!["T1593.003".to_string()],
            authorisation: Authorisation::default(),
        }
    }

    struct SpyRunner;
    impl ToolRunner for SpyRunner {
        fn run(&self, _invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
            Ok(ToolOutcome {
                code: 0,
                stdout: "out".to_string(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Default)]
    struct CapturingRunner {
        args: RefCell<Vec<String>>,
        mounts: RefCell<Vec<Mount>>,
    }
    impl ToolRunner for CapturingRunner {
        fn run(&self, invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
            *self.args.borrow_mut() = invocation.args.to_vec();
            *self.mounts.borrow_mut() = invocation.mounts.to_vec();
            Ok(ToolOutcome {
                code: 0,
                stdout: "out".to_string(),
                stderr: String::new(),
            })
        }
    }

    struct PanicRunner;
    impl ToolRunner for PanicRunner {
        fn run(&self, _invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
            unreachable!("the runner must not run when the gate refuses or validation fails");
        }
    }

    #[derive(Default)]
    struct MemFindings {
        items: RefCell<Vec<Finding>>,
    }
    impl FindingsStore for MemFindings {
        fn emit(&self, finding: &Finding) -> Result<(), StoreError> {
            self.items.borrow_mut().push(finding.clone());
            Ok(())
        }
        fn list(&self) -> Result<Vec<Finding>, StoreError> {
            Ok(self.items.borrow().clone())
        }
    }

    #[derive(Default)]
    struct MemLoot {
        items: RefCell<Vec<Loot>>,
    }
    impl LootStore for MemLoot {
        fn emit(&self, loot: &Loot) -> Result<(), StoreError> {
            self.items.borrow_mut().push(loot.clone());
            Ok(())
        }
        fn list(&self) -> Result<Vec<Loot>, StoreError> {
            Ok(self.items.borrow().clone())
        }
    }

    #[derive(Default)]
    struct MemObservations {
        items: RefCell<Vec<Observation>>,
    }
    impl ObservationStore for MemObservations {
        fn emit(&self, observation: &Observation) -> Result<(), StoreError> {
            self.items.borrow_mut().push(observation.clone());
            Ok(())
        }
        fn list(&self) -> Result<Vec<Observation>, StoreError> {
            Ok(self.items.borrow().clone())
        }
    }

    #[derive(Default)]
    struct MemWordlists {
        fetched: RefCell<Vec<String>>,
    }
    impl WordlistProvider for MemWordlists {
        fn root(&self) -> String {
            "/home/u/.searu/wordlists".to_string()
        }
        fn ensure(&self, relative: &str) -> Result<(), WordlistError> {
            self.fetched.borrow_mut().push(relative.to_string());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemSource;
    impl SourceProvider for MemSource {
        fn resolve(&self, relative: &str) -> Result<String, SourceError> {
            if relative.split(['/', '\\']).any(|segment| segment == "..") {
                return Err(SourceError::Invalid(format!(
                    "source path escapes the workspace: {relative}"
                )));
            }
            Ok(format!("/work/{relative}"))
        }
    }

    #[derive(Default)]
    struct MemAudit {
        entries: RefCell<Vec<(String, String)>>,
    }
    impl AuditLog for MemAudit {
        fn record(&self, entry: &AuditEntry) -> Result<(), StoreError> {
            self.entries
                .borrow_mut()
                .push((entry.tool.to_string(), entry.decision.to_string()));
            Ok(())
        }
    }

    const LOCAL: &str = "http://localhost:5000/cmd/dig?ip_addr=1";

    #[test]
    fn an_authorised_run_stores_the_parsed_findings_and_loot() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: SpyRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        let report = use_case
            .run(
                "faketool",
                "T1190",
                LOCAL,
                &["--os-cmd".to_string(), "env".to_string()],
            )
            .unwrap();
        assert!(matches!(
            report,
            RunReport::Ran {
                findings: 1,
                loot: 1,
                ..
            }
        ));
        assert_eq!(use_case.findings.items.borrow().len(), 1);
        assert_eq!(use_case.loot.items.borrow().len(), 1);
        assert_eq!(use_case.observations.items.borrow().len(), 1);
    }

    #[test]
    fn the_runner_receives_the_argv_the_tool_builds_not_the_raw_args() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: CapturingRunner::default(),
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        use_case
            .run("faketool", "T1190", LOCAL, &["--os-cmd".to_string()])
            .unwrap();
        assert_eq!(
            *use_case.runner.args.borrow(),
            vec!["--built".to_string(), "--os-cmd".to_string()]
        );
    }

    #[test]
    fn seclists_tokens_are_fetched_once_and_rewritten_to_the_mount() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: CapturingRunner::default(),
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        use_case
            .run(
                "faketool",
                "T1190",
                LOCAL,
                &[
                    "-w".to_string(),
                    "seclists:Fuzzing/LFI/LFI-Jhaddix.txt".to_string(),
                ],
            )
            .unwrap();

        assert_eq!(
            *use_case.wordlists.fetched.borrow(),
            vec!["Fuzzing/LFI/LFI-Jhaddix.txt".to_string()]
        );
        assert_eq!(
            *use_case.runner.args.borrow(),
            vec![
                "--built".to_string(),
                "-w".to_string(),
                "/seclists/Fuzzing/LFI/LFI-Jhaddix.txt".to_string(),
            ]
        );
        assert_eq!(
            *use_case.runner.mounts.borrow(),
            vec![Mount {
                host: "/home/u/.searu/wordlists".to_string(),
                container: "/seclists".to_string(),
                readonly: true,
            }]
        );
    }

    #[test]
    fn a_source_target_is_confined_mounted_readonly_and_rewritten() {
        let use_case = RunAction {
            roe: StubRoe(authorising_source),
            registry: FakeRegistry,
            runner: CapturingRunner::default(),
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        use_case
            .run("sourcetool", "T1593.003", "src:app/web", &[])
            .unwrap();

        assert_eq!(
            *use_case.runner.args.borrow(),
            vec!["scan".to_string(), "/src".to_string()]
        );
        assert_eq!(
            *use_case.runner.mounts.borrow(),
            vec![Mount {
                host: "/work/app/web".to_string(),
                container: "/src".to_string(),
                readonly: true,
            }]
        );
    }

    #[test]
    fn a_source_target_that_escapes_the_workspace_is_refused() {
        let use_case = RunAction {
            roe: StubRoe(authorising_source),
            registry: FakeRegistry,
            runner: PanicRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        assert!(matches!(
            use_case.run("sourcetool", "T1593.003", "src:../etc", &[]),
            Err(RunError::Source(_))
        ));
    }

    #[test]
    fn a_run_without_a_seclists_token_mounts_nothing() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: CapturingRunner::default(),
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        use_case
            .run("faketool", "T1190", LOCAL, &["--os-cmd".to_string()])
            .unwrap();
        assert!(use_case.wordlists.fetched.borrow().is_empty());
        assert!(use_case.runner.mounts.borrow().is_empty());
    }

    #[test]
    fn an_out_of_scope_target_refuses_and_never_runs() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: PanicRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        let report = use_case
            .run("faketool", "T1190", "http://evil.example.org/x", &[])
            .unwrap();
        assert!(matches!(report, RunReport::Refused(Decision::OutOfScope)));
        assert!(use_case.findings.items.borrow().is_empty());
        assert!(use_case.loot.items.borrow().is_empty());
    }

    #[test]
    fn an_authorised_run_is_audited() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: SpyRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        use_case.run("faketool", "T1190", LOCAL, &[]).unwrap();
        assert_eq!(
            *use_case.audit.entries.borrow(),
            vec![("faketool".to_string(), "authorised".to_string())]
        );
    }

    #[test]
    fn a_refused_run_is_audited_before_it_is_refused() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: PanicRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        let report = use_case
            .run("faketool", "T1190", "http://evil.example.org/x", &[])
            .unwrap();
        assert!(matches!(report, RunReport::Refused(_)));
        assert_eq!(
            *use_case.audit.entries.borrow(),
            vec![("faketool".to_string(), "OUT OF SCOPE".to_string())]
        );
    }

    #[test]
    fn an_unknown_tool_is_an_error() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: PanicRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        assert!(matches!(
            use_case.run("nope", "T1190", LOCAL, &[]),
            Err(RunError::UnknownTool(_))
        ));
    }

    #[test]
    fn a_technique_outside_the_tool_repertoire_is_an_error() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: PanicRunner,
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
            audit: MemAudit::default(),
            source: MemSource,
        };
        assert!(matches!(
            use_case.run("faketool", "T9999", LOCAL, &[]),
            Err(RunError::UnsupportedTechnique { .. })
        ));
    }

    #[test]
    fn query_findings_filters_by_technique() {
        let store = MemFindings::default();
        store
            .emit(&Finding {
                tool: "commix".to_string(),
                target: LOCAL.to_string(),
                title: "a".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![78],
                evidence: String::new(),
                loot_fingerprint: None,
            })
            .unwrap();
        store
            .emit(&Finding {
                tool: "nmap".to_string(),
                target: LOCAL.to_string(),
                title: "b".to_string(),
                severity: Severity::Info,
                status: Status::NeedsReview,
                attack_technique: vec!["T1046".to_string()],
                cwe: vec![],
                evidence: String::new(),
                loot_fingerprint: None,
            })
            .unwrap();

        let query = QueryFindings { findings: store };
        assert_eq!(query.filtered(Some("T1190"), None, None).unwrap().len(), 1);
        assert_eq!(query.filtered(None, Some("info"), None).unwrap().len(), 1);
        assert_eq!(query.filtered(None, None, None).unwrap().len(), 2);
    }

    fn bogus_technique() -> Roe {
        let mut roe = authorising();
        roe.allowed_techniques = vec!["T1190".to_string(), "T9999".to_string()];
        roe
    }

    struct FailingRoe;
    impl RoeRepository for FailingRoe {
        fn load(&self) -> Result<Roe, RepoError> {
            Err(RepoError::Parse("bad json".to_string()))
        }
    }

    #[test]
    fn validate_roe_accepts_real_techniques() {
        let use_case = ValidateRoe {
            roe: StubRoe(authorising),
        };
        let report = use_case.validate().unwrap();
        assert!(report.is_valid());
        assert!(report.unknown_techniques.is_empty());
        assert_eq!(report.allowed, 1);
        assert_eq!(report.targets, 1);
    }

    #[test]
    fn validate_roe_flags_an_unknown_technique() {
        let use_case = ValidateRoe {
            roe: StubRoe(bogus_technique),
        };
        let report = use_case.validate().unwrap();
        assert_eq!(report.unknown_techniques, vec!["T9999".to_string()]);
        assert!(!report.is_valid());
    }

    #[test]
    fn validate_roe_propagates_a_parse_error() {
        let use_case = ValidateRoe { roe: FailingRoe };
        assert!(matches!(use_case.validate(), Err(RepoError::Parse(_))));
    }

    #[derive(Default)]
    struct MemSettings {
        deny: RefCell<Vec<String>>,
    }
    impl ProjectSettings for MemSettings {
        fn denied_egress(&self) -> Result<Vec<String>, SettingsError> {
            Ok(self.deny.borrow().clone())
        }
        fn set_denied_egress(&self, deny: &[String]) -> Result<(), SettingsError> {
            *self.deny.borrow_mut() = deny.to_vec();
            Ok(())
        }
    }

    #[test]
    fn hardening_denies_every_egress_tool_on_an_empty_project() {
        let use_case = HardenProject {
            settings: MemSettings::default(),
        };
        let report = use_case.harden().unwrap();
        assert_eq!(report.added, 3);
        assert_eq!(report.total, 3);
        assert_eq!(
            *use_case.settings.deny.borrow(),
            vec![
                "WebFetch".to_string(),
                "WebSearch".to_string(),
                "mcp__*".to_string()
            ]
        );
    }

    #[test]
    fn hardening_preserves_existing_denials_and_is_idempotent() {
        let use_case = HardenProject {
            settings: MemSettings::default(),
        };
        *use_case.settings.deny.borrow_mut() =
            vec!["Bash(rm *)".to_string(), "WebFetch".to_string()];
        assert_eq!(use_case.harden().unwrap().added, 2);
        assert_eq!(use_case.harden().unwrap().added, 0);
        assert_eq!(
            use_case
                .settings
                .deny
                .borrow()
                .iter()
                .filter(|entry| *entry == "WebFetch")
                .count(),
            1
        );
    }
}
