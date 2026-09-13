//! Application use-cases, generic over the domain ports. searu gates and runs a tool, lets the tool
//! normalise its own output into findings/loot, stores them, and answers queries over that state.

use searu_domain::findings::{Finding, Loot, Observation};
use searu_domain::gate::{decide, Decision};
use searu_domain::ports::{
    FindingsStore, LootStore, Mount, ObservationStore, RepoError, RoeRepository, RunnerError,
    StoreError, ToolInvocation, ToolOutcome, ToolRunner, WordlistError, WordlistProvider,
};
use searu_domain::tools::ToolRegistry;

const SECLISTS_TOKEN: &str = "seclists:";
const SECLISTS_MOUNT: &str = "/seclists";

pub struct RunAction<R, Reg, T, FS, LS, OS, W> {
    pub roe: R,
    pub registry: Reg,
    pub runner: T,
    pub findings: FS,
    pub loot: LS,
    pub observations: OS,
    pub wordlists: W,
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
        }
    }
}

impl std::error::Error for RunError {}

impl<R, Reg, T, FS, LS, OS, W> RunAction<R, Reg, T, FS, LS, OS, W>
where
    R: RoeRepository,
    Reg: ToolRegistry,
    T: ToolRunner,
    FS: FindingsStore,
    LS: LootStore,
    OS: ObservationStore,
    W: WordlistProvider,
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

        match decide(&roe, technique, target) {
            Decision::Authorised => {}
            refused => return Ok(RunReport::Refused(refused)),
        }

        let (argv, mounts) = self.resolve_wordlists(tool.invocation(target, args))?;
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

    /// Rewrite `seclists:<path>` argument tokens to their in-container path, fetching each referenced
    /// list once and mounting the shared cache read-only when any token is present.
    fn resolve_wordlists(&self, argv: Vec<String>) -> Result<(Vec<String>, Vec<Mount>), RunError> {
        let mut resolved = Vec::with_capacity(argv.len());
        let mut uses_seclists = false;
        for arg in argv {
            match arg.strip_prefix(SECLISTS_TOKEN) {
                Some(relative) => {
                    self.wordlists
                        .ensure(relative)
                        .map_err(RunError::Wordlist)?;
                    resolved.push(format!("{SECLISTS_MOUNT}/{relative}"));
                    uses_seclists = true;
                }
                None => resolved.push(arg),
            }
        }
        let mounts = if uses_seclists {
            vec![Mount {
                host: self.wordlists.root(),
                container: SECLISTS_MOUNT.to_string(),
                readonly: true,
            }]
        } else {
            Vec::new()
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use searu_domain::findings::{Severity, Status};
    use searu_domain::ports::{Authorisation, Authoriser, Roe};
    use searu_domain::scope::{HostForm, Scope, ScopeEntry};
    use searu_domain::tools::{ParsedOutput, Tool};
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
        fn advice(&self) -> &'static str {
            ""
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

    struct FakeRegistry;
    impl ToolRegistry for FakeRegistry {
        fn tool(&self, name: &str) -> Option<&'static dyn Tool> {
            (name == "faketool").then_some(&FAKE_TOOL as &dyn Tool)
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
    fn a_run_without_a_seclists_token_mounts_nothing() {
        let use_case = RunAction {
            roe: StubRoe(authorising),
            registry: FakeRegistry,
            runner: CapturingRunner::default(),
            findings: MemFindings::default(),
            loot: MemLoot::default(),
            observations: MemObservations::default(),
            wordlists: MemWordlists::default(),
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
        };
        let report = use_case
            .run("faketool", "T1190", "http://evil.example.org/x", &[])
            .unwrap();
        assert!(matches!(report, RunReport::Refused(Decision::OutOfScope)));
        assert!(use_case.findings.items.borrow().is_empty());
        assert!(use_case.loot.items.borrow().is_empty());
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
}
