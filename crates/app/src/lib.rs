//! Application use-cases, generic over the domain ports.

use searu_domain::authorisation::{decide, Decision};
use searu_domain::capability;
use searu_domain::findings::{Finding, Loot, Severity, Status};
use searu_domain::ports::{
    ExploitError, FindingsStore, Fingerprinter, LootStore, ReflectedCommandInjector, RepoError,
    RoeRepository, RunnerError, StoreError, ToolInvocation, ToolOutcome, ToolRunner,
};
use searu_domain::scope::is_host_in_scope;

pub struct RunTool<R: RoeRepository, T: ToolRunner> {
    pub roe: R,
    pub runner: T,
}

#[derive(Debug)]
pub enum RunError {
    Repo(RepoError),
    OutOfScope(String),
    Runner(RunnerError),
}

impl<R: RoeRepository, T: ToolRunner> RunTool<R, T> {
    pub fn execute(
        &self,
        tool: &str,
        target: &str,
        args: &[String],
    ) -> Result<ToolOutcome, RunError> {
        let roe = self.roe.load().map_err(RunError::Repo)?;
        if !is_host_in_scope(target, &roe.scope) {
            return Err(RunError::OutOfScope(target.to_string()));
        }
        let invocation = ToolInvocation { tool, target, args };
        self.runner.run(&invocation).map_err(RunError::Runner)
    }
}

pub struct Assess<R, I, FP, FS, LS> {
    pub roe: R,
    pub injector: I,
    pub fingerprinter: FP,
    pub findings: FS,
    pub loot: LS,
}

#[derive(Debug)]
pub enum AssessOutcome {
    Exploited {
        category: String,
        fingerprint: String,
    },
    Refused(Decision),
}

#[derive(Debug)]
pub enum AssessError {
    Repo(RepoError),
    UnknownCapability(String),
    Exploit(ExploitError),
    NoSecret,
    Store(StoreError),
}

impl std::fmt::Display for AssessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssessError::Repo(error) => write!(f, "{error}"),
            AssessError::UnknownCapability(id) => write!(f, "unknown capability: {id}"),
            AssessError::Exploit(error) => write!(f, "{error}"),
            AssessError::NoSecret => {
                write!(
                    f,
                    "the exploit ran but no DATABASE_URL was found in the output"
                )
            }
            AssessError::Store(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AssessError {}

impl<R, I, FP, FS, LS> Assess<R, I, FP, FS, LS>
where
    R: RoeRepository,
    I: ReflectedCommandInjector,
    FP: Fingerprinter,
    FS: FindingsStore,
    LS: LootStore,
{
    pub fn run(&self, capability_id: &str, target: &str) -> Result<AssessOutcome, AssessError> {
        let roe = self.roe.load().map_err(AssessError::Repo)?;
        let capability = capability::capability(capability_id)
            .ok_or_else(|| AssessError::UnknownCapability(capability_id.to_string()))?;

        let decision = decide(&roe, capability, target);
        if decision != Decision::Authorised {
            return Ok(AssessOutcome::Refused(decision));
        }

        let output = self
            .injector
            .exploit(target, "env")
            .map_err(AssessError::Exploit)?;
        let output = html_unescape(&output);
        let secret = extract_env_var(&output, "DATABASE_URL").ok_or(AssessError::NoSecret)?;
        let fingerprint = self.fingerprinter.fingerprint(&secret);

        self.loot
            .emit(&Loot {
                fingerprint: fingerprint.clone(),
                category: "database-url".to_string(),
                value: secret,
            })
            .map_err(AssessError::Store)?;
        self.findings
            .emit(&Finding {
                tool: "http".to_string(),
                target: target.to_string(),
                title: "OS command injection".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: capability
                    .attack_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),
                cwe: vec![78],
                evidence: "the ip_addr parameter reflects injected command output".to_string(),
                loot_fingerprint: Some(fingerprint.clone()),
            })
            .map_err(AssessError::Store)?;

        Ok(AssessOutcome::Exploited {
            category: "database-url".to_string(),
            fingerprint,
        })
    }
}

pub fn extract_env_var(output: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let start = output.find(&needle)? + needle.len();
    let rest = &output[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '<')
        .unwrap_or(rest.len());
    let value = &rest[..end];
    (!value.is_empty()).then(|| value.to_string())
}

/// Decodes the HTML entities a web target emits when it reflects command output into a page (the
/// CWE-78 lab escapes `=` as `&#x3D;`, `<` as `&lt;`, and so on), so the raw command output can be
/// parsed back out.
pub fn html_unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            if let Some(decoded) = decode_entity(&after[..semi]) {
                out.push(decoded);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let code = if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                entity.strip_prefix('#')?.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use searu_domain::ports::{Authorisation, Authoriser, Roe};
    use searu_domain::scope::{HostForm, Scope, ScopeEntry};
    use std::cell::{Cell, RefCell};

    fn in_scope_roe() -> Roe {
        Roe {
            scope: Scope {
                targets: vec![ScopeEntry::Host {
                    form: HostForm::Domain,
                    value: "staging.example.com".to_string(),
                    port: None,
                }],
                exclusions: vec![],
            },
            ..Default::default()
        }
    }

    struct StubRepo(fn() -> Roe);
    impl RoeRepository for StubRepo {
        fn load(&self) -> Result<Roe, RepoError> {
            Ok((self.0)())
        }
    }

    struct FailingRepo;
    impl RoeRepository for FailingRepo {
        fn load(&self) -> Result<Roe, RepoError> {
            Err(RepoError::Io("boom".to_string()))
        }
    }

    struct SpyRunner {
        calls: Cell<u32>,
        code: i32,
    }
    impl ToolRunner for SpyRunner {
        fn run(&self, _invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
            self.calls.set(self.calls.get() + 1);
            Ok(ToolOutcome {
                code: self.code,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    struct PanicRunner;
    impl ToolRunner for PanicRunner {
        fn run(&self, _invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
            unreachable!("the runner must never be invoked for an out-of-scope target");
        }
    }

    #[test]
    fn an_out_of_scope_target_never_invokes_the_runner() {
        let use_case = RunTool {
            roe: StubRepo(in_scope_roe),
            runner: PanicRunner,
        };
        let result = use_case.execute("scan", "evil.example.org", &[]);
        assert!(matches!(result, Err(RunError::OutOfScope(_))));
    }

    #[test]
    fn an_in_scope_target_runs_the_tool_once() {
        let use_case = RunTool {
            roe: StubRepo(in_scope_roe),
            runner: SpyRunner {
                calls: Cell::new(0),
                code: 7,
            },
        };
        let result = use_case.execute("scan", "staging.example.com", &[]);
        assert!(matches!(result, Ok(outcome) if outcome.code == 7));
        assert_eq!(use_case.runner.calls.get(), 1);
    }

    #[test]
    fn a_repository_failure_propagates() {
        let use_case = RunTool {
            roe: FailingRepo,
            runner: PanicRunner,
        };
        let result = use_case.execute("scan", "staging.example.com", &[]);
        assert!(matches!(result, Err(RunError::Repo(_))));
    }

    fn authorising_roe() -> Roe {
        Roe {
            scope: Scope {
                targets: vec![ScopeEntry::Host {
                    form: HostForm::Domain,
                    value: "localhost".to_string(),
                    port: None,
                }],
                exclusions: vec![],
            },
            allowed_techniques: vec!["T1190".to_string(), "T1059".to_string()],
            authorisation: Authorisation {
                exploitation_authorised_by: Some(Authoriser {
                    name: "Lab Operator".to_string(),
                    email: "operator@example.com".to_string(),
                }),
                destructive_authorised: false,
            },
        }
    }

    fn unauthorised_roe() -> Roe {
        Roe {
            authorisation: Authorisation::default(),
            ..authorising_roe()
        }
    }

    struct FakeInjector {
        output: String,
        calls: Cell<u32>,
    }
    impl ReflectedCommandInjector for FakeInjector {
        fn exploit(&self, _target: &str, _command: &str) -> Result<String, ExploitError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.output.clone())
        }
    }

    struct PanicInjector;
    impl ReflectedCommandInjector for PanicInjector {
        fn exploit(&self, _target: &str, _command: &str) -> Result<String, ExploitError> {
            unreachable!("the injector must never run when the gate refuses");
        }
    }

    struct FixedFingerprinter;
    impl Fingerprinter for FixedFingerprinter {
        fn fingerprint(&self, _value: &str) -> String {
            "ff00ff00ff00".to_string()
        }
    }

    #[derive(Default)]
    struct CapturingFindings {
        items: RefCell<Vec<Finding>>,
    }
    impl FindingsStore for CapturingFindings {
        fn emit(&self, finding: &Finding) -> Result<(), StoreError> {
            self.items.borrow_mut().push(finding.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct CapturingLoot {
        items: RefCell<Vec<Loot>>,
    }
    impl LootStore for CapturingLoot {
        fn emit(&self, loot: &Loot) -> Result<(), StoreError> {
            self.items.borrow_mut().push(loot.clone());
            Ok(())
        }
    }

    const ENV_OUTPUT: &str = "PATH&#x3D;/usr/bin\nDATABASE_URL&#x3D;testing\nHOME&#x3D;/root";

    #[test]
    fn assess_exploits_and_stores_loot_and_a_finding() {
        let assess = Assess {
            roe: StubRepo(authorising_roe),
            injector: FakeInjector {
                output: ENV_OUTPUT.to_string(),
                calls: Cell::new(0),
            },
            fingerprinter: FixedFingerprinter,
            findings: CapturingFindings::default(),
            loot: CapturingLoot::default(),
        };

        let outcome = assess
            .run(
                "command-injection",
                "http://localhost:5000/cmd/dig?ip_addr=1",
            )
            .unwrap();
        assert!(matches!(outcome, AssessOutcome::Exploited { .. }));

        let loot = assess.loot.items.borrow();
        assert_eq!(loot.len(), 1);
        assert_eq!(loot[0].value, "testing");
        assert_eq!(loot[0].fingerprint, "ff00ff00ff00");

        let findings = assess.findings.items.borrow();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe, vec![78]);
        assert_eq!(findings[0].attack_technique, vec!["T1190", "T1059"]);
        assert_eq!(
            findings[0].loot_fingerprint.as_deref(),
            Some("ff00ff00ff00")
        );
    }

    #[test]
    fn assess_refuses_without_an_authoriser_and_never_exploits() {
        let assess = Assess {
            roe: StubRepo(unauthorised_roe),
            injector: PanicInjector,
            fingerprinter: FixedFingerprinter,
            findings: CapturingFindings::default(),
            loot: CapturingLoot::default(),
        };

        let outcome = assess
            .run(
                "command-injection",
                "http://localhost:5000/cmd/dig?ip_addr=1",
            )
            .unwrap();
        assert!(matches!(
            outcome,
            AssessOutcome::Refused(Decision::ExploitationNotAuthorised)
        ));
        assert!(assess.findings.items.borrow().is_empty());
        assert!(assess.loot.items.borrow().is_empty());
    }

    #[test]
    fn assess_refuses_an_out_of_scope_target() {
        let assess = Assess {
            roe: StubRepo(authorising_roe),
            injector: PanicInjector,
            fingerprinter: FixedFingerprinter,
            findings: CapturingFindings::default(),
            loot: CapturingLoot::default(),
        };

        let outcome = assess
            .run(
                "command-injection",
                "http://evil.example.org/cmd/dig?ip_addr=1",
            )
            .unwrap();
        assert!(matches!(
            outcome,
            AssessOutcome::Refused(Decision::OutOfScope)
        ));
    }

    #[test]
    fn extracts_an_environment_variable_value() {
        let decoded = "PATH=/usr/bin\nDATABASE_URL=testing\nHOME=/root";
        assert_eq!(
            extract_env_var(decoded, "DATABASE_URL").as_deref(),
            Some("testing")
        );
        assert_eq!(extract_env_var(decoded, "NOPE"), None);
    }

    #[test]
    fn html_unescapes_reflected_output() {
        assert!(html_unescape(ENV_OUTPUT).contains("DATABASE_URL=testing"));
        assert_eq!(html_unescape("a&amp;b&lt;c&gt;d&#x3D;e"), "a&b<c>d=e");
    }
}
