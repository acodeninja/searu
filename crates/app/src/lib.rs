//! Application use-cases, generic over the domain ports.

use searu_domain::ports::{RepoError, RoeRepository, RunnerError, ToolInvocation, ToolRunner};
use searu_domain::scope::is_in_scope;

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
    pub fn execute(&self, tool: &str, target: &str, args: &[String]) -> Result<i32, RunError> {
        let roe = self.roe.load().map_err(RunError::Repo)?;
        if !is_in_scope(target, &roe.scope) {
            return Err(RunError::OutOfScope(target.to_string()));
        }
        let invocation = ToolInvocation { tool, target, args };
        self.runner.run(&invocation).map_err(RunError::Runner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use searu_domain::ports::Roe;
    use searu_domain::scope::{EntryKind, Scope, ScopeEntry};
    use std::cell::Cell;

    fn in_scope_roe() -> Roe {
        Roe {
            scope: Scope {
                targets: vec![ScopeEntry {
                    kind: EntryKind::Domain,
                    value: "staging.example.com".to_string(),
                }],
                exclusions: vec![],
            },
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
        fn run(&self, _invocation: &ToolInvocation) -> Result<i32, RunnerError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.code)
        }
    }

    struct PanicRunner;
    impl ToolRunner for PanicRunner {
        fn run(&self, _invocation: &ToolInvocation) -> Result<i32, RunnerError> {
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
        assert!(matches!(result, Ok(7)));
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
}
