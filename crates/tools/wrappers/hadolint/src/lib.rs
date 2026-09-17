//! The hadolint tool wrapper: how searu runs hadolint's Dockerfile linter over a mounted source tree
//! and normalises its JSON output into findings. hadolint does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`;
//! hadolint lints the `Dockerfile` at the root of that tree.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::scope::SOURCE_MOUNT;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Hadolint;

pub static HADOLINT: Hadolint = Hadolint;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "Dockerfile linting — check the Dockerfile in source you obtained for insecure and fragile build practices (unpinned bases, unverified downloads, running as root) (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run hadolint --technique T1593.003 --target src:<dir-containing-a-Dockerfile>  (hadolint lints `<dir>/Dockerfile`; its own flags after `--`, e.g. `-- --ignore DL3008`)",
    interpret: "searu findings --tool hadolint — one finding per rule hit, titled by the rule code (DLxxxx / SCxxxx), evidence `file:line`. hadolint does not attach a CWE. Severity maps error/warning/info/style",
    chain: "an unpinned base or an unverified download is a supply-chain foothold to note; feed a running-as-root or exposed-secret finding into the broader attack picture",
}];

impl Tool for Hadolint {
    fn name(&self) -> &'static str {
        "hadolint"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1593.003"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, _target: &str, args: &[String]) -> Vec<String> {
        // The source target drives the read-only `/src` mount; hadolint lints the Dockerfile at its root.
        let mut argv = vec![
            "--format".to_string(),
            "json".to_string(),
            format!("{SOURCE_MOUNT}/Dockerfile"),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(Value::Array(issues)) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        for issue in &issues {
            let code = issue.get("code").and_then(Value::as_str).unwrap_or("");
            if code.is_empty() {
                continue;
            }
            let file = issue.get("file").and_then(Value::as_str).unwrap_or("");
            let line = issue.get("line").and_then(Value::as_u64).unwrap_or(0);
            if !seen.insert(format!("{code}|{file}|{line}")) {
                continue;
            }
            let level = issue.get("level").and_then(Value::as_str).unwrap_or("");
            findings.push(Finding {
                tool: "hadolint".to_string(),
                target: target.to_string(),
                title: code.to_string(),
                severity: severity_of(level),
                status: Status::NeedsReview,
                attack_technique: vec!["T1593.003".to_string()],
                cwe: Vec::new(),
                evidence: format!("{file}:{line}"),
                loot_fingerprint: None,
            });
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn severity_of(level: &str) -> Severity {
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "info" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_lints_the_dockerfile_at_the_mount_root() {
        let argv = HADOLINT.invocation("src:app", &[]);
        assert_eq!(argv, vec!["--format", "json", "/src/Dockerfile"]);
    }

    #[test]
    fn parses_issues_into_findings_with_the_rule_code_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"[
                {"code":"DL3007","level":"warning","line":1,"column":1,"file":"/src/Dockerfile",
                 "message":"Using latest is prone to errors"},
                {"code":"DL3007","level":"warning","line":1,"column":1,"file":"/src/Dockerfile",
                 "message":"Using latest is prone to errors"},
                {"code":"","level":"info","line":9,"file":"/src/Dockerfile","message":"no code"}
            ]"#
            .to_string(),
            stderr: String::new(),
        };
        let parsed = HADOLINT.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "DL3007");
        assert_eq!(parsed.findings[0].severity, Severity::Medium);
        assert_eq!(parsed.findings[0].evidence, "/src/Dockerfile:1");
    }

    #[test]
    fn a_clean_lint_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[]".to_string(),
            stderr: String::new(),
        };
        let parsed = HADOLINT.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
