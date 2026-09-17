//! The brakeman tool wrapper: how searu runs brakeman's Rails SAST over a mounted application tree and
//! normalises its JSON warnings into findings. brakeman does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` Rails app mounted read-only at `/src`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Brakeman;

pub static BRAKEMAN: Brakeman = Brakeman;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "Ruby on Rails SAST — scan a Rails application you obtained for SQL injection, mass assignment, unsafe redirects and other Rails weaknesses (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run brakeman --technique T1593.003 --target src:<workspace-relative-rails-app>  (brakeman's own flags after `--`, e.g. `-- --confidence-level 2`). The tree must be a Rails app root",
    interpret: "searu findings --tool brakeman — one finding per warning, titled by the warning type, evidence `file:line`, tagged with the warning's CWE. Severity maps brakeman's confidence; all are static and need review",
    chain: "triage each hit against the running app; a confirmed injection or auth flaw promotes to an exploitation run with an authoriser",
}];

impl Tool for Brakeman {
    fn name(&self) -> &'static str {
        "brakeman"
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

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The app rewrites the `src:` target token to the read-only `/src` mount. `-q` quiets the
        // banner; `--no-exit-on-warn`/`--no-exit-on-error` keep a scan that found issues from erroring.
        let mut argv = vec![
            "-f".to_string(),
            "json".to_string(),
            "-q".to_string(),
            "--no-exit-on-warn".to_string(),
            "--no-exit-on-error".to_string(),
            target.to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(doc) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        let Some(warnings) = doc.get("warnings").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for warning in warnings {
            let kind = warning
                .get("warning_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let file = warning.get("file").and_then(Value::as_str).unwrap_or("");
            let line = warning.get("line").and_then(Value::as_u64).unwrap_or(0);
            if !seen.insert(format!("{kind}|{file}|{line}")) {
                continue;
            }
            let confidence = warning
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or("");
            let cwe = warning
                .get("cwe_id")
                .and_then(Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .filter_map(Value::as_u64)
                        .map(|id| id as u32)
                        .collect()
                })
                .unwrap_or_default();
            findings.push(Finding {
                tool: "brakeman".to_string(),
                target: target.to_string(),
                title: kind.to_string(),
                severity: severity_of(confidence),
                status: Status::NeedsReview,
                attack_technique: vec!["T1593.003".to_string()],
                cwe,
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

fn severity_of(confidence: &str) -> Severity {
    match confidence {
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Weak" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_app_in_json_without_erroring() {
        let argv = BRAKEMAN.invocation("src:app", &[]);
        assert_eq!(
            argv,
            vec![
                "-f",
                "json",
                "-q",
                "--no-exit-on-warn",
                "--no-exit-on-error",
                "src:app",
            ]
        );
    }

    #[test]
    fn parses_warnings_into_findings_with_cwe_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"warnings":[
                {"warning_type":"SQL Injection","confidence":"Medium","cwe_id":[89],
                 "file":"app/controllers/users_controller.rb","line":3},
                {"warning_type":"SQL Injection","confidence":"Medium","cwe_id":[89],
                 "file":"app/controllers/users_controller.rb","line":3}
            ],"errors":[]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = BRAKEMAN.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "SQL Injection");
        assert_eq!(parsed.findings[0].cwe, vec![89]);
        assert_eq!(parsed.findings[0].severity, Severity::Medium);
        assert_eq!(
            parsed.findings[0].evidence,
            "app/controllers/users_controller.rb:3"
        );
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"warnings":[],"errors":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = BRAKEMAN.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
