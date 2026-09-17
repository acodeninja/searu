//! The njsscan tool wrapper: how searu runs njsscan's Node.js/JavaScript SAST over a mounted source
//! tree and normalises its JSON results into findings. njsscan does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Njsscan;

pub static NJSSCAN: Njsscan = Njsscan;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "Node.js / JavaScript SAST — scan JS/Node source you obtained for command injection, unsafe deserialisation, path traversal and other weaknesses (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run njsscan --technique T1593.003 --target src:<workspace-relative-dir>  (njsscan's own flags after `--`)",
    interpret: "searu findings --tool njsscan — one finding per rule hit, titled by the njsscan rule id, evidence `file:line`, tagged with the rule's CWE. Severity maps njsscan ERROR/WARNING; all are static and need review",
    chain: "triage each hit against the running app; a confirmed injection sink promotes to an exploitation run with an authoriser",
}];

impl Tool for Njsscan {
    fn name(&self) -> &'static str {
        "njsscan"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount.
        let mut argv = vec!["--json".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(doc) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        for section in ["nodejs", "templates"] {
            let Some(rules) = doc.get(section).and_then(Value::as_object) else {
                continue;
            };
            for (rule_id, rule) in rules {
                let metadata = rule.get("metadata");
                let severity = metadata
                    .and_then(|m| m.get("severity"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let cwe = metadata
                    .and_then(|m| m.get("cwe"))
                    .and_then(Value::as_str)
                    .and_then(cwe_number)
                    .map(|id| vec![id])
                    .unwrap_or_default();
                let Some(files) = rule.get("files").and_then(Value::as_array) else {
                    continue;
                };
                for file in files {
                    let path = file.get("file_path").and_then(Value::as_str).unwrap_or("");
                    let line = file
                        .get("match_lines")
                        .and_then(Value::as_array)
                        .and_then(|lines| lines.first())
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    if !seen.insert(format!("{rule_id}|{path}|{line}")) {
                        continue;
                    }
                    findings.push(Finding {
                        tool: "njsscan".to_string(),
                        target: target.to_string(),
                        title: rule_id.to_string(),
                        severity: severity_of(severity),
                        status: Status::NeedsReview,
                        attack_technique: vec!["T1593.003".to_string()],
                        cwe: cwe.clone(),
                        evidence: format!("{path}:{line}"),
                        loot_fingerprint: None,
                    });
                }
            }
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn severity_of(name: &str) -> Severity {
    match name {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Info,
    }
}

fn cwe_number(text: &str) -> Option<u32> {
    text.strip_prefix("CWE-")
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_source_in_json() {
        let argv = NJSSCAN.invocation("src:app", &[]);
        assert_eq!(argv, vec!["--json", "src:app"]);
    }

    #[test]
    fn parses_results_into_findings_with_cwe_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"nodejs":{
                "generic_os_command_exec":{
                    "files":[{"file_path":"/src/app.js","match_lines":[4,6]}],
                    "metadata":{"severity":"ERROR","cwe":"CWE-78: OS Command Injection"}
                }
            },"templates":{},"errors":[]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = NJSSCAN.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "generic_os_command_exec");
        assert_eq!(parsed.findings[0].cwe, vec![78]);
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.findings[0].evidence, "/src/app.js:4");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"nodejs":{},"templates":{},"errors":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = NJSSCAN.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
