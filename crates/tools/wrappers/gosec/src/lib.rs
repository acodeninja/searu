//! The gosec tool wrapper: how searu runs gosec's Go SAST over a mounted source tree and normalises its
//! JSON issues into findings. gosec does the analysis; this crate shapes the invocation and reads the
//! result. The target is a `src:<path>` tree mounted read-only at `/src`; gosec scans it with the Go
//! package pattern `/src/...`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::scope::SOURCE_MOUNT;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Gosec;

pub static GOSEC: Gosec = Gosec;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "Go SAST — scan Go source you obtained for injection sinks, weak crypto, unhandled errors and unsafe defaults (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run gosec --technique T1593.003 --target src:<workspace-relative-dir>  (gosec's own flags after `--`, e.g. `-- -severity high`). The tree needs its go.mod for gosec to load packages",
    interpret: "searu findings --tool gosec — one finding per issue, titled by the gosec rule id (Gxxx), evidence `file:line`, tagged with the rule's CWE. Severity maps gosec LOW/MEDIUM/HIGH; all are static and need review",
    chain: "triage each hit against the running app; a confirmed injection sink promotes to an exploitation run with an authoriser",
}];

impl Tool for Gosec {
    fn name(&self) -> &'static str {
        "gosec"
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
        // The source target drives the read-only `/src` mount; gosec scans it with Go's recursive
        // package pattern. `-no-fail` keeps a scan that found issues from erroring.
        let mut argv = vec![
            "-fmt=json".to_string(),
            "-no-fail".to_string(),
            format!("{SOURCE_MOUNT}/..."),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(doc) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        let Some(issues) = doc.get("Issues").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for issue in issues {
            let rule = issue.get("rule_id").and_then(Value::as_str).unwrap_or("");
            let file = issue.get("file").and_then(Value::as_str).unwrap_or("");
            let line = issue.get("line").and_then(Value::as_str).unwrap_or("");
            if !seen.insert(format!("{rule}|{file}|{line}")) {
                continue;
            }
            let severity = issue.get("severity").and_then(Value::as_str).unwrap_or("");
            let cwe = issue
                .get("cwe")
                .and_then(|cwe| cwe.get("id"))
                .and_then(Value::as_str)
                .and_then(|id| id.parse().ok())
                .map(|id: u32| vec![id])
                .unwrap_or_default();
            findings.push(Finding {
                tool: "gosec".to_string(),
                target: target.to_string(),
                title: rule.to_string(),
                severity: severity_of(severity),
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

fn severity_of(name: &str) -> Severity {
    match name {
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mount_with_the_go_recursion_pattern() {
        let argv = GOSEC.invocation("src:app", &[]);
        assert_eq!(argv, vec!["-fmt=json", "-no-fail", "/src/..."]);
    }

    #[test]
    fn parses_issues_into_findings_with_cwe_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"Issues":[
                {"rule_id":"G204","severity":"MEDIUM","confidence":"HIGH",
                 "cwe":{"id":"78"},"file":"/src/main.go","line":"6"},
                {"rule_id":"G204","severity":"MEDIUM","confidence":"HIGH",
                 "cwe":{"id":"78"},"file":"/src/main.go","line":"6"}
            ],"Stats":{}}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = GOSEC.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "G204");
        assert_eq!(parsed.findings[0].cwe, vec![78]);
        assert_eq!(parsed.findings[0].severity, Severity::Medium);
        assert_eq!(parsed.findings[0].evidence, "/src/main.go:6");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"Issues":[],"Stats":{}}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = GOSEC.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
