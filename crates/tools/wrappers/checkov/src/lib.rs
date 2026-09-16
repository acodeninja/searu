//! The checkov tool wrapper: how searu runs checkov's IaC misconfiguration scan over a mounted source
//! tree and normalises its JSON failed checks into findings. checkov does the analysis; this crate
//! shapes the invocation and reads the result. The target is a `src:<path>` tree mounted read-only at
//! `/src`; checkov reports per file path relative to that root.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Checkov;

pub static CHECKOV: Checkov = Checkov;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "infrastructure-as-code misconfiguration scanning — check Terraform, CloudFormation, Kubernetes and other IaC in source you obtained for insecure defaults and policy violations (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run checkov --technique T1593.003 --target src:<workspace-relative-dir>  (checkov's own flags after `--`, e.g. `-- --framework terraform`)",
    interpret: "searu findings --tool checkov — one finding per failed check, titled by the check id (CKV…), evidence `file:line`. checkov does not attach a CWE; consult the check's guideline for the fix",
    chain: "a misconfiguration in reachable infrastructure (open ingress, public bucket) points at a concrete attack path to pursue within the ROE",
}];

impl Tool for Checkov {
    fn name(&self) -> &'static str {
        "checkov"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--soft-fail` keeps a
        // scan that found failures from erroring; `--compact` drops the code blocks from the report.
        let mut argv = vec![
            "-d".to_string(),
            target.to_string(),
            "-o".to_string(),
            "json".to_string(),
            "--soft-fail".to_string(),
            "--compact".to_string(),
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
        // checkov emits a single object when one framework runs and an array when several do.
        let reports: Vec<&Value> = match &doc {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for report in reports {
            let Some(failed) = report
                .get("results")
                .and_then(|results| results.get("failed_checks"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for check in failed {
                let id = check.get("check_id").and_then(Value::as_str).unwrap_or("");
                let file = check.get("file_path").and_then(Value::as_str).unwrap_or("");
                let line = check
                    .get("file_line_range")
                    .and_then(Value::as_array)
                    .and_then(|range| range.first())
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if !seen.insert(format!("{id}|{file}|{line}")) {
                    continue;
                }
                let severity = check.get("severity").and_then(Value::as_str).unwrap_or("");
                findings.push(Finding {
                    tool: "checkov".to_string(),
                    target: target.to_string(),
                    title: id.to_string(),
                    severity: severity_of(severity),
                    status: Status::NeedsReview,
                    attack_technique: vec!["T1593.003".to_string()],
                    cwe: Vec::new(),
                    evidence: format!("{file}:{line}"),
                    loot_fingerprint: None,
                });
            }
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn severity_of(name: &str) -> Severity {
    // checkov only populates severity with a platform API key; default misconfigurations to Medium.
    match name {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_directory_as_json_without_erroring() {
        let argv = CHECKOV.invocation("src:app", &[]);
        assert_eq!(
            argv,
            vec!["-d", "src:app", "-o", "json", "--soft-fail", "--compact"]
        );
    }

    #[test]
    fn parses_failed_checks_from_a_single_framework_object() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"check_type":"terraform","results":{"failed_checks":[
                {"check_id":"CKV_AWS_23","file_path":"/main.tf","file_line_range":[1,9]},
                {"check_id":"CKV_AWS_23","file_path":"/main.tf","file_line_range":[1,9]}
            ]}}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = CHECKOV.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CKV_AWS_23");
        assert_eq!(parsed.findings[0].severity, Severity::Medium);
        assert_eq!(parsed.findings[0].evidence, "/main.tf:1");
    }

    #[test]
    fn parses_failed_checks_from_a_multi_framework_array() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"[
                {"check_type":"terraform","results":{"failed_checks":[
                    {"check_id":"CKV_AWS_24","file_path":"/main.tf","file_line_range":[3,3]}
                ]}},
                {"check_type":"secrets","results":{"failed_checks":[]}}
            ]"#
            .to_string(),
            stderr: String::new(),
        };
        let parsed = CHECKOV.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CKV_AWS_24");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"check_type":"terraform","results":{"failed_checks":[]}}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = CHECKOV.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
