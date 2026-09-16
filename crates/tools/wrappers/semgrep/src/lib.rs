//! The semgrep tool wrapper: how searu runs pattern SAST over a mounted source tree and normalises the
//! JSON results into findings. semgrep does the analysis; this crate shapes the invocation and reads the
//! result. The target is a `src:<path>` source tree the app mounts read-only at `/src`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Semgrep;

pub static SEMGREP: Semgrep = Semgrep;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "static application security testing — scan source you obtained (dumped or cloned) for injection, unsafe APIs, hardcoded secrets and other weakness patterns across many languages (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run semgrep --technique T1593.003 --target src:<workspace-relative-dir>  (add a `-- --config <ruleset>` to override the default `auto` registry ruleset)",
    interpret: "searu findings --tool semgrep — one finding per rule hit, titled by the semgrep rule id, evidence `file:line`, tagged with the rule's CWE(s). Severity maps ERROR→high, WARNING→medium; all are static and need review",
    chain: "triage each hit against the running app; a confirmed injection point promotes to an exploitation run (e.g. sqlmap/commix) with an authoriser",
}];

impl Tool for Semgrep {
    fn name(&self) -> &'static str {
        "semgrep"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--config auto`
        // pulls a language-matched ruleset from the registry; the caller can add their own after `--`.
        let mut argv = vec![
            "scan".to_string(),
            "--json".to_string(),
            "--config".to_string(),
            "auto".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv.push(target.to_string());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(doc) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        let Some(results) = doc.get("results").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for result in results {
            let check_id = result.get("check_id").and_then(Value::as_str).unwrap_or("");
            let path = result.get("path").and_then(Value::as_str).unwrap_or("");
            let line = result
                .get("start")
                .and_then(|start| start.get("line"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if !seen.insert(format!("{check_id}|{path}|{line}")) {
                continue;
            }
            let extra = result.get("extra");
            let severity = extra
                .and_then(|extra| extra.get("severity"))
                .and_then(Value::as_str)
                .unwrap_or("INFO");
            let cwe = extra
                .and_then(|extra| extra.get("metadata"))
                .and_then(|metadata| metadata.get("cwe"))
                .map(collect_cwe)
                .unwrap_or_default();
            findings.push(Finding {
                tool: "semgrep".to_string(),
                target: target.to_string(),
                title: check_id.to_string(),
                severity: severity_of(severity),
                status: Status::NeedsReview,
                attack_technique: vec!["T1593.003".to_string()],
                cwe,
                evidence: format!("{path}:{line}"),
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
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        _ => Severity::Info,
    }
}

fn collect_cwe(value: &Value) -> Vec<u32> {
    let mut out = Vec::new();
    let mut push = |text: &str| {
        if let Some(rest) = text.strip_prefix("CWE-") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(number) = digits.parse() {
                out.push(number);
            }
        }
    };
    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(text) = item.as_str() {
                    push(text);
                }
            }
        }
        Value::String(text) => push(text),
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_source_in_json() {
        let argv = SEMGREP.invocation("src:app", &[]);
        assert_eq!(argv, vec!["scan", "--json", "--config", "auto", "src:app"]);
    }

    #[test]
    fn parses_results_into_findings_with_cwe_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[
                {"check_id":"python.lang.security.subprocess-shell-true","path":"/src/vuln.py",
                 "start":{"line":4},
                 "extra":{"severity":"ERROR","metadata":{"cwe":["CWE-78: OS Command Injection"]}}},
                {"check_id":"python.lang.security.eval-detected","path":"/src/vuln.py",
                 "start":{"line":7},
                 "extra":{"severity":"WARNING","metadata":{"cwe":["CWE-95: Eval Injection"]}}}
            ],"errors":[]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SEMGREP.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].cwe, vec![78]);
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.findings[0].evidence, "/src/vuln.py:4");
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1593.003"]);
        assert_eq!(parsed.findings[1].cwe, vec![95]);
        assert_eq!(parsed.findings[1].severity, Severity::Medium);
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[],"errors":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = SEMGREP.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
