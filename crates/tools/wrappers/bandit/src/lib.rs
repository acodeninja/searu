//! The bandit tool wrapper: how searu runs bandit's Python SAST over a mounted source tree and
//! normalises its JSON results into findings. bandit does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Bandit;

pub static BANDIT: Bandit = Bandit;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "Python SAST — scan Python source you obtained for insecure APIs, injection sinks and unsafe defaults (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run bandit --technique T1593.003 --target src:<workspace-relative-dir>  (bandit's own flags after `--`, e.g. `-- --severity-level high`)",
    interpret: "searu findings --tool bandit — one finding per bandit test hit, titled by the test id (Bxxx), evidence `file:line`, tagged with the test's CWE. Severity maps bandit LOW/MEDIUM/HIGH; all are static and need review",
    chain: "triage each hit against the running app; a confirmed injection sink promotes to an exploitation run with an authoriser",
}];

impl Tool for Bandit {
    fn name(&self) -> &'static str {
        "bandit"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--exit-zero` keeps a
        // scan that found issues from erroring; `-r` recurses the tree.
        let mut argv = vec![
            "-r".to_string(),
            target.to_string(),
            "-f".to_string(),
            "json".to_string(),
            "--exit-zero".to_string(),
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
        let Some(results) = doc.get("results").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for result in results {
            let test_id = result.get("test_id").and_then(Value::as_str).unwrap_or("");
            let file = result.get("filename").and_then(Value::as_str).unwrap_or("");
            let line = result
                .get("line_number")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if !seen.insert(format!("{test_id}|{file}|{line}")) {
                continue;
            }
            let severity = result
                .get("issue_severity")
                .and_then(Value::as_str)
                .unwrap_or("");
            let cwe = result
                .get("issue_cwe")
                .and_then(|cwe| cwe.get("id"))
                .and_then(Value::as_u64)
                .map(|id| vec![id as u32])
                .unwrap_or_default();
            findings.push(Finding {
                tool: "bandit".to_string(),
                target: target.to_string(),
                title: test_id.to_string(),
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
    fn invocation_recurses_the_mounted_source_in_json_without_erroring() {
        let argv = BANDIT.invocation("src:app", &[]);
        assert_eq!(argv, vec!["-r", "src:app", "-f", "json", "--exit-zero"]);
    }

    #[test]
    fn parses_results_into_findings_with_cwe_and_location() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[
                {"test_id":"B602","filename":"/src/vuln.py","line_number":4,
                 "issue_severity":"HIGH","issue_cwe":{"id":78}},
                {"test_id":"B307","filename":"/src/vuln.py","line_number":7,
                 "issue_severity":"MEDIUM","issue_cwe":{"id":95}}
            ],"errors":[]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = BANDIT.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].title, "B602");
        assert_eq!(parsed.findings[0].cwe, vec![78]);
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.findings[0].evidence, "/src/vuln.py:4");
        assert_eq!(parsed.findings[1].cwe, vec![95]);
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[],"errors":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = BANDIT.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
