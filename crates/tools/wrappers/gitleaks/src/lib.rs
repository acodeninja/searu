//! The gitleaks tool wrapper: how searu runs gitleaks over a mounted source tree and normalises its
//! JSON report into hardcoded-credential findings. gitleaks does the detection; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree the app mounts read-only at `/src`.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Gitleaks;

pub static GITLEAKS: Gitleaks = Gitleaks;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "secret scanning — sweep source you obtained for hardcoded credentials, API keys and tokens (T1593.003, CWE-798; Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run gitleaks --technique T1593.003 --target src:<workspace-relative-dir>  (gitleaks' own flags after `--`, e.g. `-- --config custom.toml`)",
    interpret: "searu findings --tool gitleaks — one finding per leak, titled by the gitleaks rule id, evidence `file:line` (the secret value itself is not stored). Each is a candidate credential to verify",
    chain: "verify a leaked credential out of band; a live one authorises a credential-access run within the ROE",
}];

impl Tool for Gitleaks {
    fn name(&self) -> &'static str {
        "gitleaks"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--report-path -`
        // streams the JSON report to stdout; `--exit-code 0` keeps a successful scan non-erroring.
        let mut argv = vec![
            "dir".to_string(),
            target.to_string(),
            "--report-format".to_string(),
            "json".to_string(),
            "--report-path".to_string(),
            "-".to_string(),
            "--no-banner".to_string(),
            "--exit-code".to_string(),
            "0".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let Ok(Value::Array(leaks)) = serde_json::from_str::<Value>(&outcome.stdout) else {
            return ParsedOutput::default();
        };
        for leak in &leaks {
            let rule = leak.get("RuleID").and_then(Value::as_str).unwrap_or("");
            let file = leak.get("File").and_then(Value::as_str).unwrap_or("");
            let line = leak.get("StartLine").and_then(Value::as_u64).unwrap_or(0);
            if !seen.insert(format!("{rule}|{file}|{line}")) {
                continue;
            }
            findings.push(Finding {
                tool: "gitleaks".to_string(),
                target: target.to_string(),
                title: rule.to_string(),
                severity: Severity::High,
                status: Status::NeedsReview,
                attack_technique: vec!["T1593.003".to_string()],
                cwe: vec![798],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_source_reporting_json_to_stdout() {
        let argv = GITLEAKS.invocation("src:app", &[]);
        assert_eq!(
            argv,
            vec![
                "dir",
                "src:app",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--no-banner",
                "--exit-code",
                "0",
            ]
        );
    }

    #[test]
    fn parses_leaks_into_hardcoded_credential_findings() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"[
                {"RuleID":"stripe-access-token","Description":"Found a Stripe token",
                 "File":"/src/config.py","StartLine":2,"Secret":"sk_live_xxx"},
                {"RuleID":"stripe-access-token","Description":"Found a Stripe token",
                 "File":"/src/config.py","StartLine":2,"Secret":"sk_live_xxx"}
            ]"#
            .to_string(),
            stderr: String::new(),
        };
        let parsed = GITLEAKS.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "stripe-access-token");
        assert_eq!(parsed.findings[0].cwe, vec![798]);
        assert_eq!(parsed.findings[0].evidence, "/src/config.py:2");
        assert!(!parsed.findings[0].evidence.contains("sk_live"));
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[]".to_string(),
            stderr: String::new(),
        };
        let parsed = GITLEAKS.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
