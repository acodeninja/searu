//! The grype tool wrapper: how searu runs grype's software-composition analysis over a mounted source
//! tree and normalises its JSON matches into findings. grype does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`;
//! grype catalogues its lockfiles and installed packages and matches them against vulnerability data.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::scope::SOURCE_MOUNT;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Grype;

pub static GRYPE: Grype = Grype;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "software-composition analysis — find known-vulnerable dependencies (by CVE/GHSA) in the lockfiles and installed packages of source you obtained (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run grype --technique T1593.003 --target src:<workspace-relative-dir>  (grype's own flags after `--`, e.g. `-- --only-fixed`). First run downloads grype's vulnerability database",
    interpret: "searu findings --tool grype — one finding per vulnerable package, titled by the CVE/GHSA id, evidence the `package@version`. Severity is grype's; each is a candidate to confirm against the deployed version",
    chain: "confirm the vulnerable version is the one deployed; a reachable, exploitable CVE promotes to an exploitation run with an authoriser",
}];

impl Tool for Grype {
    fn name(&self) -> &'static str {
        "grype"
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
        // The source target drives the read-only `/src` mount; grype scans it as a directory source.
        let mut argv = vec![
            format!("dir:{SOURCE_MOUNT}"),
            "-o".to_string(),
            "json".to_string(),
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
        let Some(matches) = doc.get("matches").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for entry in matches {
            let vulnerability = entry.get("vulnerability");
            let id = vulnerability
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let artifact = entry.get("artifact");
            let name = artifact
                .and_then(|a| a.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let version = artifact
                .and_then(|a| a.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !seen.insert(format!("{id}|{name}|{version}")) {
                continue;
            }
            let severity = vulnerability
                .and_then(|v| v.get("severity"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let cwe = vulnerability
                .and_then(|v| v.get("cwes"))
                .map(collect_cwe)
                .unwrap_or_default();
            findings.push(Finding {
                tool: "grype".to_string(),
                target: target.to_string(),
                title: id.to_string(),
                severity: severity_of(severity),
                status: Status::NeedsReview,
                attack_technique: vec!["T1593.003".to_string()],
                cwe,
                evidence: format!("{name}@{version}"),
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
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn collect_cwe(value: &Value) -> Vec<u32> {
    let Value::Array(items) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|text| text.strip_prefix("CWE-"))
        .filter_map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mount_as_a_directory_source() {
        let argv = GRYPE.invocation("src:app", &[]);
        assert_eq!(argv, vec!["dir:/src", "-o", "json"]);
    }

    #[test]
    fn parses_matches_into_findings_with_the_vulnerable_package() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"matches":[
                {"vulnerability":{"id":"CVE-2019-14232","severity":"High","cwes":["CWE-400"]},
                 "artifact":{"name":"django","version":"2.2.0"}},
                {"vulnerability":{"id":"CVE-2019-14232","severity":"High","cwes":["CWE-400"]},
                 "artifact":{"name":"django","version":"2.2.0"}}
            ]}"#
            .to_string(),
            stderr: String::new(),
        };
        let parsed = GRYPE.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CVE-2019-14232");
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.findings[0].cwe, vec![400]);
        assert_eq!(parsed.findings[0].evidence, "django@2.2.0");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"matches":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = GRYPE.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
