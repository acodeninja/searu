//! The trivy tool wrapper: how searu runs trivy's filesystem vulnerability scan over a mounted source
//! tree and normalises its JSON results into findings. trivy does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`. The
//! wrapper runs the vulnerability scanner only; secret and misconfiguration scanning are other tools.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Trivy;

pub static TRIVY: Trivy = Trivy;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "software-composition analysis — find known-vulnerable dependencies (by CVE) in the lockfiles and installed packages of source you obtained, a broad-ecosystem alternative to grype (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run trivy --technique T1593.003 --target src:<workspace-relative-dir>  (trivy's own flags after `--`, e.g. `-- --severity CRITICAL,HIGH`). First run downloads trivy's vulnerability database",
    interpret: "searu findings --tool trivy — one finding per vulnerable package, titled by the CVE id, evidence the `package@version`, tagged with the CVE's CWE(s). Severity is trivy's; confirm against the deployed version",
    chain: "confirm the vulnerable version is the one deployed; a reachable, exploitable CVE promotes to an exploitation run with an authoriser",
}];

impl Tool for Trivy {
    fn name(&self) -> &'static str {
        "trivy"
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
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--scanners vuln`
        // keeps trivy to its SCA role; `--quiet` keeps progress off stdout so only JSON is captured.
        let mut argv = vec![
            "fs".to_string(),
            "--scanners".to_string(),
            "vuln".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--quiet".to_string(),
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
        let Some(results) = doc.get("Results").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for result in results {
            let Some(vulnerabilities) = result.get("Vulnerabilities").and_then(Value::as_array)
            else {
                continue;
            };
            for vulnerability in vulnerabilities {
                let id = vulnerability
                    .get("VulnerabilityID")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let name = vulnerability
                    .get("PkgName")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let version = vulnerability
                    .get("InstalledVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !seen.insert(format!("{id}|{name}|{version}")) {
                    continue;
                }
                let severity = vulnerability
                    .get("Severity")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let cwe = vulnerability
                    .get("CweIDs")
                    .map(collect_cwe)
                    .unwrap_or_default();
                findings.push(Finding {
                    tool: "trivy".to_string(),
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
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn severity_of(name: &str) -> Severity {
    match name {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
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
    fn invocation_runs_the_vuln_scanner_over_the_mount_as_json() {
        let argv = TRIVY.invocation("src:app", &[]);
        assert_eq!(
            argv,
            vec![
                "fs",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--quiet",
                "src:app",
            ]
        );
    }

    #[test]
    fn parses_vulnerabilities_into_findings_with_cwe_and_package() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"Results":[
                {"Target":"requirements.txt","Vulnerabilities":[
                    {"VulnerabilityID":"CVE-2019-14234","PkgName":"django",
                     "InstalledVersion":"2.2.0","Severity":"CRITICAL","CweIDs":["CWE-89"]},
                    {"VulnerabilityID":"CVE-2019-14234","PkgName":"django",
                     "InstalledVersion":"2.2.0","Severity":"CRITICAL","CweIDs":["CWE-89"]}
                ]}
            ]}"#
            .to_string(),
            stderr: String::new(),
        };
        let parsed = TRIVY.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CVE-2019-14234");
        assert_eq!(parsed.findings[0].severity, Severity::Critical);
        assert_eq!(parsed.findings[0].cwe, vec![89]);
        assert_eq!(parsed.findings[0].evidence, "django@2.2.0");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"Results":[{"Target":"requirements.txt"}]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = TRIVY.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
