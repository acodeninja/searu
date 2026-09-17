//! The osv-scanner tool wrapper: how searu runs Google's osv-scanner over a mounted source tree and
//! normalises its JSON results into findings. osv-scanner does the analysis; this crate shapes the
//! invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`;
//! osv-scanner matches its lockfiles against the OSV database.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct OsvScanner;

pub static OSV_SCANNER: OsvScanner = OsvScanner;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "software-composition analysis against the OSV database — find known-vulnerable dependencies in the lockfiles of source you obtained, complementing grype/trivy (T1593.003, Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run osv-scanner --technique T1593.003 --target src:<workspace-relative-dir>  (osv-scanner's own flags after `--`)",
    interpret: "searu findings --tool osv-scanner — one finding per vulnerable package, titled by the CVE (or the OSV id), evidence the `package@version`. Severity is unnormalised — confirm it from the CVE",
    chain: "confirm the vulnerable version is the one deployed; a reachable, exploitable CVE promotes to an exploitation run with an authoriser",
}];

impl Tool for OsvScanner {
    fn name(&self) -> &'static str {
        "osv-scanner"
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
        let mut argv = vec![
            "scan".to_string(),
            "source".to_string(),
            "--format".to_string(),
            "json".to_string(),
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
        let Some(results) = doc.get("results").and_then(Value::as_array) else {
            return ParsedOutput::default();
        };
        for result in results {
            let Some(packages) = result.get("packages").and_then(Value::as_array) else {
                continue;
            };
            for package in packages {
                let info = package.get("package");
                let name = info
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let version = info
                    .and_then(|p| p.get("version"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let Some(vulnerabilities) =
                    package.get("vulnerabilities").and_then(Value::as_array)
                else {
                    continue;
                };
                for vulnerability in vulnerabilities {
                    let id = vulnerability
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let title = preferred_id(vulnerability, id);
                    if !seen.insert(format!("{title}|{name}|{version}")) {
                        continue;
                    }
                    findings.push(Finding {
                        tool: "osv-scanner".to_string(),
                        target: target.to_string(),
                        title: title.to_string(),
                        severity: Severity::Medium,
                        status: Status::NeedsReview,
                        attack_technique: vec!["T1593.003".to_string()],
                        cwe: Vec::new(),
                        evidence: format!("{name}@{version}"),
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

fn preferred_id<'a>(vulnerability: &'a Value, fallback: &'a str) -> &'a str {
    vulnerability
        .get("aliases")
        .and_then(Value::as_array)
        .and_then(|aliases| {
            aliases
                .iter()
                .filter_map(Value::as_str)
                .find(|alias| alias.starts_with("CVE-"))
        })
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_source_in_json() {
        let argv = OSV_SCANNER.invocation("src:app", &[]);
        assert_eq!(argv, vec!["scan", "source", "--format", "json", "src:app"]);
    }

    #[test]
    fn parses_results_preferring_the_cve_and_recording_the_package() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[{"packages":[
                {"package":{"name":"django","version":"2.2.0","ecosystem":"PyPI"},
                 "vulnerabilities":[
                    {"id":"PYSEC-2019-11","aliases":["CVE-2019-14232","GHSA-c4qh-4vgv-qc6g"]},
                    {"id":"PYSEC-2019-11","aliases":["CVE-2019-14232"]}
                 ]}
            ]}]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = OSV_SCANNER.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CVE-2019-14232");
        assert_eq!(parsed.findings[0].evidence, "django@2.2.0");
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1593.003"]);
    }

    #[test]
    fn falls_back_to_the_osv_id_without_a_cve_alias() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[{"packages":[
                {"package":{"name":"left-pad","version":"1.0.0"},
                 "vulnerabilities":[{"id":"GHSA-abcd-1234-wxyz","aliases":[]}]}
            ]}]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = OSV_SCANNER.parse("src:app", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "GHSA-abcd-1234-wxyz");
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"results":[]}"#.to_string(),
            stderr: String::new(),
        };
        let parsed = OSV_SCANNER.parse("src:app", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
