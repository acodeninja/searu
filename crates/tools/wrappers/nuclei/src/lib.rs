//! The nuclei tool wrapper: run projectdiscovery/nuclei's templated scan and normalise its JSONL
//! output into vulnerability findings (deduplicated per template + location).

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Nuclei;

pub static NUCLEI: Nuclei = Nuclei;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "templated vulnerability scanning — CVEs, misconfigurations, exposures and default credentials across thousands of community templates",
    invoke: "searu run nuclei --technique T1595 --target http://host:port  (scans all templates; narrow with `-- -tags cve,misconfig`, `-- -severity high,critical` or `-- -t http/...`. OOB/interactsh is disabled.)",
    interpret: "searu findings --tool nuclei — one finding per template match with severity and CWE; info-severity matches are hygiene (missing headers, etc.)",
    chain: "high/critical matches name the weakness to exercise next — feed the matched endpoint to the specific tool (sqlmap, dalfox, ...)",
}];

impl Tool for Nuclei {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        let mut argv = vec![
            "-u".to_string(),
            target.to_string(),
            "-jsonl".to_string(),
            "-silent".to_string(),
            "-ni".to_string(),
            "-disable-update-check".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let info = &value["info"];
            let Some(title) = info["name"]
                .as_str()
                .or_else(|| value["template-id"].as_str())
            else {
                continue;
            };
            let matched_at = value["matched-at"]
                .as_str()
                .or_else(|| value["url"].as_str())
                .or_else(|| value["host"].as_str())
                .unwrap_or(target);
            if !seen.insert((title.to_string(), matched_at.to_string())) {
                continue;
            }
            findings.push(Finding {
                tool: "nuclei".to_string(),
                target: target.to_string(),
                title: title.to_string(),
                severity: severity_of(info["severity"].as_str().unwrap_or("info")),
                status: Status::NeedsReview,
                attack_technique: vec!["T1595".to_string()],
                cwe: cwe_ids(&info["classification"]["cwe-id"]),
                evidence: matched_at.to_string(),
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
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn cwe_number(id: &str) -> Option<u32> {
    id.to_ascii_uppercase()
        .strip_prefix("CWE-")
        .and_then(|number| number.parse().ok())
}

fn cwe_ids(value: &serde_json::Value) -> Vec<u32> {
    value
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(serde_json::Value::as_str)
                .filter_map(cwe_number)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_requests_jsonl_disables_egress_then_passes_through() {
        assert_eq!(
            Nuclei.invocation(
                "http://host:5078",
                &["-tags".to_string(), "cve".to_string()]
            ),
            vec![
                "-u",
                "http://host:5078",
                "-jsonl",
                "-silent",
                "-ni",
                "-disable-update-check",
                "-tags",
                "cve"
            ]
        );
    }

    #[test]
    fn parses_jsonl_matches_into_findings_deduplicated() {
        let stdout = "\
{\"template-id\":\"http-missing-security-headers\",\"info\":{\"name\":\"HTTP Missing Security Headers\",\"severity\":\"info\",\"classification\":{\"cwe-id\":[\"cwe-693\"]}},\"matched-at\":\"http://host:5078\",\"matcher-name\":\"csp\"}\n\
{\"template-id\":\"http-missing-security-headers\",\"info\":{\"name\":\"HTTP Missing Security Headers\",\"severity\":\"info\",\"classification\":{\"cwe-id\":[\"cwe-693\"]}},\"matched-at\":\"http://host:5078\",\"matcher-name\":\"hsts\"}\n\
{\"template-id\":\"CVE-2021-1234\",\"info\":{\"name\":\"Some RCE\",\"severity\":\"critical\",\"classification\":{\"cwe-id\":[\"CWE-78\"]}},\"matched-at\":\"http://host/x\"}\n";
        let parsed = Nuclei.parse("http://host:5078", "T1046", &outcome(stdout));
        assert_eq!(
            parsed.findings.len(),
            2,
            "the two header lines should collapse to one"
        );

        let headers = parsed
            .findings
            .iter()
            .find(|f| f.title == "HTTP Missing Security Headers")
            .unwrap();
        assert_eq!(headers.severity, Severity::Info);
        assert_eq!(headers.cwe, vec![693]);
        assert_eq!(headers.attack_technique, vec!["T1595"]);
        assert_eq!(headers.evidence, "http://host:5078");

        let rce = parsed
            .findings
            .iter()
            .find(|f| f.title == "Some RCE")
            .unwrap();
        assert_eq!(rce.severity, Severity::Critical);
        assert_eq!(rce.cwe, vec![78]);
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        assert!(Nuclei
            .parse("http://host", "T1046", &outcome(""))
            .findings
            .is_empty());
    }
}
