//! The dalfox tool wrapper: XSS detection. dalfox v3 emits a single JSON object `{ findings, meta }`;
//! we record each finding as a cross-site-scripting finding (CWE-79), Confirmed when dalfox verified
//! it (`type: V`) and NeedsReview otherwise.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Dalfox;

pub static DALFOX: Dalfox = Dalfox;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "XSS detection & verification — reflected/stored/DOM cross-site scripting in a parameter",
    invoke: "searu run dalfox --technique T1595 --target 'http://host:port/path?param=test'  (point at a URL carrying the parameter to test; dalfox also mines parameters)",
    interpret: "searu findings --tool dalfox — confirmed (verified) or reflected XSS, CWE-79, with the PoC URL as evidence",
    chain: "a confirmed XSS is a client-side foothold (session theft, CSRF); the PoC URL is the reproduction",
}];

impl Tool for Dalfox {
    fn name(&self) -> &'static str {
        "dalfox"
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
            "url".to_string(),
            "--url".to_string(),
            target.to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--no-color".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let root = serde_json::Deserializer::from_str(&outcome.stdout)
            .into_iter::<serde_json::Value>()
            .flatten()
            .find(|value| value.get("findings").is_some());
        let mut findings = Vec::new();
        for finding in root
            .as_ref()
            .and_then(|root| root["findings"].as_array())
            .into_iter()
            .flatten()
        {
            let param = finding["param"].as_str().unwrap_or("a parameter");
            let status = if finding["type"].as_str() == Some("V") {
                Status::Confirmed
            } else {
                Status::NeedsReview
            };
            let evidence = finding["data"]
                .as_str()
                .or_else(|| finding["payload"].as_str())
                .unwrap_or_default();
            findings.push(Finding {
                tool: "dalfox".to_string(),
                target: target.to_string(),
                title: format!("Cross-site scripting in {param}"),
                severity: severity_of(finding["severity"].as_str().unwrap_or("medium")),
                status,
                attack_technique: vec!["T1595".to_string()],
                cwe: cwe_number(finding["cwe"].as_str().unwrap_or_default())
                    .into_iter()
                    .collect(),
                evidence: evidence.to_string(),
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
    match name.to_ascii_lowercase().as_str() {
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
    fn invocation_uses_the_url_flag_and_json_then_passes_through() {
        assert_eq!(
            Dalfox.invocation("http://h/?q=1", &["--deep-domxss".to_string()]),
            vec![
                "url",
                "--url",
                "http://h/?q=1",
                "--format",
                "json",
                "--no-color",
                "--deep-domxss"
            ]
        );
    }

    #[test]
    fn a_verified_finding_becomes_a_confirmed_xss() {
        let stdout = "{\"findings\":[{\"cwe\":\"CWE-79\",\"param\":\"q\",\"payload\":\"<svg onload=alert(1)>\",\"data\":\"http://h/?q=%3Csvg%3E\",\"severity\":\"High\",\"type\":\"V\",\"inject_type\":\"inHTML\"}],\"meta\":{\"findings_count\":1}}";
        let parsed = Dalfox.parse("http://h/?q=test", &outcome(stdout));
        assert_eq!(parsed.findings.len(), 1);
        let xss = &parsed.findings[0];
        assert_eq!(xss.title, "Cross-site scripting in q");
        assert_eq!(xss.severity, Severity::High);
        assert_eq!(xss.status, Status::Confirmed);
        assert_eq!(xss.cwe, vec![79]);
        assert_eq!(xss.attack_technique, vec!["T1595"]);
        assert_eq!(xss.evidence, "http://h/?q=%3Csvg%3E");
    }

    #[test]
    fn no_findings_records_nothing() {
        let stdout = "{\"findings\":[],\"meta\":{\"findings_count\":0}}";
        assert!(Dalfox
            .parse("http://h", &outcome(stdout))
            .findings
            .is_empty());
    }
}
