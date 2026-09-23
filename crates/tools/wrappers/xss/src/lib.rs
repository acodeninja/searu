//! The xss tool wrapper: confirm cross-site scripting by driving a real browser and detecting a payload
//! that actually executes (raising a marked dialog) — the DOM-based XSS a raw HTTP fuzzer (dalfox)
//! cannot see because it never runs the page's JavaScript. The caller marks the injection point with a
//! `PAYLOAD` placeholder in the target (or names a query param); a fired payload is a confirmed CWE-79.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Xss;

pub static XSS: Xss = Xss;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "cross-site scripting, incl. DOM-based — a real browser renders the app and a payload that executes is confirmed by a marked dialog, catching the DOM XSS dalfox's raw requests miss (T1595, CWE-79). Active tier: allow-listing the technique is enough",
    invoke: "searu run xss --technique T1595 --target 'http://host:port/#/search?q=PAYLOAD'  (put PAYLOAD where the value goes — query or hash route — or name the param with `-- --param q`)",
    interpret: "searu findings --tool xss — a confirmed CWE-79 finding naming the payload that executed and the url that fired it",
    chain: "with reflected/DOM XSS proven, escalate per the ROE (cookie/JWT theft, admin action via the victim) or report it as client-side code execution",
}];

impl Tool for Xss {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        // The payload-driving script is spliced into a heredoc so it stays a lint-able file while
        // travelling inside the single Dockerfile the adapter builds.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../xss.js"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The target carries the injection point (a PAYLOAD placeholder); the runner rewrites its host
        // for container reachability.
        let mut argv = vec!["--url".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if record["kind"] != "xss-confirmed" {
                continue;
            }
            let payload = record["payload"].as_str().unwrap_or_default();
            let url = record["url"].as_str().unwrap_or(target);
            findings.push(Finding {
                tool: "xss".to_string(),
                target: url.to_string(),
                title: "Cross-site scripting".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1595".to_string()],
                cwe: vec![79],
                evidence: format!("payload executed in the browser: {payload}"),
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
    fn invocation_carries_the_target_with_its_injection_point() {
        let argv = XSS.invocation("http://h:3000/#/search?q=PAYLOAD", &[]);
        assert_eq!(argv, vec!["--url", "http://h:3000/#/search?q=PAYLOAD"]);
    }

    #[test]
    fn a_fired_payload_is_a_confirmed_xss_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"kind\":\"xss-confirmed\",\"payload\":\"<iframe src=javascript:alert(`x`)>\",\"url\":\"http://h/#/search?q=...\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = XSS.parse("http://h/#/search?q=PAYLOAD", "T1595", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Cross-site scripting");
        assert_eq!(parsed.findings[0].cwe, vec![79]);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
        assert_eq!(parsed.findings[0].target, "http://h/#/search?q=...");
        assert!(parsed.findings[0].evidence.contains("iframe"));
    }

    #[test]
    fn every_firing_payload_records_its_own_finding() {
        // The tool no longer stops at the first hit, so a run that fires two payloads reports both —
        // including the challenge-canonical iframe, not just whichever executed first.
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"kind\":\"xss-confirmed\",\"payload\":\"<img src=x onerror=alert(`x`)>\",\"url\":\"http://h/#/search?q=a\"}\n\
                     {\"kind\":\"xss-confirmed\",\"payload\":\"<iframe src=javascript:alert(`x`)>\",\"url\":\"http://h/#/search?q=b\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = XSS.parse("http://h/#/search?q=PAYLOAD", "T1595", &outcome);
        assert_eq!(parsed.findings.len(), 2);
        assert!(parsed
            .findings
            .iter()
            .any(|f| f.evidence.contains("iframe")));
    }

    #[test]
    fn no_execution_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = XSS.parse("http://h/#/search?q=PAYLOAD", "T1595", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
