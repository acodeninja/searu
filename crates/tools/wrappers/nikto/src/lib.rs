//! The nikto tool wrapper: web-server misconfiguration scanning. nikto's JSON output cannot target a
//! pipe, so we parse its text report — each reported item is a `+ [<id>] <location>: <message>` line —
//! into info-level findings for review.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Nikto;

pub static NIKTO: Nikto = Nikto;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "web-server misconfiguration & known-file scanning — dangerous methods, outdated software, exposed files, missing headers",
    invoke: "searu run nikto --technique T1595 --target http://host:port  (slow; bound it with `-- -maxtime 120` and focus with `-- -Tuning <categories>`)",
    interpret: "searu findings --tool nikto — one per reported item (info-level; review each, nikto is noisy)",
    chain: "outdated software / exposed files point at a specific exploit — feed them to nuclei, sqlmap or a CVE lookup",
}];

impl Tool for Nikto {
    fn name(&self) -> &'static str {
        "nikto"
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
            "-h".to_string(),
            target.to_string(),
            "-ask".to_string(),
            "no".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Some(rest) = line.trim_start().strip_prefix("+ [") else {
                continue;
            };
            let Some((id, tail)) = rest.split_once("] ") else {
                continue;
            };
            let (location, message) = tail.split_once(": ").unwrap_or(("", tail));
            let title = message.split(" See:").next().unwrap_or(message).trim();
            if title.is_empty() || !seen.insert((title.to_string(), location.to_string())) {
                continue;
            }
            findings.push(Finding {
                tool: "nikto".to_string(),
                target: target.to_string(),
                title: title.to_string(),
                severity: Severity::Info,
                status: Status::NeedsReview,
                attack_technique: vec!["T1595".to_string()],
                cwe: Vec::new(),
                evidence: format!("{} (nikto {id})", location.trim()),
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

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_targets_the_host_non_interactively_then_passes_through() {
        assert_eq!(
            Nikto.invocation("http://h", &["-Tuning".to_string(), "b".to_string()]),
            vec!["-h", "http://h", "-ask", "no", "-Tuning", "b"]
        );
    }

    #[test]
    fn parses_reported_items_into_findings() {
        let stdout = "- Nikto v2.6.1\n\
+ Target IP:          172.17.0.1\n\
+ [000287] /: Retrieved x-powered-by header: Express.\n\
+ [013587] /: Suggested security header missing: content-security-policy. See: https://x\n\
+ 1624 requests: 0 errors and 2 items reported\n";
        let parsed = Nikto.parse("http://h", &outcome(stdout));
        assert_eq!(parsed.findings.len(), 2);
        assert!(parsed
            .findings
            .iter()
            .all(|f| f.severity == Severity::Info && f.attack_technique == vec!["T1595"]));
        assert!(parsed
            .findings
            .iter()
            .any(|f| f.title == "Retrieved x-powered-by header: Express."));
        let header = parsed
            .findings
            .iter()
            .find(|f| f.title.starts_with("Suggested security header"))
            .unwrap();
        assert_eq!(
            header.title,
            "Suggested security header missing: content-security-policy."
        );
        assert!(header.evidence.contains("nikto 013587"));
    }

    #[test]
    fn no_reported_items_records_nothing() {
        assert!(Nikto
            .parse("http://h", &outcome("- Nikto v2.6.1\n+ Target IP: x\n"))
            .findings
            .is_empty());
    }
}
