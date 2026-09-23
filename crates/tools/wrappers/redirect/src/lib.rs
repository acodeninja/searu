//! The redirect tool wrapper: test an app's redirect endpoint for an open/unvalidated redirect
//! (CWE-601). It sends attacker destinations (and allow-list-bypass variants that append a known
//! allow-listed URL) to the redirect parameter *without following redirects*; if the server answers 3xx
//! with a `Location` pointing off the target origin to our controlled destination, that is a confirmed
//! open redirect. This is the tool for the `redirect-ssrf` coverage class.

use searu_domain::findings::{Finding, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Redirect;

pub static REDIRECT: Redirect = Redirect;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "open / unvalidated redirect — coax a redirect endpoint into sending the victim off-site, incl. defeating a substring allow-list by appending an allow-listed URL to an attacker URL (T1595, CWE-601). Active tier: allow-listing the technique is enough",
    invoke: "searu run redirect --technique T1595 --target http://host:port/redirect  (`--param to` names the redirect parameter; bypass a substring allow-list with `-- --allowlisted https://github.com/juice-shop/juice-shop`; set the attacker URL with `--attacker https://evil.example`)",
    interpret: "searu findings --tool redirect — a confirmed CWE-601 finding naming the payload and the Location it was sent to; searu observations --kind redirect for every probe's status/Location",
    chain: "an open redirect chains into phishing/OAuth-token theft and is a stepping stone to SSRF where the redirect is followed server-side",
}];

impl Tool for Redirect {
    fn name(&self) -> &'static str {
        "redirect"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        // The probe script is spliced into a heredoc so it stays a lint-able file while travelling
        // inside the single Dockerfile the adapter builds.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../redirect.py"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The target is the redirect endpoint; the runner rewrites its host for reachability.
        let mut argv = vec!["--url".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            if let Some(rest) = line.strip_prefix("REDIRECT-VIOLATION ") {
                let location = field(rest, "location=");
                let payload = field(rest, "payload=");
                findings.push(Finding {
                    tool: "redirect".to_string(),
                    target: field(rest, "url=").unwrap_or_else(|| target.to_string()),
                    title: "Open redirect".to_string(),
                    severity: Severity::Medium,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1595".to_string()],
                    cwe: vec![601],
                    evidence: format!(
                        "redirect sent off-site to {} via payload {}",
                        location.as_deref().unwrap_or("?"),
                        payload.as_deref().unwrap_or("?")
                    ),
                    loot_fingerprint: None,
                });
                continue;
            }
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                if record["kind"] == "redirect" {
                    if let Some(url) = record["url"].as_str() {
                        let status = record["status"].as_i64().unwrap_or_default();
                        let location = record["location"].as_str().unwrap_or("-");
                        observations.push(Observation {
                            kind: "redirect".to_string(),
                            value: url.to_string(),
                            detail: Some(format!("status {status} -> {location}")),
                        });
                    }
                }
            }
        }
        ParsedOutput {
            findings,
            observations,
            ..Default::default()
        }
    }
}

fn field(line: &str, marker: &str) -> Option<String> {
    line.split_once(marker)
        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(rest).to_string())
        .filter(|value| !value.is_empty())
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
    fn invocation_puts_the_redirect_endpoint_first() {
        let argv = REDIRECT.invocation(
            "http://h:3000/redirect",
            &[
                "--allowlisted".to_string(),
                "https://ok.example".to_string(),
            ],
        );
        assert_eq!(
            argv,
            vec![
                "--url",
                "http://h:3000/redirect",
                "--allowlisted",
                "https://ok.example"
            ]
        );
    }

    #[test]
    fn an_off_site_redirect_is_a_confirmed_finding() {
        let out = outcome(
            "{\"kind\":\"redirect\",\"status\":302,\"location\":\"https://evil.example/pwned\",\"url\":\"http://h/redirect?to=...\"}\n\
             REDIRECT-VIOLATION status=302 location=https://evil.example/pwned payload=https://evil.example/pwned url=http://h/redirect?to=x\n",
        );
        let parsed = REDIRECT.parse("http://h/redirect", "T1595", &out);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Open redirect");
        assert_eq!(parsed.findings[0].cwe, vec![601]);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
        assert!(parsed.findings[0].evidence.contains("evil.example"));
        assert_eq!(parsed.observations.len(), 1);
    }

    #[test]
    fn a_contained_redirect_records_only_the_probe() {
        let out = outcome(
            "{\"kind\":\"redirect\",\"status\":200,\"location\":null,\"url\":\"http://h/redirect?to=x\"}\n",
        );
        let parsed = REDIRECT.parse("http://h/redirect", "T1595", &out);
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.observations.len(), 1);
    }
}
