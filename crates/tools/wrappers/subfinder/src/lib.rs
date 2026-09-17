//! The subfinder tool wrapper: passively enumerate a domain's subdomains and normalise subfinder's
//! JSONL into recon observations. subfinder does the OSINT gathering (querying third-party sources);
//! this crate shapes the invocation and reads the result. The target is a bare domain.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Subfinder;

pub static SUBFINDER: Subfinder = Subfinder;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "attack-surface mapping — passively enumerate a domain's subdomains from third-party sources before touching the target (T1590, Passive: allow-listing the technique is enough, no packets to the target)",
    invoke: "searu run subfinder --technique T1590 --target <domain>  (a bare domain, not a URL; subfinder's own flags after `--`)",
    interpret: "searu observations --kind subdomain — each is a candidate host; the ROE's domain suffix rule keeps discovered subdomains in scope",
    chain: "resolve the live ones with dnsx, then fingerprint (httpx) and scan the surface they expose",
}];

impl Tool for Subfinder {
    fn name(&self) -> &'static str {
        "subfinder"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1590"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // `-d` takes the domain; `-silent` keeps the banner off stdout; `-oJ` emits JSONL.
        let mut argv = vec![
            "-d".to_string(),
            target.to_string(),
            "-silent".to_string(),
            "-oJ".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(host) = record.get("host").and_then(Value::as_str) else {
                continue;
            };
            if !seen.insert(host.to_string()) {
                continue;
            }
            let source = record
                .get("source")
                .and_then(Value::as_str)
                .map(str::to_string);
            observations.push(Observation {
                kind: "subdomain".to_string(),
                value: host.to_string(),
                detail: source,
            });
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_enumerates_the_domain_as_jsonl() {
        let argv = SUBFINDER.invocation("example.com", &[]);
        assert_eq!(argv, vec!["-d", "example.com", "-silent", "-oJ"]);
    }

    #[test]
    fn parses_jsonl_into_deduplicated_subdomain_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"host\":\"api.example.com\",\"input\":\"example.com\",\"source\":\"crtsh\"}\n\
                     {\"host\":\"api.example.com\",\"input\":\"example.com\",\"source\":\"other\"}\n\
                     {\"host\":\"mail.example.com\",\"input\":\"example.com\",\"source\":\"dnsdumpster\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SUBFINDER.parse("example.com", "T1046", &outcome);
        assert_eq!(parsed.observations.len(), 2);
        assert_eq!(parsed.observations[0].kind, "subdomain");
        assert_eq!(parsed.observations[0].value, "api.example.com");
        assert_eq!(parsed.observations[0].detail.as_deref(), Some("crtsh"));
        assert_eq!(parsed.observations[1].value, "mail.example.com");
    }

    #[test]
    fn no_subdomains_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = SUBFINDER.parse("example.com", "T1046", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
