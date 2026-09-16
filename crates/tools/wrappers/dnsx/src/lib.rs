//! The dnsx tool wrapper: resolve a host's DNS records and normalise dnsx's JSONL into recon
//! observations. dnsx does the resolving; this crate shapes the invocation and reads the result. dnsx
//! reads the host to resolve on stdin, which the runner already feeds the target on.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Dnsx;

pub static DNSX: Dnsx = Dnsx;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "DNS resolution — resolve a host/subdomain to its A/AAAA/CNAME records, confirming which candidates are live and mapping them to addresses (T1595, Active: allow-listing the technique is enough)",
    invoke: "searu run dnsx --technique T1595 --target <host-or-domain>  (dnsx's own flags after `--`; the host is fed on stdin)",
    interpret: "searu observations --kind dns — each is a resolved record (value = the address / CNAME target, detail = `<TYPE> <host>`); the addresses are new hosts to fingerprint and scan",
    chain: "feed the live subdomains subfinder surfaced through dnsx, then httpx-fingerprint and scan the resolved addresses",
}];

impl Tool for Dnsx {
    fn name(&self) -> &'static str {
        "dnsx"
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

    fn invocation(&self, _target: &str, args: &[String]) -> Vec<String> {
        // dnsx reads the host on stdin (the runner feeds the target there); these flags ask for JSON
        // A/AAAA/CNAME records with no banner.
        let mut argv = vec![
            "-json".to_string(),
            "-a".to_string(),
            "-aaaa".to_string(),
            "-cname".to_string(),
            "-silent".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(host) = record.get("host").and_then(Value::as_str) else {
                continue;
            };
            for (key, label) in [("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME")] {
                let Some(values) = record.get(key).and_then(Value::as_array) else {
                    continue;
                };
                for value in values {
                    let Some(value) = value.as_str() else {
                        continue;
                    };
                    if !seen.insert(format!("{label}|{value}")) {
                        continue;
                    }
                    observations.push(Observation {
                        kind: "dns".to_string(),
                        value: value.to_string(),
                        detail: Some(format!("{label} {host}")),
                    });
                }
            }
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
    fn invocation_asks_for_json_records_reading_the_host_from_stdin() {
        let argv = DNSX.invocation("one.one.one.one", &[]);
        assert_eq!(argv, vec!["-json", "-a", "-aaaa", "-cname", "-silent"]);
    }

    #[test]
    fn parses_records_into_deduplicated_dns_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"host\":\"one.one.one.one\",\"a\":[\"1.0.0.1\",\"1.1.1.1\"],\"aaaa\":[\"2606:4700:4700::1111\"],\"cname\":[]}\n\
                     {\"host\":\"one.one.one.one\",\"a\":[\"1.1.1.1\"]}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = DNSX.parse("one.one.one.one", &outcome);
        assert_eq!(parsed.observations.len(), 3);
        assert_eq!(parsed.observations[0].kind, "dns");
        assert_eq!(parsed.observations[0].value, "1.0.0.1");
        assert_eq!(
            parsed.observations[0].detail.as_deref(),
            Some("A one.one.one.one")
        );
        assert_eq!(parsed.observations[2].value, "2606:4700:4700::1111");
    }

    #[test]
    fn no_records_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = DNSX.parse("nope.invalid", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
