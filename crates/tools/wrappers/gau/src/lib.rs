//! The gau tool wrapper: mine a domain's historical URLs from web archives (Wayback, CommonCrawl, OTX)
//! and normalise them into endpoint observations. gau does the OSINT gathering (querying third-party
//! archives); this crate shapes the invocation and reads the result. The target is a bare domain.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Gau;

pub static GAU: Gau = Gau;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "historical-URL mining — recover a domain's known URLs from public web archives without touching the target, surfacing old endpoints, parameters and paths (T1593, Passive: allow-listing the technique is enough)",
    invoke: "searu run gau --technique T1593 --target <domain>  (a bare domain; gau's own flags after `--`, e.g. `-- --subs` to include subdomains)",
    interpret: "searu observations --kind endpoint — each is an archived URL; parameterised ones and old paths are prime targets to re-test against the live app",
    chain: "feed the parameterised URLs into discovery (arjun) and initial access (dalfox/sqlmap); confirm which archived paths still resolve",
}];

impl Tool for Gau {
    fn name(&self) -> &'static str {
        "gau"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1593"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // gau takes the domain as a positional argument and prints one URL per line; `--threads` bounds
        // the archive queries.
        let mut argv = vec![target.to_string(), "--threads".to_string(), "5".to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let url = line.trim();
            if !url.starts_with("http") || !seen.insert(url.to_string()) {
                continue;
            }
            observations.push(Observation {
                kind: "endpoint".to_string(),
                value: url.to_string(),
                detail: Some("historical".to_string()),
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
    fn invocation_mines_the_domain() {
        let argv = GAU.invocation("example.com", &[]);
        assert_eq!(argv, vec!["example.com", "--threads", "5"]);
    }

    #[test]
    fn parses_urls_into_deduplicated_endpoint_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "https://example.com/old?id=1\n\
                     https://example.com/old?id=1\n\
                     http://example.com/legacy\n\
                     not-a-url\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = GAU.parse("example.com", &outcome);
        assert_eq!(parsed.observations.len(), 2);
        assert_eq!(parsed.observations[0].kind, "endpoint");
        assert_eq!(parsed.observations[0].value, "https://example.com/old?id=1");
        assert_eq!(parsed.observations[0].detail.as_deref(), Some("historical"));
        assert_eq!(parsed.observations[1].value, "http://example.com/legacy");
    }

    #[test]
    fn no_urls_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = GAU.parse("example.com", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
