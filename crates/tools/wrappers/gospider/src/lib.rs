//! The gospider tool wrapper: crawl a web target and normalise gospider's JSONL into endpoint
//! observations. gospider does the crawling; this crate shapes the invocation and reads the result. The
//! target is a URL; searu rewrites it for container reachability.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Gospider;

pub static GOSPIDER: Gospider = Gospider;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "web crawling — map a site's URLs, forms and linked JavaScript from robots/sitemap/body/JS to build the attack surface (T1595, Active: allow-listing the technique is enough)",
    invoke: "searu run gospider --technique T1595 --target http://host:port  (gospider's own flags after `--`, e.g. `-- -d 2 -c 10` for depth/concurrency)",
    interpret: "searu observations --kind endpoint — each is a discovered URL, with how it was found (form/url/javascript/robots) as the detail; these are the routes and forms to fingerprint and attack",
    chain: "feed the endpoints and forms into discovery (ffuf/arjun) and initial access (dalfox/sqlmap) for the parameters worth attacking",
}];

impl Tool for Gospider {
    fn name(&self) -> &'static str {
        "gospider"
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
        // `-s` takes the seed URL (the runner rewrites it for reachability); `--json` emits JSONL and
        // `-q` quiets the banner.
        let mut argv = vec![
            "-s".to_string(),
            target.to_string(),
            "--json".to_string(),
            "-q".to_string(),
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
            let Some(url) = record.get("output").and_then(Value::as_str) else {
                continue;
            };
            if url.is_empty() || !seen.insert(url.to_string()) {
                continue;
            }
            let detail = record
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_string);
            observations.push(Observation {
                kind: "endpoint".to_string(),
                value: url.to_string(),
                detail,
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
    fn invocation_seeds_the_crawl_from_the_target_as_json() {
        let argv = GOSPIDER.invocation("http://host:3000", &[]);
        assert_eq!(argv, vec!["-s", "http://host:3000", "--json", "-q"]);
    }

    #[test]
    fn parses_jsonl_into_deduplicated_endpoint_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"source\":\"robots\",\"type\":\"url\",\"output\":\"http://h:3000/ftp\"}\n\
                     {\"source\":\"body\",\"type\":\"url\",\"output\":\"http://h:3000/ftp\"}\n\
                     {\"source\":\"body\",\"type\":\"form\",\"output\":\"http://h:3000/login\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = GOSPIDER.parse("http://h:3000", &outcome);
        assert_eq!(parsed.observations.len(), 2);
        assert_eq!(parsed.observations[0].kind, "endpoint");
        assert_eq!(parsed.observations[0].value, "http://h:3000/ftp");
        assert_eq!(parsed.observations[0].detail.as_deref(), Some("url"));
        assert_eq!(parsed.observations[1].detail.as_deref(), Some("form"));
    }

    #[test]
    fn nothing_crawled_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = GOSPIDER.parse("http://h:3000", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
