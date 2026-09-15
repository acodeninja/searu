//! The feroxbuster tool wrapper: recursive content discovery. feroxbuster emits one JSON object per
//! line (`type: response` for a discovered path, plus a trailing `statistics` object); we record each
//! response as an endpoint observation. The wordlist is supplied by the caller as a `seclists:` token.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Feroxbuster;

pub static FEROXBUSTER: Feroxbuster = Feroxbuster;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "recursive content & route discovery — brute-force paths and files against a wordlist",
    invoke: "searu run feroxbuster --technique T1595 --target http://host:port -- -w seclists:Discovery/Web-Content/common.txt  (a wordlist is required; add `-x php,txt` for extensions, `-r` to follow redirects)",
    interpret: "searu observations --kind endpoint — one per discovered path with its status",
    chain: "discovered endpoints feed Initial access — the parameters they take are where you test for injection",
}];

impl Tool for Feroxbuster {
    fn name(&self) -> &'static str {
        "feroxbuster"
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
            "--json".to_string(),
            "--silent".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if value["type"].as_str() != Some("response") {
                continue;
            }
            let Some(url) = value["url"].as_str() else {
                continue;
            };
            let detail = value["status"]
                .as_i64()
                .map(|status| format!("status {status}"));
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

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_requests_json_silent_then_passes_the_wordlist_through() {
        assert_eq!(
            Feroxbuster.invocation(
                "http://host",
                &[
                    "-w".to_string(),
                    "seclists:Discovery/Web-Content/common.txt".to_string()
                ]
            ),
            vec![
                "-u",
                "http://host",
                "--json",
                "--silent",
                "-w",
                "seclists:Discovery/Web-Content/common.txt"
            ]
        );
    }

    #[test]
    fn response_lines_become_endpoint_observations_ignoring_statistics() {
        let stdout = "\
{\"type\":\"response\",\"url\":\"http://h/download\",\"path\":\"/download\",\"status\":500,\"method\":\"GET\",\"content_length\":938}\n\
{\"type\":\"response\",\"url\":\"http://h/\",\"path\":\"/\",\"status\":200}\n\
{\"type\":\"statistics\",\"timeouts\":0,\"requests\":3}\n";
        let parsed = Feroxbuster.parse("http://h", &outcome(stdout));
        assert_eq!(parsed.observations.len(), 2);
        assert!(parsed.observations.iter().all(|o| o.kind == "endpoint"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.value == "http://h/download" && o.detail.as_deref() == Some("status 500")));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.value == "http://h/" && o.detail.as_deref() == Some("status 200")));
    }

    #[test]
    fn no_matches_records_nothing() {
        assert!(Feroxbuster
            .parse("http://h", &outcome(""))
            .observations
            .is_empty());
    }
}
