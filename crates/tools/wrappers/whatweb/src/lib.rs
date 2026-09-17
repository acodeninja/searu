//! The whatweb tool wrapper: fingerprint a target's technology stack and normalise whatweb's JSON
//! (one object per line, amid its plaintext summary) into recon observations.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Whatweb;

pub static WHATWEB: Whatweb = Whatweb;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "HTTP technology & stack fingerprint — server, framework, CMS, JS libraries, headers",
    invoke: "searu run whatweb --technique T1595 --target http://host:port  (add `-- -a 3` for an aggressive scan)",
    interpret: "searu observations --kind tech / --kind server / --kind title — the detected stack",
    chain: "the stack picks the CMS scanner (wpscan/joomscan), the SecLists wordlist and the weakness to look for",
}];

impl Tool for Whatweb {
    fn name(&self) -> &'static str {
        "whatweb"
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
            "--colour=never".to_string(),
            "--log-json=/dev/stdout".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv.push(target.to_string());
        argv
    }

    fn parse(&self, _target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(plugins) = value["plugins"].as_object() else {
                continue;
            };
            for (name, details) in plugins {
                let strings: Vec<&str> = details["string"]
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect()
                    })
                    .unwrap_or_default();
                let detail = (!strings.is_empty()).then(|| strings.join(", "));
                let kind = match name.as_str() {
                    "HTTPServer" => "server",
                    "Title" => "title",
                    _ => "tech",
                };
                observations.push(Observation {
                    kind: kind.to_string(),
                    value: name.clone(),
                    detail,
                });
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

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_requests_json_with_the_target_last() {
        assert_eq!(
            Whatweb.invocation("http://host", &["-a".to_string(), "3".to_string()]),
            vec![
                "--colour=never",
                "--log-json=/dev/stdout",
                "-a",
                "3",
                "http://host"
            ]
        );
    }

    #[test]
    fn parses_plugins_into_observations_skipping_the_plaintext_summary() {
        let stdout = "[\n\
{\"target\":\"http://host\",\"http_status\":200,\"plugins\":{\"X-Powered-By\":{\"string\":[\"Express\"]},\"HTTPServer\":{\"string\":[\"nginx\"]},\"Title\":{\"string\":[\"Jolly Jabs\"]},\"HTML5\":{}}}\n\
http://host [200 OK] X-Powered-By[Express], HTTPServer[nginx]\n\
]\n";
        let parsed = Whatweb.parse("http://host", "T1046", &outcome(stdout));
        assert!(parsed.observations.iter().any(|o| o.kind == "tech"
            && o.value == "X-Powered-By"
            && o.detail.as_deref() == Some("Express")));
        assert!(parsed.observations.iter().any(|o| o.kind == "server"
            && o.value == "HTTPServer"
            && o.detail.as_deref() == Some("nginx")));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "title" && o.detail.as_deref() == Some("Jolly Jabs")));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.value == "HTML5" && o.detail.is_none()));
    }

    #[test]
    fn nothing_recorded_without_json() {
        assert!(Whatweb
            .parse("http://host", "T1046", &outcome("http://host [200 OK]\n"))
            .observations
            .is_empty());
    }
}
