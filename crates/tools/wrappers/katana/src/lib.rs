//! The katana tool wrapper: crawl a target and normalise katana's JSONL into endpoint/param
//! observations for the recon map.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Tool};

pub struct Katana;

pub static KATANA: Katana = Katana;

impl Tool for Katana {
    fn name(&self) -> &'static str {
        "katana"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn advice(&self) -> &'static str {
        include_str!("../advice.md")
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // Seed URL via `-u` (the runner rewrites it for container reachability).
        let mut argv = vec![
            "-u".to_string(),
            target.to_string(),
            "-jsonl".to_string(),
            "-silent".to_string(),
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
            let Some(url) = value["request"]["endpoint"].as_str() else {
                continue;
            };

            push_unique(
                &mut observations,
                Observation {
                    kind: "endpoint".to_string(),
                    value: path_of(url).to_string(),
                    detail: value["request"]["method"].as_str().map(str::to_string),
                },
            );

            for param in query_params(url) {
                push_unique(
                    &mut observations,
                    Observation {
                        kind: "param".to_string(),
                        value: param,
                        detail: Some(path_of(url).to_string()),
                    },
                );
            }

            if let Some(body) = value["request"]["body"].as_str() {
                for field in form_fields(body) {
                    push_unique(
                        &mut observations,
                        Observation {
                            kind: "param".to_string(),
                            value: field,
                            detail: Some(path_of(url).to_string()),
                        },
                    );
                }
            }
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

fn path_of(url: &str) -> &str {
    let after_scheme = match url.find("://") {
        Some(index) => &url[index + 3..],
        None => url,
    };
    let path = match after_scheme.find('/') {
        Some(slash) => &after_scheme[slash..],
        None => "/",
    };
    let end = path.find(['?', '#']).unwrap_or(path.len());
    &path[..end]
}

fn query_params(url: &str) -> Vec<String> {
    url.split_once('?')
        .map(|(_, query)| form_fields(query))
        .unwrap_or_default()
}

fn form_fields(encoded: &str) -> Vec<String> {
    encoded
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn push_unique(observations: &mut Vec<Observation>, observation: Observation) {
    if !observations
        .iter()
        .any(|o| o.kind == observation.kind && o.value == observation.value)
    {
        observations.push(observation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoints_and_params_from_jsonl() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"request":{"method":"GET","endpoint":"http://localhost:5000/login"}}
{"request":{"method":"GET","endpoint":"http://localhost:5000/download?file=readme.txt"}}
{"request":{"method":"POST","endpoint":"http://localhost:5000/login","body":"username=&password="}}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = Katana.parse("http://localhost:5000", &outcome);
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "endpoint" && o.value == "/login"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "endpoint" && o.value == "/download"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "param" && o.value == "file"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "param" && o.value == "username"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "param" && o.value == "password"));
    }
}
