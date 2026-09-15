//! The httpx tool wrapper: probe a target and normalise httpx's JSON into recon observations.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Httpx;

pub static HTTPX: Httpx = Httpx;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "HTTP fingerprint — identify the stack (status, title, server, technologies) before choosing an attack",
    invoke: "searu run httpx --technique T1595 --target http://host:port  (target passed to httpx with `-u`; Active tier, allow-listing the technique is enough)",
    interpret: "searu observations --kind server / --kind tech / --kind endpoint — the server/tech values are your stack and OS hints",
    chain: "the stack hints pick the SecLists wordlist for Discovery and the weakness to look for in Initial access",
}];

impl Tool for Httpx {
    fn name(&self) -> &'static str {
        "httpx"
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
        // Target via `-u` (the runner rewrites it for container reachability). Short flags: JSON
        // output plus status code, title, tech detection, and the server header.
        let mut argv = vec![
            "-u".to_string(),
            target.to_string(),
            "-silent".to_string(),
            "-json".to_string(),
            "-sc".to_string(),
            "-title".to_string(),
            "-td".to_string(),
            "-server".to_string(),
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
            if let Some(url) = value["url"].as_str() {
                let status = value["status_code"].as_i64();
                let title = value["title"].as_str().unwrap_or_default();
                let detail = match (status, title.is_empty()) {
                    (Some(code), false) => Some(format!("status {code}; {title}")),
                    (Some(code), true) => Some(format!("status {code}")),
                    (None, false) => Some(title.to_string()),
                    (None, true) => None,
                };
                observations.push(Observation {
                    kind: "endpoint".to_string(),
                    value: url.to_string(),
                    detail,
                });
            }
            if let Some(location) = value["location"].as_str() {
                if !location.is_empty() {
                    observations.push(Observation {
                        kind: "endpoint".to_string(),
                        value: location.to_string(),
                        detail: Some("redirect target".to_string()),
                    });
                }
            }
            if let Some(server) = value["webserver"].as_str() {
                observations.push(Observation {
                    kind: "server".to_string(),
                    value: server.to_string(),
                    detail: None,
                });
            }
            if let Some(techs) = value["tech"].as_array() {
                for tech in techs.iter().filter_map(|t| t.as_str()) {
                    observations.push(Observation {
                        kind: "tech".to_string(),
                        value: tech.to_string(),
                        detail: None,
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
    fn parses_httpx_json_into_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: r#"{"url":"http://localhost:5000","status_code":302,"location":"/login","webserver":"Express","tech":["Express","Node.js"]}"#
                .to_string(),
            stderr: String::new(),
        };
        let parsed = Httpx.parse("http://localhost:5000", &outcome);
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "endpoint" && o.value == "http://localhost:5000"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "endpoint" && o.value == "/login"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "server" && o.value == "Express"));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "tech" && o.value == "Node.js"));
    }
}
