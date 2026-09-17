//! The wafw00f tool wrapper: fingerprint a protecting WAF/CDN. wafw00f prints a pretty JSON array
//! (followed by its banner) to stdout; we read the first JSON value and record a `waf` observation
//! only when one is actually detected.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Wafw00f;

pub static WAFW00F: Wafw00f = Wafw00f;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "WAF/CDN detection — identify a protecting firewall so later tools can be tuned or evaded",
    invoke: "searu run wafw00f --technique T1595 --target http://host:port",
    interpret: "searu observations --kind waf — the detected firewall + vendor (nothing is recorded when no WAF is found)",
    chain: "a WAF means tune payloads and rate — feed it into sqlmap tamper scripts and nuclei rate limits",
}];

impl Tool for Wafw00f {
    fn name(&self) -> &'static str {
        "wafw00f"
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
            "-a".to_string(),
            "-f".to_string(),
            "json".to_string(),
            "-o".to_string(),
            "/dev/stdout".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv.push(target.to_string());
        argv
    }

    fn parse(&self, _target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let array = serde_json::Deserializer::from_str(&outcome.stdout)
            .into_iter::<serde_json::Value>()
            .flatten()
            .find(|value| value.is_array());
        for entry in array
            .as_ref()
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
        {
            if entry["detected"].as_bool() != Some(true) {
                continue;
            }
            let firewall = entry["firewall"].as_str().unwrap_or("unknown");
            let detail = entry["manufacturer"]
                .as_str()
                .filter(|manufacturer| *manufacturer != "None")
                .map(str::to_string);
            observations.push(Observation {
                kind: "waf".to_string(),
                value: firewall.to_string(),
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
    fn invocation_requests_json_to_stdout_with_the_target_last() {
        assert_eq!(
            Wafw00f.invocation("http://host", &["-p".to_string(), "proxy".to_string()]),
            vec![
                "-a",
                "-f",
                "json",
                "-o",
                "/dev/stdout",
                "-p",
                "proxy",
                "http://host"
            ]
        );
    }

    #[test]
    fn a_detected_waf_becomes_an_observation_ignoring_the_trailing_banner() {
        let stdout = "[\n  {\n    \"detected\": true,\n    \"firewall\": \"Cloudflare\",\n    \"manufacturer\": \"Cloudflare Inc.\",\n    \"url\": \"http://h\"\n  }\n]\n            ______\n[*] Checking http://h\n";
        let parsed = Wafw00f.parse("http://h", "T1046", &outcome(stdout));
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.observations[0].kind, "waf");
        assert_eq!(parsed.observations[0].value, "Cloudflare");
        assert_eq!(
            parsed.observations[0].detail.as_deref(),
            Some("Cloudflare Inc.")
        );
    }

    #[test]
    fn no_waf_records_nothing() {
        let stdout = "[\n  {\"detected\": false, \"firewall\": \"None\", \"manufacturer\": \"None\", \"url\": \"http://h\"}\n]\n[*] banner\n";
        assert!(Wafw00f
            .parse("http://h", "T1046", &outcome(stdout))
            .observations
            .is_empty());
    }
}
