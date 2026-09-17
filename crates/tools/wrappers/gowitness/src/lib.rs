//! The gowitness tool wrapper: screenshot a web target and normalise gowitness's log into a screenshot
//! observation. gowitness drives headless Chrome and writes the PNG/JPEG into the run's output
//! directory (mounted writable at `/out` via the `out:` token); this crate shapes the invocation and
//! reads the result. The target is a URL.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Gowitness;

pub static GOWITNESS: Gowitness = Gowitness;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "surface triage by screenshot — capture what a URL renders (login page, admin panel, default app, error) to prioritise targets visually (T1595, Active: allow-listing the technique is enough)",
    invoke: "searu run gowitness --technique T1595 --target http://host:port  (gowitness's own flags after `--`)",
    interpret: "searu observations --kind screenshot — the captured URL and its page title; the image file is saved under the run's output directory (searu observations --kind output)",
    chain: "eyeball the screenshots to pick the interesting hosts, then fingerprint (httpx) and crawl (gospider) the ones worth attacking",
}];

impl Tool for Gowitness {
    fn name(&self) -> &'static str {
        "gowitness"
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
        // The `out:` token mounts the run's output directory writable at `/out`; gowitness writes the
        // screenshot there. The runner rewrites the target URL for container reachability.
        let mut argv = vec![
            "scan".to_string(),
            "single".to_string(),
            "--url".to_string(),
            target.to_string(),
            "--screenshot-path".to_string(),
            "out:".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        // gowitness logs each capture to stderr; scan both streams for the result line.
        for line in outcome.stdout.lines().chain(outcome.stderr.lines()) {
            if !line.contains("have-screenshot=true") {
                continue;
            }
            let Some(url) = field(line, "target=") else {
                continue;
            };
            let title = between(line, "title=\"", "\"");
            observations.push(Observation {
                kind: "screenshot".to_string(),
                value: url,
                detail: title,
            });
        }
        ParsedOutput {
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

fn between(line: &str, open: &str, close: &str) -> Option<String> {
    let (_, rest) = line.split_once(open)?;
    let (value, _) = rest.split_once(close)?;
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_screenshots_the_target_into_the_output_mount() {
        let argv = GOWITNESS.invocation("http://h:3000", &[]);
        assert_eq!(
            argv,
            vec![
                "scan",
                "single",
                "--url",
                "http://h:3000",
                "--screenshot-path",
                "out:"
            ]
        );
    }

    #[test]
    fn parses_a_capture_into_a_screenshot_observation() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: "INFO result 🤖 target=http://h:3000 status-code=200 title=\"OWASP Juice Shop\" have-screenshot=true\n"
                .to_string(),
        };
        let parsed = GOWITNESS.parse("http://h:3000", &outcome);
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.observations[0].kind, "screenshot");
        assert_eq!(parsed.observations[0].value, "http://h:3000");
        assert_eq!(
            parsed.observations[0].detail.as_deref(),
            Some("OWASP Juice Shop")
        );
    }

    #[test]
    fn a_failed_capture_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: "INFO result target=http://h:3000 have-screenshot=false\n".to_string(),
        };
        let parsed = GOWITNESS.parse("http://h:3000", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
