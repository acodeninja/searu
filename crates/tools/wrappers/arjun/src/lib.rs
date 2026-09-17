//! The arjun tool wrapper: hidden HTTP parameter discovery. arjun's JSON output needs a seekable file
//! (not stdout), so we parse its console output instead — each confirmed parameter is announced as
//! `parameter detected: <name>, based on: <reason>` — into `param` observations.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Arjun;

pub static ARJUN: Arjun = Arjun;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "hidden HTTP parameter discovery — brute-force query/body parameters an endpoint secretly accepts",
    invoke: "searu run arjun --technique T1595 --target http://host:port/endpoint  (point at a specific endpoint; add `-- -m POST` for body params, `-- -m JSON` for JSON)",
    interpret: "searu observations --kind param — each hidden parameter arjun confirmed",
    chain: "feed the discovered parameters to Initial access — they are where you test for injection (sqlmap -p, ffuf, dalfox)",
}];

impl Tool for Arjun {
    fn name(&self) -> &'static str {
        "arjun"
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
        let mut argv = vec!["-u".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        const MARKER: &str = "parameter detected: ";
        let clean = strip_ansi(&outcome.stdout);
        let mut observations = Vec::new();
        let mut seen = HashSet::new();
        let mut haystack = clean.as_str();
        while let Some(index) = haystack.find(MARKER) {
            haystack = &haystack[index + MARKER.len()..];
            let name = haystack
                .split([',', '\n', '\r'])
                .next()
                .unwrap_or_default()
                .trim();
            if !name.is_empty() && seen.insert(name.to_string()) {
                observations.push(Observation {
                    kind: "param".to_string(),
                    value: name.to_string(),
                    detail: None,
                });
            }
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_escape = false;
    for c in text.chars() {
        if in_escape {
            in_escape = !c.is_ascii_alphabetic();
        } else if c == '\u{1b}' {
            in_escape = true;
        } else {
            out.push(c);
        }
    }
    out
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
    fn invocation_targets_the_url_then_passes_through() {
        assert_eq!(
            Arjun.invocation("http://h/x", &["-m".to_string(), "POST".to_string()]),
            vec!["-u", "http://h/x", "-m", "POST"]
        );
    }

    #[test]
    fn detected_parameters_become_observations_deduplicated() {
        let stdout = "Processing chunks: 2/2  \u{1b}[1;92m[\u{2713}]\u{1b}[0m parameter detected: file, based on: http code\n\u{1b}[1;92m[\u{2713}]\u{1b}[0m parameter detected: id, based on: body length\nparameter detected: file, based on: http code\n";
        let parsed = Arjun.parse("http://h/x", "T1046", &outcome(stdout));
        assert_eq!(
            parsed.observations.len(),
            2,
            "the repeated `file` collapses"
        );
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "param" && o.value == "file"));
        assert!(parsed.observations.iter().any(|o| o.value == "id"));
    }

    #[test]
    fn no_parameters_records_nothing() {
        assert!(Arjun
            .parse("http://h", "T1046", &outcome("Processing chunks: 2/2\n"))
            .observations
            .is_empty());
    }
}
