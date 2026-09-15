//! The gobuster tool wrapper: directory/file brute-forcing (`dir` mode). gobuster prints plain result
//! lines (`/path (Status: N) [Size: M]`), sometimes prefixed with an ANSI erase sequence; we strip
//! ANSI and record each as an endpoint observation. The wordlist is a caller-supplied `seclists:` token.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Gobuster;

pub static GOBUSTER: Gobuster = Gobuster;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "directory & file brute-forcing against a wordlist (dir mode)",
    invoke: "searu run gobuster --technique T1595 --target http://host:port -- -w seclists:Discovery/Web-Content/common.txt  (a wordlist is required; add `-x php,txt` for extensions)",
    interpret: "searu observations --kind endpoint — one per discovered path with its status",
    chain: "discovered endpoints feed Initial access — the parameters they take are where you test for injection",
}];

impl Tool for Gobuster {
    fn name(&self) -> &'static str {
        "gobuster"
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
            "dir".to_string(),
            "-u".to_string(),
            target.to_string(),
            "-q".to_string(),
            "-z".to_string(),
            "--no-color".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let base = target.trim_end_matches('/');
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            let clean = strip_ansi(line);
            let clean = clean.trim();
            let Some(path) = clean.split_whitespace().next() else {
                continue;
            };
            if !path.starts_with('/') {
                continue;
            }
            let status = clean
                .split_once("(Status:")
                .and_then(|(_, rest)| rest.trim().split(')').next())
                .map(str::trim);
            observations.push(Observation {
                kind: "endpoint".to_string(),
                value: format!("{base}{path}"),
                detail: status.map(|status| format!("status {status}")),
            });
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_escape = false;
    for c in line.chars() {
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
    fn invocation_is_dir_mode_then_passes_the_wordlist_through() {
        assert_eq!(
            Gobuster.invocation("http://h", &["-w".to_string(), "seclists:x".to_string()]),
            vec![
                "dir",
                "-u",
                "http://h",
                "-q",
                "-z",
                "--no-color",
                "-w",
                "seclists:x"
            ]
        );
    }

    #[test]
    fn parses_result_lines_stripping_ansi_and_prefixing_the_target() {
        let stdout = "\u{1b}[2K/download             (Status: 500) [Size: 938]\n/login            (Status: 200) [Size: 1]\n";
        let parsed = Gobuster.parse("http://h", &outcome(stdout));
        assert_eq!(parsed.observations.len(), 2);
        assert!(parsed.observations.iter().any(|o| o.kind == "endpoint"
            && o.value == "http://h/download"
            && o.detail.as_deref() == Some("status 500")));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.value == "http://h/login" && o.detail.as_deref() == Some("status 200")));
    }

    #[test]
    fn non_result_lines_are_ignored() {
        assert!(Gobuster
            .parse("http://h", &outcome("Starting gobuster\n===============\n"))
            .observations
            .is_empty());
    }
}
