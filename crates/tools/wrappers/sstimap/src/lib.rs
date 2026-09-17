//! The sstimap tool wrapper: detect server-side template injection in a URL parameter and normalise
//! SSTImap's console report into a finding. SSTImap does the detection/exploitation; this crate shapes
//! the invocation and reads the result. The target is a URL carrying the parameter to test.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Sstimap;

pub static SSTIMAP: Sstimap = Sstimap;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "server-side template injection — confirm a parameter is rendered by a template engine, the flaw that escalates to code and OS-command execution (T1190, CWE-1336/94). Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
    invoke: "searu run sstimap --technique T1190 --target 'http://host:port/page?name=x' -- -e  (add `-e`/`-o <cmd>` after `--` to evaluate template / run OS commands once detection confirms)",
    interpret: "searu findings --tool sstimap — a confirmed SSTI finding (CWE-1336/94); the evidence names the template engine and injected parameter",
    chain: "a confirmed engine with `Shell command execution: ok` authorises an OS-command run within the ROE (`-- -o id`) — treat that as full compromise",
}];

impl Tool for Sstimap {
    fn name(&self) -> &'static str {
        "sstimap"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1190"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // SSTImap runs detection non-interactively against the URL given with `-u`.
        let mut argv = vec!["-u".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let lines: Vec<String> = outcome.stdout.lines().map(strip_ansi).collect();
        let confirmed = lines
            .iter()
            .any(|line| line.contains("identified the following injection point"));
        if !confirmed {
            return ParsedOutput::default();
        }
        let engine = field(&lines, "Engine:");
        let parameter = lines.iter().find_map(|line| {
            line.split_once("parameter:")
                .map(|(_, v)| v.trim().to_string())
        });
        let evidence = match (engine, parameter) {
            (Some(engine), Some(parameter)) => format!("{engine} engine, parameter {parameter}"),
            (Some(engine), None) => format!("{engine} engine"),
            _ => "confirmed template injection".to_string(),
        };
        ParsedOutput {
            findings: vec![Finding {
                tool: "sstimap".to_string(),
                target: target.to_string(),
                title: "Server-side template injection".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![1336, 94],
                evidence,
                loot_fingerprint: None,
            }],
            ..Default::default()
        }
    }
}

fn field(lines: &[String], label: &str) -> Option<String> {
    lines
        .iter()
        .find_map(|line| line.split_once(label).map(|(_, v)| v.trim().to_string()))
        .filter(|value| !value.is_empty())
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

    #[test]
    fn invocation_detects_against_the_target_url() {
        let argv = SSTIMAP.invocation("http://h/p?name=x", &[]);
        assert_eq!(argv, vec!["-u", "http://h/p?name=x"]);
    }

    #[test]
    fn parses_a_confirmed_injection_point_into_a_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "\u{1b}[92m[+]\u{1b}[0m SSTImap identified the following injection point:\n\
                       GET parameter: name\n\
                       Engine: Jinja2\n\
                       Injection: {{*}}\n\
                       Technique: render\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SSTIMAP.parse("http://h/p?name=x", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Server-side template injection");
        assert_eq!(parsed.findings[0].cwe, vec![1336, 94]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert_eq!(parsed.findings[0].evidence, "Jinja2 engine, parameter name");
    }

    #[test]
    fn a_non_injectable_target_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[-] Tested parameters appear to be not injectable.\n".to_string(),
            stderr: String::new(),
        };
        let parsed = SSTIMAP.parse("http://h/p?name=x", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
