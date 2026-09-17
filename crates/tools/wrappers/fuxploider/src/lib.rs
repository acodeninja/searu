//! The fuxploider tool wrapper: probe a file-upload form for unrestricted upload and normalise
//! fuxploider's console report into a finding. fuxploider does the fuzzing; this crate shapes the
//! invocation and reads the result. The target is the URL of a page carrying an upload form.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Fuxploider;

pub static FUXPLOIDER: Fuxploider = Fuxploider;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "unrestricted file upload — fuzz an upload form to find which dangerous extensions it accepts, the flaw that escalates to a web shell / code execution (T1190, CWE-434). Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
    invoke: "searu run fuxploider --technique T1190 --target 'http://host:port/upload' -- --not-regex 'not allowed'  (fuxploider needs an oracle — `--not-regex`/`--true-regex` matching an upload failure/success — after `--`)",
    interpret: "searu findings --tool fuxploider — an unrestricted-upload finding (CWE-434) when it uploads a dangerous extension; the evidence is how many extensions slipped through (or that code execution was reached)",
    chain: "upload a web shell in an accepted extension and browse to it for code execution within the ROE — treat that as full compromise",
}];

impl Tool for Fuxploider {
    fn name(&self) -> &'static str {
        "fuxploider"
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
        // fuxploider takes the upload page URL with `-u` and auto-detects the form; the caller supplies
        // the success/failure oracle (`--not-regex`/`--true-regex`) after `--`.
        let mut argv = vec!["-u".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let lines: Vec<String> = outcome.stdout.lines().map(strip_ansi).collect();
        let code_execution = lines
            .iter()
            .any(|line| line.contains("Code execution obtained"));
        let valid = lines
            .iter()
            .filter_map(|line| line.split_once("are valid"))
            .filter_map(|(head, _)| head.split_whitespace().last()?.parse::<u32>().ok())
            .next_back()
            .unwrap_or(0);
        if !code_execution && valid == 0 {
            return ParsedOutput::default();
        }
        let evidence = if code_execution {
            "code execution obtained via file upload".to_string()
        } else {
            format!("{valid} uploadable file extension(s)")
        };
        ParsedOutput {
            findings: vec![Finding {
                tool: "fuxploider".to_string(),
                target: target.to_string(),
                title: "Unrestricted file upload".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![434],
                evidence,
                loot_fingerprint: None,
            }],
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

    #[test]
    fn invocation_targets_the_upload_page() {
        let argv = FUXPLOIDER.invocation("http://h/upload", &[]);
        assert_eq!(argv, vec!["-u", "http://h/upload"]);
    }

    #[test]
    fn parses_valid_extensions_into_an_upload_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[*] starting\n### Tried 20 extensions,  3 are valid.\n".to_string(),
            stderr: String::new(),
        };
        let parsed = FUXPLOIDER.parse("http://h/upload", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Unrestricted file upload");
        assert_eq!(parsed.findings[0].cwe, vec![434]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert_eq!(
            parsed.findings[0].evidence,
            "3 uploadable file extension(s)"
        );
    }

    #[test]
    fn code_execution_is_reported_as_such() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "Code execution obtained ('a','b','c','d')\n".to_string(),
            stderr: String::new(),
        };
        let parsed = FUXPLOIDER.parse("http://h/upload", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(
            parsed.findings[0].evidence,
            "code execution obtained via file upload"
        );
    }

    #[test]
    fn a_restricted_upload_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "### Tried 20 extensions,  0 are valid.\n".to_string(),
            stderr: String::new(),
        };
        let parsed = FUXPLOIDER.parse("http://h/upload", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
