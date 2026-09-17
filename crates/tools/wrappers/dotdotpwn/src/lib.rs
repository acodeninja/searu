//! The dotdotpwn tool wrapper: fuzz a URL parameter for directory traversal and normalise dotdotpwn's
//! report into path-traversal findings. dotdotpwn does the fuzzing; this crate shapes the invocation and
//! reads the result. The target is a URL with a `TRAVERSAL` placeholder where the payload is inserted.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Dotdotpwn;

pub static DOTDOTPWN: Dotdotpwn = Dotdotpwn;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "directory-traversal exploitation — fuzz a URL parameter with dot-slash payloads to read files outside the web root (T1190, CWE-22). Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
    invoke: "searu run dotdotpwn --technique T1190 --target 'http://host:port/download?file=TRAVERSAL' -- -k \"root:\" -b -q  (put the `TRAVERSAL` marker where the payload goes; `-k` is a string that proves a leaked file, `-b` breaks on the first hit)",
    interpret: "searu findings --tool dotdotpwn — a confirmed path-traversal finding (CWE-22); the evidence is the traversal URL that leaked the file",
    chain: "reproduce the leaking URL to pull sensitive files (config, credentials); feed any secrets into the wider attack picture",
}];

impl Tool for Dotdotpwn {
    fn name(&self) -> &'static str {
        "dotdotpwn"
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
        // The `http-url` module fuzzes the `TRAVERSAL` marker in the target URL. dotdotpwn prompts to
        // start; the runner's target-on-stdin satisfies that prompt.
        let mut argv = vec![
            "-m".to_string(),
            "http-url".to_string(),
            "-u".to_string(),
            target.to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            if !line.contains("<- VULNERABLE") {
                continue;
            }
            let evidence = vulnerable_url(line).unwrap_or_else(|| line.trim().to_string());
            if !seen.insert(evidence.clone()) {
                continue;
            }
            findings.push(Finding {
                tool: "dotdotpwn".to_string(),
                target: target.to_string(),
                title: "Path traversal".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![22],
                evidence,
                loot_fingerprint: None,
            });
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn vulnerable_url(line: &str) -> Option<String> {
    let head = line.split(" <- VULNERABLE").next()?;
    let payload = head
        .split_once("URL: ")
        .or_else(|| head.split_once("Path: "))
        .map(|(_, rest)| rest)?;
    Some(payload.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_fuzzes_the_traversal_marker_in_the_url() {
        let argv = DOTDOTPWN.invocation("http://h/download?file=TRAVERSAL", &[]);
        assert_eq!(
            argv,
            vec!["-m", "http-url", "-u", "http://h/download?file=TRAVERSAL"]
        );
    }

    #[test]
    fn parses_vulnerable_lines_into_traversal_findings() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[+] Traversal Engine DONE !\n\
                     [*] Testing URL: http://h/download?file=../etc/passwd <- VULNERABLE\n\
                     [*] Testing URL: http://h/download?file=../etc/passwd <- VULNERABLE\n\
                     [+] Total Traversals found: 1\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = DOTDOTPWN.parse("http://h/download?file=TRAVERSAL", "T1046", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Path traversal");
        assert_eq!(parsed.findings[0].cwe, vec![22]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert_eq!(
            parsed.findings[0].evidence,
            "http://h/download?file=../etc/passwd"
        );
    }

    #[test]
    fn a_clean_run_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[+] Total Traversals found: 0\n".to_string(),
            stderr: String::new(),
        };
        let parsed = DOTDOTPWN.parse("http://h/download?file=TRAVERSAL", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
