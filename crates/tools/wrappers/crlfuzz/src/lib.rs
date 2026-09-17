//! The crlfuzz tool wrapper: fuzz a URL for CRLF injection and normalise crlfuzz's output into findings.
//! crlfuzz does the fuzzing (writing vulnerable URLs to stdout, request noise to stderr); this crate
//! shapes the invocation and reads the result. The target is a URL.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Crlfuzz;

pub static CRLFUZZ: Crlfuzz = Crlfuzz;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "CRLF-injection detection — fuzz a URL for carriage-return/line-feed injection that lets you inject response headers (session fixation, cache poisoning, open redirect) (T1595, CWE-93; Active: allow-listing the technique is enough)",
    invoke: "searu run crlfuzz --technique T1595 --target 'http://host:port/path?param=x'  (crlfuzz's own flags after `--`, e.g. `-- -X POST -d 'a=b'`)",
    interpret: "searu findings --tool crlfuzz — one finding per injectable URL; the evidence is the payload URL that injected a header",
    chain: "reproduce the payload to inject a Set-Cookie / Location header; escalate to session fixation or an open redirect within the ROE",
}];

impl Tool for Crlfuzz {
    fn name(&self) -> &'static str {
        "crlfuzz"
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
        // crlfuzz takes the URL with `-u` and writes injectable URLs to stdout.
        let mut argv = vec!["-u".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for raw in outcome.stdout.lines() {
            let line = strip_ansi(raw);
            let line = line.trim();
            let url = match line.split_once("[VLN]") {
                Some((_, rest)) => rest.trim(),
                None if line.starts_with("http") => line,
                None => continue,
            };
            if url.is_empty() || !seen.insert(url.to_string()) {
                continue;
            }
            findings.push(Finding {
                tool: "crlfuzz".to_string(),
                target: target.to_string(),
                title: "CRLF injection".to_string(),
                severity: Severity::Medium,
                status: Status::NeedsReview,
                attack_technique: vec!["T1595".to_string()],
                cwe: vec![93],
                evidence: url.to_string(),
                loot_fingerprint: None,
            });
        }
        ParsedOutput {
            findings,
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
    fn invocation_fuzzes_the_target_url() {
        let argv = CRLFUZZ.invocation("http://h/p?x=1", &[]);
        assert_eq!(argv, vec!["-u", "http://h/p?x=1"]);
    }

    #[test]
    fn parses_vulnerable_urls_into_crlf_findings() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "\u{1b}[32m[VLN]\u{1b}[0m http://h/p?x=%0d%0aSet-Cookie:z\n\
                     http://h/p?y=%0d%0aSet-Cookie:z\n\
                     http://h/p?x=%0d%0aSet-Cookie:z\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = CRLFUZZ.parse("http://h/p?x=1", &outcome);
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].title, "CRLF injection");
        assert_eq!(parsed.findings[0].cwe, vec![93]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1595"]);
        assert_eq!(
            parsed.findings[0].evidence,
            "http://h/p?x=%0d%0aSet-Cookie:z"
        );
    }

    #[test]
    fn a_clean_run_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: "[INF] scanning\n".to_string(),
        };
        let parsed = CRLFUZZ.parse("http://h/p?x=1", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
